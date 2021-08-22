/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "stratum_server.h"
#include "block_template.h"
#include "p2pool.h"
#include "params.h"

static constexpr char log_category_prefix[] = "StratumServer ";

static constexpr int DEFAULT_BACKLOG = 128;
static constexpr uint64_t DEFAULT_BAN_TIME = 600;

#include "tcp_server.inl"

namespace p2pool {

StratumServer::StratumServer(p2pool* pool)
	: TCPServer(StratumClient::allocate, pool->params().m_stratumAddresses)
	, m_pool(pool)
	, m_extraNonce(0)
	, m_rd{}
	, m_rng(m_rd())
{
	uv_mutex_init_checked(&m_blobsQueueLock);
	uv_mutex_init_checked(&m_rngLock);
	uv_mutex_init_checked(&m_submittedSharesPoolLock);

	m_submittedSharesPool.resize(10);
	for (size_t i = 0; i < m_submittedSharesPool.size(); ++i) {
		m_submittedSharesPool[i] = new SubmittedShare{};
	}

	const int err = uv_async_init(&m_loop, &m_blobsAsync, on_blobs_ready);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		return;
	}
	m_blobsAsync.data = this;
	m_blobsQueue.reserve(2);
}

StratumServer::~StratumServer()
{
	uv_close(reinterpret_cast<uv_handle_t*>(&m_blobsAsync), nullptr);

	shutdown_tcp();

	uv_mutex_destroy(&m_blobsQueueLock);
	uv_mutex_destroy(&m_rngLock);
	uv_mutex_destroy(&m_submittedSharesPoolLock);

	for (SubmittedShare* share : m_submittedSharesPool) {
		delete share;
	}
}

void StratumServer::on_block(const BlockTemplate& block)
{
	LOGINFO(3, "new block template at height " << block.height());

	const uint32_t num_connections = m_numConnections;
	if (num_connections == 0) {
		LOGINFO(3, "no clients connected");
		return;
	}

	BlobsData* blobs_data = new BlobsData{};

	difficulty_type difficulty;
	difficulty_type sidechain_difficulty;
	size_t nonce_offset;

	// More clients might connect between now and when we actually go through clients list - get_hashing_blobs() and async send take some time
	// Even if they do, they'll be added to the beginning of the list and will get their block template in on_login()
	// We'll iterate through the list backwards so when we get to the beginning and run out of extra_nonce values, it'll be only new clients left
	blobs_data->m_numClientsExpected = num_connections;
	m_extraNonce.exchange(blobs_data->m_numClientsExpected);

	blobs_data->m_blobSize = block.get_hashing_blobs(0, blobs_data->m_numClientsExpected, blobs_data->m_blobs, blobs_data->m_height, difficulty, sidechain_difficulty, blobs_data->m_seedHash, nonce_offset, blobs_data->m_templateId);
	blobs_data->m_target = std::max(difficulty.target(), sidechain_difficulty.target());

	{
		MutexLock lock(m_blobsQueueLock);
		m_blobsQueue.push_back(blobs_data);
	}

	const int err = uv_async_send(&m_blobsAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));

		bool found = false;
		{
			MutexLock lock(m_blobsQueueLock);

			auto it = std::find(m_blobsQueue.begin(), m_blobsQueue.end(), blobs_data);
			if (it != m_blobsQueue.end()) {
				found = true;
				m_blobsQueue.erase(it);
			}
		}

		if (found) {
			delete blobs_data;
		}
	}
}

bool StratumServer::on_login(StratumClient* client, uint32_t id)
{
	const uint32_t extra_nonce = m_extraNonce.fetch_add(1);

	uint8_t hashing_blob[128];
	uint64_t height;
	difficulty_type difficulty;
	difficulty_type sidechain_difficulty;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;

	const size_t blob_size = m_pool->block_template().get_hashing_blob(extra_nonce, hashing_blob, height, difficulty, sidechain_difficulty, seed_hash, nonce_offset, template_id);
	const uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());

	uint32_t job_id;
	{
		MutexLock lock(client->m_jobsLock);

		job_id = client->m_perConnectionJobId++;

		StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(client->m_jobs)];
		saved_job.job_id = job_id;
		saved_job.extra_nonce = extra_nonce;
		saved_job.template_id = template_id;
		saved_job.target = target;
	}

	const bool result = send(client,
		[client, id, &hashing_blob, job_id, blob_size, target, height, &seed_hash](void* buf)
		{
			do {
				client->m_rpcId = static_cast<uint32_t>(static_cast<StratumServer*>(client->m_owner)->get_random64());
			} while (!client->m_rpcId);

			log::Stream s(reinterpret_cast<char*>(buf));
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{\"id\":\"";
			s << log::Hex(client->m_rpcId) << "\",\"job\":{\"blob\":\"";
			s << log::hex_buf(hashing_blob, blob_size) << "\",\"job_id\":\"";
			s << log::Hex(job_id) << "\",\"target\":\"";
			s << log::hex_buf(reinterpret_cast<const uint8_t*>(&target), sizeof(target)) << "\",\"algo\":\"rx/0\",\"height\":";
			s << height << ",\"seed_hash\":\"";
			s << seed_hash << "\"},\"extensions\":[\"algo\"],\"status\":\"OK\"}}\n";
			return s.m_pos;
		});

	return result;
}

bool StratumServer::on_submit(StratumClient* client, uint32_t id, const char* job_id_str, const char* nonce_str)
{
	uint32_t job_id = 0;

	for (size_t i = 0; job_id_str[i]; ++i) {
		uint32_t d;
		if (!from_hex(job_id_str[i], d)) {
			LOGWARN(1, "client: invalid params ('job_id' is not a hex integer)");
			return false;
		}
		job_id = (job_id << 4) + d;
	}

	uint32_t nonce = 0;

	for (int i = static_cast<int>(sizeof(uint32_t)) - 1; i >= 0; --i) {
		uint32_t d[2];
		if (!from_hex(nonce_str[i * 2], d[0]) || !from_hex(nonce_str[i * 2 + 1], d[1])) {
			LOGWARN(1, "Client: invalid params ('nonce' is not a hex integer)");
			return false;
		}
		nonce = (nonce << 8) | (d[0] << 4) | d[1];
	}

	uint32_t template_id = 0;
	uint32_t extra_nonce = 0;

	bool found = false;
	{
		MutexLock lock(client->m_jobsLock);

		const StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(client->m_jobs)];
		if (saved_job.job_id == job_id) {
			template_id = saved_job.template_id;
			extra_nonce = saved_job.extra_nonce;
			found = true;
		}
	}

	if (found) {
		SubmittedShare* share;

		{
			MutexLock lock(m_submittedSharesPoolLock);

			if (!m_submittedSharesPool.empty()) {
				share = m_submittedSharesPool.back();
				m_submittedSharesPool.pop_back();
			}
			else {
				share = new SubmittedShare{};
			}
		}

		share->m_req.data = share;
		share->m_server = this;
		share->m_client = client;
		share->m_clientResetCounter = client->m_resetCounter.load();
		share->m_rpcId = client->m_rpcId;
		share->m_id = id;
		share->m_templateId = template_id;
		share->m_nonce = nonce;
		share->m_extraNonce = extra_nonce;

		const int err = uv_queue_work(&m_loop, &share->m_req, on_share_found, on_after_share_found);
		if (err) {
			LOGERR(1, "uv_queue_work failed, error " << uv_err_name(err));
			MutexLock lock(m_submittedSharesPoolLock);
			m_submittedSharesPool.push_back(share);
			return false;
		}

		return true;
	}

	LOGWARN(1, "client: got a share with invalid job id");

	const bool result = send(client,
		[id](void* buf)
		{
			log::Stream s(reinterpret_cast<char*>(buf));
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid job id\"}}\n";
			return s.m_pos;
		});

	return result;
}

uint64_t StratumServer::get_random64()
{
	MutexLock lock(m_rngLock);
	return m_rng();
}

void StratumServer::on_blobs_ready()
{
	std::vector<BlobsData*> blobs_queue;
	blobs_queue.reserve(2);

	{
		MutexLock lock(m_blobsQueueLock);
		blobs_queue = m_blobsQueue;
		m_blobsQueue.clear();
	}

	if (blobs_queue.empty()) {
		return;
	}

	ON_SCOPE_LEAVE([&blobs_queue]()
		{
			for (BlobsData* data : blobs_queue) {
				delete data;
			}
		});

	// Only send the latest blob
	BlobsData* data = blobs_queue.back();

	size_t numClientsProcessed = 0;
	uint32_t extra_nonce = 0;
	{
		MutexLock lock2(m_clientsListLock);

		for (StratumClient* client = static_cast<StratumClient*>(m_connectedClientsList->m_prev); client != m_connectedClientsList; client = static_cast<StratumClient*>(client->m_prev)) {
			++numClientsProcessed;

			if (!client->m_rpcId) {
				// Not logged in yet, on_login() will send the job to this client
				continue;
			}

			if (extra_nonce >= data->m_numClientsExpected) {
				// We don't have any more extra_nonce values available
				continue;
			}

			uint8_t* hashing_blob = data->m_blobs.data() + extra_nonce * data->m_blobSize;

			uint32_t job_id;
			{
				MutexLock lock3(client->m_jobsLock);

				job_id = client->m_perConnectionJobId++;

				StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(client->m_jobs)];
				saved_job.job_id = job_id;
				saved_job.extra_nonce = extra_nonce;
				saved_job.template_id = data->m_templateId;
				saved_job.target = data->m_target;
			}

			const bool result = send(client,
				[data, client, hashing_blob, &job_id](void* buf)
				{
					log::Stream s(reinterpret_cast<char*>(buf));
					s << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{\"blob\":\"";
					s << log::hex_buf(hashing_blob, data->m_blobSize) << "\",\"job_id\":\"";
					s << log::Hex(job_id) << "\",\"target\":\"";
					s << log::hex_buf(reinterpret_cast<const uint8_t*>(&data->m_target), sizeof(data->m_target)) << "\",\"algo\":\"rx/0\",\"height\":";
					s << data->m_height << ",\"seed_hash\":\"";
					s << data->m_seedHash << "\"}}\n";
					return s.m_pos;
				});

			if (result) {
				++extra_nonce;
			}
			else {
				client->close();
			}
		}

		if (numClientsProcessed != m_numConnections) {
			LOGWARN(1, "client list is broken, expected " << m_numConnections << ", got " << numClientsProcessed << " clients");
		}
	}

	LOGINFO(3, "sent new job to " << extra_nonce << '/' << numClientsProcessed << " clients");
}

void StratumServer::on_share_found(uv_work_t* req)
{
	num_running_jobs.fetch_add(1);

	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);
	StratumClient* client = share->m_client;
	StratumServer* server = share->m_server;
	p2pool* pool = server->m_pool;
	BlockTemplate& block = pool->block_template();

	if (pool->stopped()) {
		LOGWARN(0, "p2pool is shutting down, but a share was found. Trying to process it anyway!");
	}

	uint8_t blob[128];
	uint64_t height;
	difficulty_type difficulty;
	difficulty_type sidechain_difficulty;
	hash seed_hash;
	size_t nonce_offset;

	const uint32_t blob_size = block.get_hashing_blob(share->m_templateId, share->m_extraNonce, blob, height, difficulty, sidechain_difficulty, seed_hash, nonce_offset);
	if (!blob_size) {
		LOGWARN(1, "client: got a stale share");
		share->m_result = SubmittedShare::Result::STALE;
		return;
	}

	for (uint32_t i = 0, nonce = share->m_nonce; i < sizeof(share->m_nonce); ++i) {
		blob[nonce_offset + i] = nonce & 255;
		nonce >>= 8;
	}

	hash pow_hash;
	if (!pool->calculate_hash(blob, blob_size, seed_hash, pow_hash)) {
		LOGWARN(1, "client: couldn't check share PoW");
		share->m_result = SubmittedShare::Result::COULDNT_CHECK_POW;
		return;
	}

	// Send the response to miner
	const uint64_t value = *reinterpret_cast<uint64_t*>(pow_hash.h + HASH_SIZE - sizeof(uint64_t));
	const uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());

	if (LIKELY(value < target)) {
		LOGINFO(0, log::Green() << "SHARE FOUND at mainchain height " << height);
		share->m_result = SubmittedShare::Result::OK;
	}
	else {
		LOGWARN(1, "got a low diff share from " << static_cast<char*>(client->m_addrString));
		share->m_result = SubmittedShare::Result::LOW_DIFF;
	}

	// First check if we found a mainnet block
	if (difficulty.check_pow(pow_hash)) {
		pool->submit_block(share->m_templateId, share->m_nonce, share->m_extraNonce);
		block.update_tx_keys();
	}

	// Then check if we found a sidechain block
	if (sidechain_difficulty.check_pow(pow_hash)) {
		pool->submit_sidechain_block(share->m_templateId, share->m_nonce, share->m_extraNonce);
	}
}

void StratumServer::on_after_share_found(uv_work_t* req, int /*status*/)
{
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);

	ON_SCOPE_LEAVE(
		[share]()
		{
			num_running_jobs.fetch_sub(1);

			MutexLock lock(share->m_server->m_submittedSharesPoolLock);
			share->m_server->m_submittedSharesPool.push_back(share);
		});

	StratumClient* client = share->m_client;
	StratumServer* server = share->m_server;

	if ((client->m_resetCounter.load() == share->m_clientResetCounter) && (client->m_rpcId == share->m_rpcId)) {
		const bool result = server->send(client,
			[share](void* buf)
			{
				log::Stream s(reinterpret_cast<char*>(buf));
				switch (share->m_result) {
				case SubmittedShare::Result::STALE:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n";
					break;
				case SubmittedShare::Result::COULDNT_CHECK_POW:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Couldn't check PoW\"}}\n";
					break;
				case SubmittedShare::Result::LOW_DIFF:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Low diff share\"}}\n";
					break;
				case SubmittedShare::Result::OK:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n";
					break;
				}
				return s.m_pos;
			});

		if (share->m_result == SubmittedShare::Result::LOW_DIFF) {
			client->ban(DEFAULT_BAN_TIME);
			client->close();
		}
		else if (!result) {
			client->close();
		}
	}
}

StratumServer::StratumClient::StratumClient()
	: m_rpcId(0)
	, m_jobs{}
	, m_perConnectionJobId(0)
{
	uv_mutex_init_checked(&m_jobsLock);
}

StratumServer::StratumClient::~StratumClient()
{
	uv_mutex_destroy(&m_jobsLock);
}

void StratumServer::StratumClient::reset()
{
	Client::reset();
	m_rpcId = 0;
	memset(m_jobs, 0, sizeof(m_jobs));
	m_perConnectionJobId = 0;
}

bool StratumServer::StratumClient::on_read(char* data, uint32_t size)
{
	if ((data != m_readBuf + m_numRead) || (data + size > m_readBuf + sizeof(m_readBuf))) {
		LOGERR(1, "client: invalid data pointer or size in on_read()");
		ban(DEFAULT_BAN_TIME);
		return false;
	}

	m_numRead += size;

	char* line_start = m_readBuf;
	for (char* c = data; c < m_readBuf + m_numRead; ++c) {
		if (*c == '\n') {
			*c = '\0';
			if (!process_request(line_start, static_cast<uint32_t>(c - line_start))) {
				ban(DEFAULT_BAN_TIME);
				return false;
			}
			line_start = c + 1;
		}
	}

	// Move the possible unfinished line to the beginning of m_readBuf to free up more space for reading
	if (line_start != m_readBuf) {
		m_numRead = static_cast<uint32_t>(m_readBuf + m_numRead - line_start);
		if (m_numRead > 0) {
			memmove(m_readBuf, line_start, m_numRead);
		}
	}

	return true;
}

bool StratumServer::StratumClient::process_request(char* data, uint32_t /*size*/)
{
	rapidjson::Document doc;
	if (doc.ParseInsitu(data).HasParseError()) {
		LOGWARN(1, "client: invalid JSON request ('id' field not found)");
		return false;
	}

	if (!doc.IsObject()) {
		LOGWARN(1, "client: invalid JSON request (not an object)");
		return false;
	}

	if (!doc.HasMember("id")) {
		LOGWARN(1, "client: invalid JSON request ('id' field not found)");
		return false;
	}

	auto& id = doc["id"];
	if (!id.IsUint()) {
		LOGWARN(1, "client: invalid JSON request ('id' field is not an integer)");
		return false;
	}

	if (!doc.HasMember("method")) {
		LOGWARN(1, "client: invalid JSON request ('method' field not found)");
		return false;
	}

	auto& method = doc["method"];
	if (!method.IsString()) {
		LOGWARN(1, "client: invalid JSON request ('method' field is not a string)");
		return false;
	}

	const char* s = method.GetString();
	if (strcmp(s, "login") == 0) {
		LOGINFO(5, "incoming login from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_login(doc, id.GetUint());
	}
	else if (strcmp(s, "submit") == 0) {
		LOGINFO(3, "incoming share from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_submit(doc, id.GetUint());
	}
	else {
		LOGWARN(1, "client: invalid JSON request (unknown method)");
		return false;
	}

	return true;
}

bool StratumServer::StratumClient::process_login(rapidjson::Document& /*doc*/, uint32_t id)
{
	return static_cast<StratumServer*>(m_owner)->on_login(this, id);
}

bool StratumServer::StratumClient::process_submit(rapidjson::Document& doc, uint32_t id)
{
	if (!doc.HasMember("params")) {
		LOGWARN(1, "client: invalid JSON request ('params' field not found)");
		return false;
	}

	auto& params = doc["params"];
	if (!params.IsObject()) {
		LOGWARN(1, "client: invalid JSON request ('params' field is not an object)");
		return false;
	}

	if (!params.HasMember("id")) {
		LOGWARN(1, "client: invalid params ('id' field not found)");
		return false;
	}

	auto& rpcId = params["id"];
	if (!rpcId.IsString()) {
		LOGWARN(1, "client: invalid params ('id' field is not a string)");
		return false;
	}

	if (!params.HasMember("job_id")) {
		LOGWARN(1, "client: invalid params ('job_id' field not found)");
		return false;
	}

	auto& job_id = params["job_id"];
	if (!job_id.IsString()) {
		LOGWARN(1, "client: invalid params ('job_id' field is not a string)");
		return false;
	}

	if (!params.HasMember("nonce")) {
		LOGWARN(1, "client: invalid params ('nonce' field not found)");
		return false;
	}

	auto& nonce = params["nonce"];
	if (!nonce.IsString()) {
		LOGWARN(1, "client: invalid params ('nonce' field is not a string)");
		return false;
	}

	if (nonce.GetStringLength() != sizeof(uint32_t) * 2) {
		LOGWARN(1, "client: invalid params ('nonce' field has invalid length)");
		return false;
	}

	return static_cast<StratumServer*>(m_owner)->on_submit(this, id, job_id.GetString(), nonce.GetString());
}

} // namespace p2pool

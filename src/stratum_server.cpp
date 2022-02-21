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
#include "side_chain.h"
#include "params.h"
#include "p2pool_api.h"

static constexpr char log_category_prefix[] = "StratumServer ";

static constexpr int DEFAULT_BACKLOG = 128;
static constexpr uint64_t DEFAULT_BAN_TIME = 600;

// Use short target format (4 bytes) for diff <= 4 million
static constexpr uint64_t TARGET_4_BYTES_LIMIT = std::numeric_limits<uint64_t>::max() / 4000000;

#include "tcp_server.inl"

namespace p2pool {

StratumServer::StratumServer(p2pool* pool)
	: TCPServer(StratumClient::allocate)
	, m_pool(pool)
	, m_extraNonce(0)
	, m_rd{}
	, m_rng(m_rd())
	, m_cumulativeHashes(0)
	, m_cumulativeHashesAtLastShare(0)
	, m_hashrateDataHead(0)
	, m_hashrateDataTail_15m(0)
	, m_hashrateDataTail_1h(0)
	, m_hashrateDataTail_24h(0)
	, m_cumulativeFoundSharesDiff(0.0)
	, m_totalFoundShares(0)
	, m_apiLastUpdateTime(0)
{
	m_hashrateData[0] = { time(nullptr), 0 };

	uv_mutex_init_checked(&m_blobsQueueLock);
	uv_mutex_init_checked(&m_rngLock);
	uv_mutex_init_checked(&m_submittedSharesPoolLock);
	uv_rwlock_init_checked(&m_hashrateDataLock);

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

	start_listening(pool->params().m_stratumAddresses);
}

StratumServer::~StratumServer()
{
	uv_close(reinterpret_cast<uv_handle_t*>(&m_blobsAsync), nullptr);

	shutdown_tcp();

	uv_mutex_destroy(&m_blobsQueueLock);
	uv_mutex_destroy(&m_rngLock);
	uv_mutex_destroy(&m_submittedSharesPoolLock);
	uv_rwlock_destroy(&m_hashrateDataLock);

	for (SubmittedShare* share : m_submittedSharesPool) {
		delete share;
	}
}

void StratumServer::on_block(const BlockTemplate& block)
{
	LOGINFO(4, "new block template at height " << block.height());

	const uint32_t num_connections = m_numConnections;
	if (num_connections == 0) {
		LOGINFO(4, "no clients connected");
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

	// Integrity checks
	if (blobs_data->m_blobSize < 76) {
		LOGERR(1, "internal error: get_hashing_blobs returned too small blobs (" << blobs_data->m_blobSize << " bytes)");
	}
	else if (blobs_data->m_blobs.size() != blobs_data->m_blobSize * num_connections) {
		LOGERR(1, "internal error: get_hashing_blobs returned wrong amount of data");
	}
	else if (num_connections > 1) {
		std::vector<uint64_t> blob_hashes;
		blob_hashes.reserve(num_connections);

		const uint8_t* data = blobs_data->m_blobs.data();
		const size_t size = blobs_data->m_blobSize;

		// Get first 8 bytes of the Merkle root hash from each blob
		for (size_t i = 0; i < num_connections; ++i) {
			blob_hashes.emplace_back(*reinterpret_cast<const uint64_t*>(data + i * size + 43));
		}

		// Find duplicates
		std::sort(blob_hashes.begin(), blob_hashes.end());

		for (uint32_t i = 1; i < num_connections; ++i) {
			if (blob_hashes[i - 1] == blob_hashes[i]) {
				LOGERR(1, "internal error: get_hashing_blobs returned two identical blobs");
				break;
			}
		}
	}

	blobs_data->m_target = std::max(difficulty.target(), sidechain_difficulty.target());

	{
		MutexLock lock(m_blobsQueueLock);
		m_blobsQueue.push_back(blobs_data);
	}

	if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_blobsAsync))) {
		return;
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

bool StratumServer::get_custom_user(const char* s, std::string& user)
{
	user.clear();
	// Find first of '+' or '.', drop non-printable characters
	while (s && (user.length() < 64)) {
		const char c = *s;
		if (!c) {
			break;
		}
		if ((c == '+') || (c == '.')) {
			break;
		}
		// Limit to printable ASCII characters
		if (c >= ' ' && c <= '~') {
			user += c;
		}
		++s;
	}

	return !user.empty();
}

bool StratumServer::get_custom_diff(const char* s, difficulty_type& diff)
{
	const char* diff_str = nullptr;

	// Find last of '+' or '.'
	while (s) {
		const char c = *s;
		if (!c) {
			break;
		}
		if ((c == '+') || (c == '.')) {
			diff_str = s;
		}
		++s;
	}

	if (diff_str) {
		const uint64_t t = strtoull(diff_str + 1, nullptr, 10);
		if (t) {
			// Don't let clients set difficulty less than 1000
			diff = { std::max<uint64_t>(t + 1, 1000), 0 };
			return true;
		}
	}

	return false;
}

bool StratumServer::on_login(StratumClient* client, uint32_t id, const char* login)
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

	uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());

	if (get_custom_diff(login, client->m_customDiff)) {
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << " set custom difficulty " << client->m_customDiff);
		target = std::max(target, client->m_customDiff.target());
	}

	if (get_custom_user(login, client->m_customUser)) {
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << " set custom user " << client->m_customUser);
	}

	uint32_t job_id;
	{
		MutexLock lock(client->m_jobsLock);

		job_id = client->m_perConnectionJobId++;

		StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(&StratumClient::m_jobs)];
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

			log::hex_buf target_hex(reinterpret_cast<const uint8_t*>(&target), sizeof(uint64_t));

			if (target >= TARGET_4_BYTES_LIMIT) {
				target_hex.m_data += sizeof(uint32_t);
				target_hex.m_size -= sizeof(uint32_t);
			}

			log::Stream s(reinterpret_cast<char*>(buf));
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{\"id\":\"";
			s << log::Hex(client->m_rpcId) << "\",\"job\":{\"blob\":\"";
			s << log::hex_buf(hashing_blob, blob_size) << "\",\"job_id\":\"";
			s << log::Hex(job_id) << "\",\"target\":\"";
			s << target_hex << "\",\"algo\":\"rx/0\",\"height\":";
			s << height << ",\"seed_hash\":\"";
			s << seed_hash << "\"},\"extensions\":[\"algo\"],\"status\":\"OK\"}}\n";
			return s.m_pos;
		});

	return result;
}

bool StratumServer::on_submit(StratumClient* client, uint32_t id, const char* job_id_str, const char* nonce_str, const char* result_str)
{
	uint32_t job_id = 0;

	for (size_t i = 0; job_id_str[i]; ++i) {
		uint32_t d;
		if (!from_hex(job_id_str[i], d)) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('job_id' is not a hex integer)");
			return false;
		}
		job_id = (job_id << 4) + d;
	}

	uint32_t nonce = 0;

	for (int i = static_cast<int>(sizeof(uint32_t)) - 1; i >= 0; --i) {
		uint32_t d[2];
		if (!from_hex(nonce_str[i * 2], d[0]) || !from_hex(nonce_str[i * 2 + 1], d[1])) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('nonce' is not a hex integer)");
			return false;
		}
		nonce = (nonce << 8) | (d[0] << 4) | d[1];
	}

	hash resultHash;

	for (size_t i = 0; i < HASH_SIZE; ++i) {
		uint32_t d[2];
		if (!from_hex(result_str[i * 2], d[0]) || !from_hex(result_str[i * 2 + 1], d[1])) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('result' is not a hex value)");
			return false;
		}
		resultHash.h[i] = static_cast<uint8_t>((d[0] << 4) | d[1]);
	}

	uint32_t template_id = 0;
	uint32_t extra_nonce = 0;
	uint64_t target = 0;

	bool found = false;
	{
		MutexLock lock(client->m_jobsLock);

		const StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(&StratumClient::m_jobs)];
		if (saved_job.job_id == job_id) {
			template_id = saved_job.template_id;
			extra_nonce = saved_job.extra_nonce;
			target = saved_job.target;
			found = true;
		}
	}

	if (found) {
		BlockTemplate& block = m_pool->block_template();
		difficulty_type mainchain_diff, sidechain_diff;

		if (!block.get_difficulties(template_id, mainchain_diff, sidechain_diff)) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a stale share");
			return send(client,
				[id](void* buf)
				{
					log::Stream s(reinterpret_cast<char*>(buf));
					s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n";
					return s.m_pos;
				});
		}

		if (mainchain_diff.check_pow(resultHash)) {
			const std::string& s = client->m_customUser;
			LOGINFO(0, log::Green() << "client " << static_cast<char*>(client->m_addrString) << (!s.empty() ? " user " : "") << s << " found a mainchain block, submitting it");
			m_pool->submit_block_async(template_id, nonce, extra_nonce);
			block.update_tx_keys();
		}

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
		share->m_clientAddr = client->m_addr;
		share->m_clientResetCounter = client->m_resetCounter.load();
		share->m_rpcId = client->m_rpcId;
		share->m_id = id;
		share->m_templateId = template_id;
		share->m_nonce = nonce;
		share->m_extraNonce = extra_nonce;
		share->m_target = target;
		share->m_resultHash = resultHash;
		share->m_sidechainDifficulty = sidechain_diff;

		// If this share is below sidechain difficulty, process it in this thread because it'll be quick
		if (!share->m_sidechainDifficulty.check_pow(share->m_resultHash)) {
			on_share_found(&share->m_req);
			on_after_share_found(&share->m_req, 0);
			return true;
		}

		// Else switch to a worker thread to check PoW which can take a long time
		const int err = uv_queue_work(&m_loop, &share->m_req, on_share_found, on_after_share_found);
		if (err) {
			LOGERR(1, "uv_queue_work failed, error " << uv_err_name(err));

			// If uv_queue_work failed, process this share here anyway
			on_share_found(&share->m_req);
			on_after_share_found(&share->m_req, 0);
		}

		return true;
	}

	LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a share with invalid job id");

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

void StratumServer::print_status()
{
	update_hashrate_data(0, time(nullptr));
	print_stratum_status();
}

void StratumServer::reset_share_counters()
{
	m_cumulativeHashesAtLastShare = 0;
	m_cumulativeFoundSharesDiff = 0.0;
	m_totalFoundShares = 0;
}

void StratumServer::print_stratum_status() const
{
	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;

	{
		ReadLock lock(m_hashrateDataLock);

		total_hashes = m_cumulativeHashes;
		hashes_since_last_share = m_cumulativeHashes - m_cumulativeHashesAtLastShare;

		const HashrateData* data = m_hashrateData;
		const HashrateData& head = data[m_hashrateDataHead];
		const HashrateData& tail_15m = data[m_hashrateDataTail_15m];
		const HashrateData& tail_1h = data[m_hashrateDataTail_1h];
		const HashrateData& tail_24h = data[m_hashrateDataTail_24h];

		hashes_15m = head.m_cumulativeHashes - tail_15m.m_cumulativeHashes;
		dt_15m = static_cast<int64_t>(head.m_timestamp - tail_15m.m_timestamp);

		hashes_1h = head.m_cumulativeHashes - tail_1h.m_cumulativeHashes;
		dt_1h = static_cast<int64_t>(head.m_timestamp - tail_1h.m_timestamp);

		hashes_24h = head.m_cumulativeHashes - tail_24h.m_cumulativeHashes;
		dt_24h = static_cast<int64_t>(head.m_timestamp - tail_24h.m_timestamp);
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	double average_effort = 0.0;
	const double diff = m_cumulativeFoundSharesDiff;
	if (diff > 0.0) {
		average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
	}

	LOGINFO(0, "status" <<
		"\nHashrate (15m est) = " << log::Hashrate(hashrate_15m) <<
		"\nHashrate (1h  est) = " << log::Hashrate(hashrate_1h) <<
		"\nHashrate (24h est) = " << log::Hashrate(hashrate_24h) <<
		"\nTotal hashes       = " << total_hashes <<
		"\nShares found       = " << m_totalFoundShares <<
		"\nAverage effort     = " << average_effort << '%' <<
		"\nCurrent effort     = " << static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double() << '%' <<
		"\nConnections        = " << m_numConnections << " (" << m_numIncomingConnections << " incoming)"
	);
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

	const time_t cur_time = time(nullptr);
	{
		MutexLock lock2(m_clientsListLock);

		for (StratumClient* client = static_cast<StratumClient*>(m_connectedClientsList->m_prev); client != m_connectedClientsList; client = static_cast<StratumClient*>(client->m_prev)) {
			++numClientsProcessed;

			if (!client->m_rpcId) {
				// Not logged in yet, on_login() will send the job to this client. Also close inactive connections.
				if (cur_time >= client->m_connectedTime + 10) {
					LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " didn't send login data");
					client->ban(DEFAULT_BAN_TIME);
					client->close();
				}
				continue;
			}

			if (extra_nonce >= data->m_numClientsExpected) {
				// We don't have any more extra_nonce values available
				continue;
			}

			uint8_t* hashing_blob = data->m_blobs.data() + extra_nonce * data->m_blobSize;

			uint64_t target = data->m_target;
			if (client->m_customDiff.lo) {
				target = std::max(target, client->m_customDiff.target());
			}

			uint32_t job_id;
			{
				MutexLock lock3(client->m_jobsLock);

				job_id = client->m_perConnectionJobId++;

				StratumClient::SavedJob& saved_job = client->m_jobs[job_id % array_size(&StratumClient::m_jobs)];
				saved_job.job_id = job_id;
				saved_job.extra_nonce = extra_nonce;
				saved_job.template_id = data->m_templateId;
				saved_job.target = target;
			}

			const bool result = send(client,
				[data, target, hashing_blob, &job_id](void* buf)
				{
					log::hex_buf target_hex(reinterpret_cast<const uint8_t*>(&target), sizeof(uint64_t));

					if (target >= TARGET_4_BYTES_LIMIT) {
						target_hex.m_data += sizeof(uint32_t);
						target_hex.m_size -= sizeof(uint32_t);
					}

					log::Stream s(reinterpret_cast<char*>(buf));
					s << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{\"blob\":\"";
					s << log::hex_buf(hashing_blob, data->m_blobSize) << "\",\"job_id\":\"";
					s << log::Hex(job_id) << "\",\"target\":\"";
					s << target_hex << "\",\"algo\":\"rx/0\",\"height\":";
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

void StratumServer::update_hashrate_data(uint64_t hashes, time_t timestamp)
{
	constexpr size_t N = array_size(&StratumServer::m_hashrateData);

	WriteLock lock(m_hashrateDataLock);

	m_cumulativeHashes += hashes;

	HashrateData* data = m_hashrateData;
	HashrateData& head = data[m_hashrateDataHead];
	if (head.m_timestamp == timestamp) {
		head.m_cumulativeHashes = m_cumulativeHashes;
	}
	else {
		m_hashrateDataHead = (m_hashrateDataHead + 1) % N;
		data[m_hashrateDataHead] = { timestamp, m_cumulativeHashes };
	}

	while (data[m_hashrateDataTail_15m].m_timestamp + 15 * 60 < timestamp) {
		m_hashrateDataTail_15m = (m_hashrateDataTail_15m + 1) % N;
	}

	while (data[m_hashrateDataTail_1h].m_timestamp + 60 * 60 < timestamp) {
		m_hashrateDataTail_1h = (m_hashrateDataTail_1h + 1) % N;
	}

	while (data[m_hashrateDataTail_24h].m_timestamp + 60 * 60 * 24 < timestamp) {
		m_hashrateDataTail_24h = (m_hashrateDataTail_24h + 1) % N;
	}
}

void StratumServer::on_share_found(uv_work_t* req)
{
	bkg_jobs_tracker.start("StratumServer::on_share_found");

	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);
	StratumClient* client = share->m_client;
	StratumServer* server = share->m_server;
	p2pool* pool = server->m_pool;

	uint64_t target = share->m_target;
	if (target >= TARGET_4_BYTES_LIMIT) {
		target = (target >> 32) << 32;
	}

	uint64_t rem;
	const uint64_t hashes = (target > 1) ? udiv128(1, 0, target, &rem) : 0;

	if (pool->stopped()) {
		LOGWARN(0, "p2pool is shutting down, but a share was found. Trying to process it anyway!");
	}

	if (share->m_sidechainDifficulty.check_pow(share->m_resultHash)) {
		uint8_t blob[128];
		uint64_t height;
		difficulty_type difficulty;
		difficulty_type sidechain_difficulty;
		hash seed_hash;
		size_t nonce_offset;

		const uint32_t blob_size = pool->block_template().get_hashing_blob(share->m_templateId, share->m_extraNonce, blob, height, difficulty, sidechain_difficulty, seed_hash, nonce_offset);
		if (!blob_size) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a stale share");
			share->m_result = SubmittedShare::Result::STALE;
			return;
		}

		for (uint32_t i = 0, nonce = share->m_nonce; i < sizeof(share->m_nonce); ++i) {
			blob[nonce_offset + i] = nonce & 255;
			nonce >>= 8;
		}

		hash pow_hash;
		if (!pool->calculate_hash(blob, blob_size, height, seed_hash, pow_hash)) {
			LOGWARN(3, "client " << static_cast<char*>(client->m_addrString) << " couldn't check share PoW");
			share->m_result = SubmittedShare::Result::COULDNT_CHECK_POW;
			return;
		}

		if (pow_hash != share->m_resultHash) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " submitted a share with invalid PoW");
			share->m_result = SubmittedShare::Result::INVALID_POW;
			return;
		}

		const uint64_t n = server->m_cumulativeHashes + hashes;
		const double diff = sidechain_difficulty.to_double();
		const double effort = static_cast<double>(n - server->m_cumulativeHashesAtLastShare) * 100.0 / diff;
		server->m_cumulativeHashesAtLastShare = n;

		server->m_cumulativeFoundSharesDiff += diff;
		++server->m_totalFoundShares;

		const std::string& s = client->m_customUser;
		LOGINFO(0, log::Green() << "SHARE FOUND: mainchain height " << height << ", diff " << sidechain_difficulty << ", client " << static_cast<char*>(client->m_addrString) << (!s.empty() ? " user " : "") << s << ", effort " << effort << '%');
		pool->submit_sidechain_block(share->m_templateId, share->m_nonce, share->m_extraNonce);
	}

	// Send the response to miner
	const uint64_t value = *reinterpret_cast<uint64_t*>(share->m_resultHash.h + HASH_SIZE - sizeof(uint64_t));

	if (LIKELY(value < target)) {
		const time_t timestamp = time(nullptr);
		server->update_hashrate_data(hashes, timestamp);
		server->api_update_local_stats(timestamp);
		share->m_result = SubmittedShare::Result::OK;
	}
	else {
		LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a low diff share");
		share->m_result = SubmittedShare::Result::LOW_DIFF;
	}
}

void StratumServer::on_after_share_found(uv_work_t* req, int /*status*/)
{
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);

	ON_SCOPE_LEAVE(
		[share]()
		{
			{
				MutexLock lock(share->m_server->m_submittedSharesPoolLock);
				share->m_server->m_submittedSharesPool.push_back(share);
			}
			bkg_jobs_tracker.stop("StratumServer::on_share_found");
		});

	StratumClient* client = share->m_client;
	StratumServer* server = share->m_server;

	const bool bad_share = (share->m_result == SubmittedShare::Result::LOW_DIFF) || (share->m_result == SubmittedShare::Result::INVALID_POW);

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
				case SubmittedShare::Result::INVALID_POW:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid PoW\"}}\n";
					break;
				case SubmittedShare::Result::OK:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n";
					break;
				}
				return s.m_pos;
			});

		if (bad_share) {
			client->ban(DEFAULT_BAN_TIME);
			client->close();
		}
		else if (!result) {
			client->close();
		}
	}
	else if (bad_share) {
		server->ban(share->m_clientAddr, DEFAULT_BAN_TIME);
	}
}

StratumServer::StratumClient::StratumClient()
	: m_rpcId(0)
	, m_connectedTime(0)
	, m_jobs{}
	, m_perConnectionJobId(0)
	, m_customDiff{}
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
	m_connectedTime = 0;
	memset(m_jobs, 0, sizeof(m_jobs));
	m_perConnectionJobId = 0;
	m_customDiff = {};
	m_customUser.clear();
}

bool StratumServer::StratumClient::on_connect()
{
	m_connectedTime = time(nullptr);
	return true;
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
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (parse error)");
		return false;
	}

	if (!doc.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (not an object)");
		return false;
	}

	if (!doc.HasMember("id")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('id' field not found)");
		return false;
	}

	auto& id = doc["id"];
	if (!id.IsUint()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('id' field is not an integer)");
		return false;
	}

	if (!doc.HasMember("method")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('method' field not found)");
		return false;
	}

	auto& method = doc["method"];
	if (!method.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('method' field is not a string)");
		return false;
	}

	const char* s = method.GetString();
	if (strcmp(s, "login") == 0) {
		LOGINFO(6, "incoming login from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_login(doc, id.GetUint());
	}
	else if (strcmp(s, "submit") == 0) {
		LOGINFO(6, "incoming share from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_submit(doc, id.GetUint());
	}
	else if (strcmp(s, "keepalived") == 0) {
		LOGINFO(6, "incoming keepalive from " << log::Gray() << static_cast<char*>(m_addrString));
		return true;
	}
	else {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (unknown method)");
		return false;
	}

	return true;
}

bool StratumServer::StratumClient::process_login(rapidjson::Document& doc, uint32_t id)
{
	if (!doc.HasMember("params")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON login request ('params' field not found)");
		return false;
	}

	auto& params = doc["params"];
	if (!params.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON login request ('params' field is not an object)");
		return false;
	}

	if (!params.HasMember("login")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid login params ('login' field not found)");
		return false;
	}

	auto& login = params["login"];
	if (!login.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid login params ('login' field is not a string)");
		return false;
	}

	return static_cast<StratumServer*>(m_owner)->on_login(this, id, login.GetString());
}

bool StratumServer::StratumClient::process_submit(rapidjson::Document& doc, uint32_t id)
{
	if (!doc.HasMember("params")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON submit request ('params' field not found)");
		return false;
	}

	auto& params = doc["params"];
	if (!params.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON submit request ('params' field is not an object)");
		return false;
	}

	if (!params.HasMember("id")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('id' field not found)");
		return false;
	}

	auto& rpcId = params["id"];
	if (!rpcId.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('id' field is not a string)");
		return false;
	}

	if (!params.HasMember("job_id")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('job_id' field not found)");
		return false;
	}

	auto& job_id = params["job_id"];
	if (!job_id.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('job_id' field is not a string)");
		return false;
	}

	if (!params.HasMember("nonce")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field not found)");
		return false;
	}

	auto& nonce = params["nonce"];
	if (!nonce.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field is not a string)");
		return false;
	}

	if (nonce.GetStringLength() != sizeof(uint32_t) * 2) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field has invalid length)");
		return false;
	}

	if (!params.HasMember("result")) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field not found)");
		return false;
	}

	auto& result = params["result"];
	if (!result.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field is not a string)");
		return false;
	}

	if (result.GetStringLength() != HASH_SIZE * 2) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field has invalid length)");
		return false;
	}

	return static_cast<StratumServer*>(m_owner)->on_submit(this, id, job_id.GetString(), nonce.GetString(), result.GetString());
}

void StratumServer::api_update_local_stats(time_t timestamp)
{
	if (!m_pool->api() || !m_pool->params().m_localStats) {
		return;
	}

	// Rate limit to no more than once in 60 seconds.
	if (timestamp < m_apiLastUpdateTime + 60) {
		return;
	}

	m_apiLastUpdateTime = timestamp;

	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;

	{
		ReadLock lock(m_hashrateDataLock);

		total_hashes = m_cumulativeHashes;
		hashes_since_last_share = m_cumulativeHashes - m_cumulativeHashesAtLastShare;

		const HashrateData* data = m_hashrateData;
		const HashrateData& head = data[m_hashrateDataHead];
		const HashrateData& tail_15m = data[m_hashrateDataTail_15m];
		const HashrateData& tail_1h = data[m_hashrateDataTail_1h];
		const HashrateData& tail_24h = data[m_hashrateDataTail_24h];

		hashes_15m = head.m_cumulativeHashes - tail_15m.m_cumulativeHashes;
		dt_15m = static_cast<int64_t>(head.m_timestamp - tail_15m.m_timestamp);

		hashes_1h = head.m_cumulativeHashes - tail_1h.m_cumulativeHashes;
		dt_1h = static_cast<int64_t>(head.m_timestamp - tail_1h.m_timestamp);

		hashes_24h = head.m_cumulativeHashes - tail_24h.m_cumulativeHashes;
		dt_24h = static_cast<int64_t>(head.m_timestamp - tail_24h.m_timestamp);
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	double average_effort = 0.0;
	const double diff = m_cumulativeFoundSharesDiff;
	if (diff > 0.0) {
		average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
	}

	int shares_found = m_totalFoundShares;

	double current_effort = static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double();

	int connections = m_numConnections;
	int incoming_connections = m_numIncomingConnections;

	m_pool->api()->set(p2pool_api::Category::LOCAL, "stats",
		[hashrate_15m, hashrate_1h, hashrate_24h, total_hashes, shares_found, average_effort, current_effort, connections, incoming_connections](log::Stream& s)
		{
			s << "{\"hashrate_15m\":" << hashrate_15m
				<< ",\"hashrate_1h\":" << hashrate_1h
				<< ",\"hashrate_24h\":" << hashrate_24h
				<< ",\"total_hashes\":" << total_hashes
				<< ",\"shares_found\":" << shares_found
				<< ",\"average_effort\":" << average_effort
				<< ",\"current_effort\":" << current_effort
				<< ",\"connections\":" << connections
				<< ",\"incoming_connections\":" << incoming_connections
				<< "}";
		});
}

} // namespace p2pool

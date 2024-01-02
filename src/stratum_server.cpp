/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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

LOG_CATEGORY(StratumServer)

static constexpr int DEFAULT_BACKLOG = 128;
static constexpr uint64_t DEFAULT_BAN_TIME = 600;
static constexpr uint64_t MIN_DIFF = 1000;
static constexpr uint64_t AUTO_DIFF_TARGET_TIME = 30;

// Use short target format (4 bytes) for diff <= 4 million
static constexpr uint64_t TARGET_4_BYTES_LIMIT = std::numeric_limits<uint64_t>::max() / 4000001;

static constexpr int32_t BAD_SHARE_POINTS = -5;
static constexpr int32_t GOOD_SHARE_POINTS = 1;
static constexpr int32_t BAN_THRESHOLD_POINTS = -15;

namespace p2pool {

StratumServer::StratumServer(p2pool* pool)
	: TCPServer(DEFAULT_BACKLOG, StratumClient::allocate)
	, m_pool(pool)
	, m_autoDiff(pool->params().m_autoDiff)
	, m_rng(RandomDeviceSeed::instance)
	, m_cumulativeHashes(0)
	, m_cumulativeHashesAtLastShare(0)
	, m_hashrateDataHead(0)
	, m_hashrateDataTail_15m(0)
	, m_hashrateDataTail_1h(0)
	, m_hashrateDataTail_24h(0)
	, m_cumulativeFoundSharesDiff(0.0)
	, m_totalFoundShares(0)
	, m_totalFailedShares(0)
	, m_apiLastUpdateTime(0)
{
	m_callbackBuf.resize(STRATUM_BUF_SIZE);

	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	m_hashrateData[0] = { seconds_since_epoch(), 0 };

	uv_mutex_init_checked(&m_blobsQueueLock);
	uv_mutex_init_checked(&m_showWorkersLock);
	uv_mutex_init_checked(&m_rngLock);
	uv_rwlock_init_checked(&m_hashrateDataLock);

	m_extraNonce = get_random32();

	m_submittedSharesPool.resize(10);
	for (size_t i = 0; i < m_submittedSharesPool.size(); ++i) {
		SubmittedShare* share = new SubmittedShare{};
		ASAN_POISON_MEMORY_REGION(share, sizeof(SubmittedShare));
		m_submittedSharesPool[i] = share;
	}

	uv_async_init_checked(&m_loop, &m_blobsAsync, on_blobs_ready);
	m_blobsAsync.data = this;
	m_blobsQueue.reserve(2);

	uv_async_init_checked(&m_loop, &m_showWorkersAsync, on_show_workers);
	m_showWorkersAsync.data = this;

	const Params& params = pool->params();
	start_listening(params.m_stratumAddresses, params.m_upnp && params.m_upnpStratum);
}

StratumServer::~StratumServer()
{
	shutdown_tcp();

	{
		MutexLock lock(m_blobsQueueLock);

		for (BlobsData* data : m_blobsQueue) {
			delete data;
		}
	}

	uv_mutex_destroy(&m_blobsQueueLock);
	uv_mutex_destroy(&m_showWorkersLock);
	uv_mutex_destroy(&m_rngLock);
	uv_rwlock_destroy(&m_hashrateDataLock);

	for (SubmittedShare* share : m_submittedSharesPool) {
		ASAN_UNPOISON_MEMORY_REGION(share, sizeof(SubmittedShare));
		delete share;
	}
}

void StratumServer::on_block(const BlockTemplate& block)
{
	LOGINFO(4, "new block template at height " << block.height());

	const uint32_t num_connections = m_numConnections;
	if (num_connections == 0) {
		LOGINFO(4, "no clients connected");
		api_update_local_stats(seconds_since_epoch());
		return;
	}

	const uint32_t extra_nonce_start = get_random32();
	m_extraNonce.exchange(extra_nonce_start + num_connections);

	BlobsData* blobs_data = new BlobsData{};
	blobs_data->m_extraNonceStart = extra_nonce_start;

	difficulty_type difficulty;
	difficulty_type aux_diff;
	difficulty_type sidechain_difficulty;
	size_t nonce_offset;

	// More clients might connect between now and when we actually go through clients list - get_hashing_blobs() and async send take some time
	// Even if they do, they'll be added to the beginning of the list and will get their block template in on_login()
	// We'll iterate through the list backwards so when we get to the beginning and run out of extra_nonce values, it'll be only new clients left
	blobs_data->m_numClientsExpected = num_connections;
	blobs_data->m_blobSize = block.get_hashing_blobs(extra_nonce_start, num_connections, blobs_data->m_blobs, blobs_data->m_height, difficulty, aux_diff, sidechain_difficulty, blobs_data->m_seedHash, nonce_offset, blobs_data->m_templateId);

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
			blob_hashes.emplace_back(read_unaligned(reinterpret_cast<const uint64_t*>(data + i * size + 43)));
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
	blobs_data->m_target = std::max(blobs_data->m_target, aux_diff.target());

	{
		MutexLock lock(m_blobsQueueLock);

		if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_blobsAsync))) {
			delete blobs_data;
			return;
		}

		m_blobsQueue.push_back(blobs_data);

		const int err = uv_async_send(&m_blobsAsync);
		if (err) {
			LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));

			m_blobsQueue.pop_back();
			delete blobs_data;
		}
	}

	api_update_local_stats(seconds_since_epoch());
}

template<size_t N>
static bool get_custom_user(const char* s, char (&user)[N])
{
	size_t len = 0;

	// Find first of '+' or '.', drop non-printable characters
	while (s && (len < N - 1)) {
		const char c = *s;
		if (!c) {
			break;
		}
		if ((c == '+') || (c == '.')) {
			break;
		}
		// Limit to printable ASCII characters, also skip comma and JSON special characters
		if (c >= ' ' && c <= '~' && c != ',' && c != '"' && c != '\\') {
			user[len++] = c;
		}
		++s;
	}
	user[len] = '\0';

	return (len > 0);
}

static bool get_custom_diff(const char* s, difficulty_type& diff)
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
			// Don't let clients set difficulty less than MIN_DIFF
			diff = { std::max<uint64_t>(t + 1, MIN_DIFF), 0 };
			return true;
		}
	}

	return false;
}

bool StratumServer::on_login(StratumClient* client, uint32_t id, const char* login)
{
	if (client->m_rpcId) {
		LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " tried to login, but it's already logged in");
		return false;
	}

	const uint32_t extra_nonce = m_extraNonce.fetch_add(1);

	uint8_t hashing_blob[128];
	uint64_t height, sidechain_height;
	difficulty_type difficulty;
	difficulty_type aux_diff;
	difficulty_type sidechain_difficulty;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;

	const size_t blob_size = m_pool->block_template().get_hashing_blob(extra_nonce, hashing_blob, height, sidechain_height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset, template_id);

	uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());
	target = std::max(target, aux_diff.target());

	if (get_custom_diff(login, client->m_customDiff)) {
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << " set custom difficulty " << client->m_customDiff);
		target = std::max(target, client->m_customDiff.target());
	}
	else if (m_autoDiff) {
		// Limit autodiff to 4000000 for maximum compatibility
		target = std::max(target, TARGET_4_BYTES_LIMIT);
	}

	if (get_custom_user(login, client->m_customUser)) {
		const char* s = client->m_customUser;
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << " set custom user " << s);
	}

	uint32_t job_id;
	{
		job_id = ++client->m_perConnectionJobId;

		StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
		saved_job.job_id = job_id;
		saved_job.extra_nonce = extra_nonce;
		saved_job.template_id = template_id;
		saved_job.target = target;
	}
	client->m_lastJobTarget = target;

	const bool result = send(client,
		[client, id, &hashing_blob, job_id, blob_size, target, height, &seed_hash](uint8_t* buf, size_t buf_size)
		{
			do {
				client->m_rpcId = static_cast<StratumServer*>(client->m_owner)->get_random32();
			} while (!client->m_rpcId);

			log::hex_buf target_hex(&target);

			if (target >= TARGET_4_BYTES_LIMIT) {
				target_hex.m_data += sizeof(uint32_t);
				target_hex.m_size -= sizeof(uint32_t);
			}

			log::Stream s(buf, buf_size);
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

	if (!job_id) {
		LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('job_id' can't be 0)");
		return false;
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
		const StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
		if (saved_job.job_id == job_id) {
			template_id = saved_job.template_id;
			extra_nonce = saved_job.extra_nonce;
			target = saved_job.target;
			found = true;
		}
	}

	if (found) {
		const BlockTemplate& block = m_pool->block_template();
		uint64_t height, sidechain_height;
		difficulty_type mainchain_diff, aux_diff, sidechain_diff;

		if (!block.get_difficulties(template_id, height, sidechain_height, mainchain_diff, aux_diff, sidechain_diff)) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a stale share");
			return send(client,
				[id](uint8_t* buf, size_t buf_size)
				{
					log::Stream s(buf, buf_size);
					s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n";
					return s.m_pos;
				});
		}

		if (mainchain_diff.check_pow(resultHash)) {
			const char* s = client->m_customUser;
			LOGINFO(0, log::Green() << "client " << static_cast<char*>(client->m_addrString) << (*s ? " user " : "") << s << " found a mainchain block at height " << height << ", submitting it");
			m_pool->submit_block_async(template_id, nonce, extra_nonce);
		}

		if (aux_diff.check_pow(resultHash)) {
			for (const AuxChainData& aux_data : block.get_aux_chains(template_id)) {
				if (aux_data.difficulty.check_pow(resultHash)) {
					const char* s = client->m_customUser;
					LOGINFO(0, log::Green() << "client " << static_cast<char*>(client->m_addrString) << (*s ? " user " : "") << s << " found an aux block for chain_id " << aux_data.unique_id << ", diff " << aux_data.difficulty << ", submitting it");
					m_pool->submit_aux_block(aux_data.unique_id, template_id, nonce, extra_nonce);
				}
			}
		}

		SubmittedShare* share;

		if (!m_submittedSharesPool.empty()) {
			share = m_submittedSharesPool.back();
			m_submittedSharesPool.pop_back();
			ASAN_UNPOISON_MEMORY_REGION(share, sizeof(SubmittedShare));
		}
		else {
			share = new SubmittedShare{};
		}

		if (target >= TARGET_4_BYTES_LIMIT) {
			// "Low diff share" fix: adjust target to the same value as XMRig would use
			target = std::numeric_limits<uint64_t>::max() / (std::numeric_limits<uint32_t>::max() / (target >> 32));
		}

		share->m_req.data = share;
		share->m_server = this;
		share->m_client = client;
		share->m_clientIPv6 = client->m_isV6;
		share->m_clientAddr = client->m_addr;
		memcpy(share->m_clientAddrString, client->m_addrString, sizeof(share->m_clientAddrString));
		memcpy(share->m_clientCustomUser, client->m_customUser, sizeof(share->m_clientCustomUser));
		share->m_clientResetCounter = client->m_resetCounter.load();
		share->m_rpcId = client->m_rpcId;
		share->m_id = id;
		share->m_templateId = template_id;
		share->m_nonce = nonce;
		share->m_extraNonce = extra_nonce;
		share->m_target = target;
		share->m_resultHash = resultHash;
		share->m_sidechainDifficulty = sidechain_diff;
		share->m_mainchainHeight = height;
		share->m_sidechainHeight = sidechain_height;
		share->m_effort = -1.0;
		share->m_timestamp = seconds_since_epoch();

		uint64_t rem;
		share->m_hashes = (target > 1) ? udiv128(1, 0, target, &rem) : 1;
		share->m_highEnoughDifficulty = sidechain_diff.check_pow(resultHash);
		share->m_score = 0;

		// Don't count shares that were found during sync
		const SideChain& side_chain = m_pool->side_chain();
		const PoolBlock* tip = side_chain.chainTip();
		if (tip && (sidechain_height + side_chain.chain_window_size() < tip->m_sidechainHeight)) {
			share->m_highEnoughDifficulty = false;
		}

		update_auto_diff(client, share->m_timestamp, share->m_hashes);

		// If this share is below sidechain difficulty, process it in this thread because it'll be quick
		if (!share->m_highEnoughDifficulty) {
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

	LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a share with invalid job id " << job_id << " (latest job sent has id " << client->m_perConnectionJobId << ')');

	const bool result = send(client,
		[id](uint8_t* buf, size_t buf_size)
		{
			log::Stream s(buf, buf_size);
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid job id\"}}\n";
			return s.m_pos;
		});

	return result;
}

uint32_t StratumServer::get_random32()
{
	MutexLock lock(m_rngLock);
	return static_cast<uint32_t>(m_rng() >> 32);
}

void StratumServer::print_status()
{
	update_hashrate_data(0, seconds_since_epoch());
	print_stratum_status();
}

void StratumServer::show_workers_async()
{
	MutexLock lock(m_showWorkersLock);

	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_showWorkersAsync))) {
		uv_async_send(&m_showWorkersAsync);
	}
}

void StratumServer::show_workers()
{
	check_event_loop_thread(__func__);

	const uint64_t cur_time = seconds_since_epoch();
	const difficulty_type pool_diff = m_pool->side_chain().difficulty();

	int addr_len = 0;
	for (const StratumClient* c = static_cast<StratumClient*>(m_connectedClientsList->m_next); c != m_connectedClientsList; c = static_cast<StratumClient*>(c->m_next)) {
		addr_len = std::max(addr_len, static_cast<int>(strlen(c->m_addrString)));
	}

	size_t n = 0;

	LOGINFO(0, log::pad_right("IP:port", addr_len + 8)
			<< log::pad_right("uptime", 20)
			<< log::pad_right("difficulty", 20)
			<< log::pad_right("hashrate", 15)
			<< "name"
	);

	for (const StratumClient* c = static_cast<StratumClient*>(m_connectedClientsList->m_next); c != m_connectedClientsList; c = static_cast<StratumClient*>(c->m_next)) {
		difficulty_type diff = pool_diff;
		if (c->m_lastJobTarget > 1) {
			uint64_t r;
			diff.lo = udiv128(1, 0, c->m_lastJobTarget, &r);
			diff.hi = 0;
			if (r) {
				++diff.lo;
			}
		}
		LOGINFO(0, log::pad_right(static_cast<const char*>(c->m_addrString), addr_len + 8)
				<< log::pad_right(log::Duration(cur_time - c->m_connectedTime), 20)
				<< log::pad_right(diff, 20)
				<< log::pad_right(log::Hashrate(c->m_autoDiff.lo / AUTO_DIFF_TARGET_TIME, m_autoDiff && (c->m_autoDiff != 0)), 15)
				<< (c->m_rpcId ? c->m_customUser : "not logged in")
		);
		++n;
	}

	LOGINFO(0, "Total: " << n << " workers");
}

void StratumServer::reset_share_counters()
{
	WriteLock lock(m_hashrateDataLock);

	m_cumulativeHashesAtLastShare = m_cumulativeHashes;
	m_totalFoundShares = 0;
	m_totalFailedShares = 0;
}

const char* StratumServer::get_log_category() const
{
	return log_category_prefix;
}

void StratumServer::print_stratum_status() const
{
	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;
	double average_effort;
	uint32_t shares_found, shares_failed;

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

		average_effort = 0.0;
		const double diff = m_cumulativeFoundSharesDiff;
		if (diff > 0.0) {
			average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
		}

		shares_found = m_totalFoundShares;
		shares_failed = m_totalFailedShares;
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	char shares_failed_buf[64] = {};
	if (shares_failed) {
		log::Stream s(shares_failed_buf);
		s << log::Yellow() << "\nShares failed      = " << shares_failed << log::NoColor();
	}

	LOGINFO(0, "status" <<
		"\nHashrate (15m est) = " << log::Hashrate(hashrate_15m) <<
		"\nHashrate (1h  est) = " << log::Hashrate(hashrate_1h) <<
		"\nHashrate (24h est) = " << log::Hashrate(hashrate_24h) <<
		"\nTotal hashes       = " << total_hashes <<
		"\nShares found       = " << shares_found << static_cast<const char*>(shares_failed_buf) <<
		"\nAverage effort     = " << average_effort << '%' <<
		"\nCurrent effort     = " << static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double() << '%' <<
		"\nConnections        = " << m_numConnections.load() << " (" << m_numIncomingConnections.load() << " incoming)"
	);
}

// Compresses 64-bit hashes value into 16-bit value (5 bits for shift, 11 bits for data)
namespace {

enum HashValue : uint64_t {
	bits = 11,
	mask = (1 << bits) - 1,
};

static constexpr FORCEINLINE uint64_t hash_uncompress(uint64_t h)
{
	return (h & HashValue::mask) << (h >> HashValue::bits);
};

enum HashMaxValue : uint64_t {
	value = hash_uncompress(std::numeric_limits<uint16_t>::max())
};

static FORCEINLINE uint16_t hash_compress(uint64_t h)
{
	if (h <= HashValue::mask) {
		return static_cast<uint16_t>(h);
	}

	if (h >= HashMaxValue::value) {
		return std::numeric_limits<uint16_t>::max();
	}

	const uint64_t shift = bsr(h) - (HashValue::bits - 1);
	return static_cast<uint16_t>((shift << HashValue::bits) | (h >> shift));
}

}

void StratumServer::update_auto_diff(StratumClient* client, const uint64_t timestamp, const uint64_t hashes)
{
	const uint16_t hashes_compressed = hash_compress(hashes);
	client->m_autoDiffWindowHashes += hash_uncompress(hashes_compressed);

	const uint32_t k = client->m_autoDiffIndex++;
	constexpr uint32_t N = StratumClient::AUTO_DIFF_SIZE;

	StratumClient::AutoDiffData& auto_diff_data = client->m_autoDiffData[k % N];

	if (k >= N) {
		client->m_autoDiffWindowHashes -= hash_uncompress(auto_diff_data.m_hashes);
	}

	const uint16_t t1 = auto_diff_data.m_timestamp;
	const uint16_t t2 = static_cast<uint16_t>(timestamp);
	auto_diff_data.m_timestamp = t2;
	auto_diff_data.m_hashes = hashes_compressed;

	if (k >= N) {
		// Full window
		const uint16_t dt = t2 - t1;
		client->m_autoDiff.lo = std::max<uint64_t>((client->m_autoDiffWindowHashes * AUTO_DIFF_TARGET_TIME) / (dt ? dt : 1), MIN_DIFF);
		client->m_autoDiff.hi = 0;
	}
	else if (k >= 10) {
		// Partial window
		const uint64_t h0 = hash_uncompress(client->m_autoDiffData[0].m_hashes);
		const uint16_t dt = client->m_autoDiffData[k].m_timestamp - client->m_autoDiffData[0].m_timestamp;

		client->m_autoDiff.lo = std::max<uint64_t>(((client->m_autoDiffWindowHashes - h0) * AUTO_DIFF_TARGET_TIME) / (dt ? dt : 1), MIN_DIFF);
		client->m_autoDiff.hi = 0;
	}
	else if (k == 0) {
		// First share, fix auto diff to current difficulty until we have at least 10 shares
		client->m_autoDiff.lo = hashes;
		client->m_autoDiff.hi = 0;
	}
}

void StratumServer::on_blobs_ready()
{
	check_event_loop_thread(__func__);

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
	const uint32_t extra_nonce_start = data->m_extraNonceStart;

	size_t numClientsProcessed = 0;
	uint32_t num_sent = 0;

	const uint64_t cur_time = seconds_since_epoch();

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

		if (num_sent >= data->m_numClientsExpected) {
			// We don't have any more extra_nonce values available
			continue;
		}

		uint8_t* hashing_blob = data->m_blobs.data() + num_sent * data->m_blobSize;

		uint64_t target = data->m_target;
		if (client->m_customDiff.lo) {
			target = std::max(target, client->m_customDiff.target());
		}
		else if (m_autoDiff) {
			// Limit autodiff to 4000000 for maximum compatibility
			target = std::max(target, TARGET_4_BYTES_LIMIT);

			if (client->m_autoDiff.lo) {
				const uint32_t k = client->m_autoDiffIndex;
				const uint16_t elapsed_time = static_cast<uint16_t>(cur_time) - client->m_autoDiffData[(k - 1) % StratumClient::AUTO_DIFF_SIZE].m_timestamp;
				if (elapsed_time > AUTO_DIFF_TARGET_TIME * 5) {
					// More than 500% effort, reduce the auto diff by 1/8 every time until the share is found
					client->m_autoDiff.lo = std::max<uint64_t>(client->m_autoDiff.lo - client->m_autoDiff.lo / 8, MIN_DIFF);
				}
				target = std::max(target, client->m_autoDiff.target());
			}
			else {
				// Not enough shares from the client yet, cut diff in half every 16 seconds
				const uint64_t num_halvings = (cur_time - client->m_connectedTime) / 16;
				constexpr uint64_t max_target = (std::numeric_limits<uint64_t>::max() / MIN_DIFF) + 1;
				for (uint64_t i = 0; (i < num_halvings) && (target < max_target); ++i) {
					target *= 2;
				}
				target = std::min<uint64_t>(target, max_target);
			}
		}

		uint32_t job_id;
		{
			job_id = ++client->m_perConnectionJobId;

			StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
			saved_job.job_id = job_id;
			saved_job.extra_nonce = extra_nonce_start + num_sent;
			saved_job.template_id = data->m_templateId;
			saved_job.target = target;
		}
		client->m_lastJobTarget = target;

		const bool result = send(client,
			[data, target, hashing_blob, job_id](uint8_t* buf, size_t buf_size)
			{
				log::hex_buf target_hex(&target);

				if (target >= TARGET_4_BYTES_LIMIT) {
					target_hex.m_data += sizeof(uint32_t);
					target_hex.m_size -= sizeof(uint32_t);
				}

				log::Stream s(buf, buf_size);
				s << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{\"blob\":\"";
				s << log::hex_buf(hashing_blob, data->m_blobSize) << "\",\"job_id\":\"";
				s << log::Hex(job_id) << "\",\"target\":\"";
				s << target_hex << "\",\"algo\":\"rx/0\",\"height\":";
				s << data->m_height << ",\"seed_hash\":\"";
				s << data->m_seedHash << "\"}}\n";
				return s.m_pos;
			});

		if (result) {
			++num_sent;
		}
		else {
			client->close();
		}
	}

	const uint32_t num_connections = m_numConnections;
	if (numClientsProcessed != num_connections) {
		LOGWARN(1, "client list is broken, expected " << num_connections << ", got " << numClientsProcessed << " clients");
	}

	LOGINFO(3, "sent new job to " << num_sent << '/' << numClientsProcessed << " clients");
}

void StratumServer::update_hashrate_data(uint64_t hashes, uint64_t timestamp)
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
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);
	StratumServer* server = share->m_server;

	if (server->is_banned(share->m_clientIPv6, share->m_clientAddr)) {
		share->m_highEnoughDifficulty = false;
		share->m_result = SubmittedShare::Result::BANNED;
		return;
	}

	if (share->m_highEnoughDifficulty) {
		BACKGROUND_JOB_START(StratumServer::on_share_found);
	}

	p2pool* pool = server->m_pool;

	const uint64_t target = share->m_target;
	const uint64_t hashes = share->m_hashes;

	if (pool->stopped()) {
		LOGWARN(0, "p2pool is shutting down, but a share was found. Trying to process it anyway!");
	}

	if (share->m_highEnoughDifficulty) {
		uint8_t blob[128];
		uint64_t height;
		difficulty_type difficulty;
		difficulty_type aux_diff;
		difficulty_type sidechain_difficulty;
		hash seed_hash;
		size_t nonce_offset;

		const uint32_t blob_size = pool->block_template().get_hashing_blob(share->m_templateId, share->m_extraNonce, blob, height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset);
		if (!blob_size) {
			LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " got a stale share");
			share->m_result = SubmittedShare::Result::STALE;
			return;
		}

		for (uint32_t i = 0, nonce = share->m_nonce; i < sizeof(share->m_nonce); ++i) {
			blob[nonce_offset + i] = nonce & 255;
			nonce >>= 8;
		}

		hash pow_hash;
		if (!pool->calculate_hash(blob, blob_size, height, seed_hash, pow_hash, false)) {
			LOGWARN(3, "client " << static_cast<char*>(share->m_clientAddrString) << " couldn't check share PoW");
			share->m_result = SubmittedShare::Result::COULDNT_CHECK_POW;
			return;
		}

		if (pow_hash != share->m_resultHash) {
			LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " submitted a share with invalid PoW");
			share->m_result = SubmittedShare::Result::INVALID_POW;
			share->m_score = BAD_SHARE_POINTS;

			// Calculate the same hash second time to check if it's an unstable hardware that caused this
			hash pow_hash2;
			if (pool->calculate_hash(blob, blob_size, height, seed_hash, pow_hash2, true) && (pow_hash2 != pow_hash)) {
				LOGERR(0, "UNSTABLE HARDWARE DETECTED: Calculated the same hash twice, got different results: " << pow_hash << " != " << pow_hash2);
			}

			return;
		}

		share->m_score = GOOD_SHARE_POINTS;

		const double diff = sidechain_difficulty.to_double();
		{
			WriteLock lock(server->m_hashrateDataLock);

			const uint64_t n = server->m_cumulativeHashes + hashes;
			share->m_effort = static_cast<double>(n - server->m_cumulativeHashesAtLastShare) * 100.0 / diff;
			server->m_cumulativeHashesAtLastShare = n;

			server->m_cumulativeFoundSharesDiff += diff;
			++server->m_totalFoundShares;
		}

		if (!pool->submit_sidechain_block(share->m_templateId, share->m_nonce, share->m_extraNonce)) {
			WriteLock lock(server->m_hashrateDataLock);

			if (server->m_totalFoundShares > 0) {
				--server->m_totalFoundShares;
				++server->m_totalFailedShares;
			}
		}
	}

	// Send the response to miner
	const uint64_t value = share->m_resultHash.u64()[HASH_SIZE / sizeof(uint64_t) - 1];

	if (LIKELY(value < target)) {
		const uint64_t timestamp = share->m_timestamp;
		server->update_hashrate_data(hashes, timestamp);
		server->api_update_local_stats(timestamp);
		share->m_result = SubmittedShare::Result::OK;
	}
	else {
		LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " got a low diff share");
		share->m_result = SubmittedShare::Result::LOW_DIFF;
		share->m_score = BAD_SHARE_POINTS;
	}
}

void StratumServer::on_after_share_found(uv_work_t* req, int /*status*/)
{
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);

	if (share->m_highEnoughDifficulty) {
		const char* s = share->m_clientCustomUser;
		if (share->m_result == SubmittedShare::Result::OK) {
			LOGINFO(0, log::Green() << "SHARE FOUND: mainchain height " << share->m_mainchainHeight << ", sidechain height " << share->m_sidechainHeight << ", diff " << share->m_sidechainDifficulty << ", client " << static_cast<char*>(share->m_clientAddrString) << (*s ? ", user " : "") << s << ", effort " << share->m_effort << '%');
		}
		else {
			static const char* reason_list[] = {
				"stale share",
				"couldn't check PoW",
				"low difficulty",
				"invalid PoW",
				"worker banned",
			};
			static_assert(array_size(reason_list) == static_cast<size_t>(SubmittedShare::Result::OK), "Update reason_list to match SubmittedShare::Result enum");

			const size_t k = static_cast<size_t>(share->m_result);
			const char* reason = (k < array_size(reason_list)) ? reason_list[k] : "unknown";
			LOGWARN(0, "INVALID SHARE: mainchain height " << share->m_mainchainHeight << ", sidechain height " << share->m_sidechainHeight << ", diff " << share->m_sidechainDifficulty << ", client " << static_cast<char*>(share->m_clientAddrString) << (*s ? ", user " : "") << s << ", reason: " << reason);
		}
		BACKGROUND_JOB_STOP(StratumServer::on_share_found);
	}

	StratumServer* server = share->m_server;

	ON_SCOPE_LEAVE([share, server]()
		{
			ASAN_POISON_MEMORY_REGION(share, sizeof(SubmittedShare));
			server->m_submittedSharesPool.push_back(share);
		});

	const bool bad_share = (share->m_result == SubmittedShare::Result::LOW_DIFF) || (share->m_result == SubmittedShare::Result::INVALID_POW);

	StratumClient* client = share->m_client;

	if (client->m_resetCounter.load() == share->m_clientResetCounter) {
		const bool result = server->send(client,
			[share](uint8_t* buf, size_t buf_size)
			{
				log::Stream s(buf, buf_size);
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
				case SubmittedShare::Result::BANNED:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Banned\"}}\n";
					break;
				case SubmittedShare::Result::OK:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n";
					break;
				}
				return s.m_pos;
			});

		client->m_score += share->m_score;

		if (bad_share && (client->m_score <= BAN_THRESHOLD_POINTS)) {
			client->ban(DEFAULT_BAN_TIME);
			client->close();
		}
		else if (!result) {
			client->close();
		}
	}
	else if (bad_share) {
		server->ban(share->m_clientIPv6, share->m_clientAddr, DEFAULT_BAN_TIME);
	}
}

void StratumServer::on_shutdown()
{
	{
		MutexLock lock(m_blobsQueueLock);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_blobsAsync), nullptr);
	}
	{
		MutexLock lock(m_showWorkersLock);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_showWorkersAsync), nullptr);
	}
}

StratumServer::StratumClient::StratumClient()
	: Client(m_stratumReadBuf, sizeof(m_stratumReadBuf))
	, m_rpcId(0)
	, m_perConnectionJobId(0)
	, m_connectedTime(0)
	, m_jobs{}
	, m_autoDiffData{}
	, m_autoDiffWindowHashes(0)
	, m_autoDiffIndex(0)
	, m_customDiff{}
	, m_autoDiff{}
	, m_customUser{}
	, m_lastJobTarget(0)
	, m_score(0)
{
	m_stratumReadBuf[0] = '\0';
}

void StratumServer::StratumClient::reset()
{
	Client::reset();
	m_rpcId = 0;
	m_perConnectionJobId = 0;
	m_connectedTime = 0;

	for (int i = 0; i < JOBS_SIZE; ++i) {
		m_jobs[i].job_id = 0;
	}

	m_autoDiffWindowHashes = 0;
	m_autoDiffIndex = 0;
	m_customDiff = {};
	m_autoDiff = {};
	m_customUser[0] = '\0';

	m_lastJobTarget = 0;

	m_score = 0;
}

bool StratumServer::StratumClient::on_connect()
{
	m_connectedTime = seconds_since_epoch();
	return true;
}

bool StratumServer::StratumClient::on_read(char* data, uint32_t size)
{
	if ((data != m_readBuf + m_numRead) || (data + size > m_readBuf + m_readBufSize)) {
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

	LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (unknown method)");
	return false;
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

void StratumServer::api_update_local_stats(uint64_t timestamp)
{
	if (!m_pool->api() || !m_pool->params().m_localStats || m_pool->stopped()) {
		return;
	}

	// Rate limit to no more than once in 20 seconds.
	uint64_t t = m_apiLastUpdateTime.load();
	if (timestamp < t + 20) {
		return;
	}

	if (!m_apiLastUpdateTime.compare_exchange_strong(t, timestamp)) {
		return;
	}

	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;
	double average_effort;
	uint32_t shares_found, shares_failed;

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

		average_effort = 0.0;
		const double diff = m_cumulativeFoundSharesDiff;
		if (diff > 0.0) {
			average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
		}

		shares_found = m_totalFoundShares;
		shares_failed = m_totalFailedShares;
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	double current_effort = static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double();

	uint32_t connections = m_numConnections;
	uint32_t incoming_connections = m_numIncomingConnections;

	const double block_reward_share_percent = m_pool->side_chain().get_reward_share(m_pool->params().m_wallet) * 100.0;

	CallOnLoop(&m_loop, [=]() {
		m_pool->api()->set(p2pool_api::Category::LOCAL, "stratum", [=](log::Stream& s) {
			s	<< "{\"hashrate_15m\":" << hashrate_15m
				<< ",\"hashrate_1h\":" << hashrate_1h
				<< ",\"hashrate_24h\":" << hashrate_24h
				<< ",\"total_hashes\":" << total_hashes
				<< ",\"shares_found\":" << shares_found
				<< ",\"shares_failed\":" << shares_failed
				<< ",\"average_effort\":" << average_effort
				<< ",\"current_effort\":" << current_effort
				<< ",\"connections\":" << connections
				<< ",\"incoming_connections\":" << incoming_connections
				<< ",\"block_reward_share_percent\":" << block_reward_share_percent
				<< ",\"workers\":[";

			const difficulty_type pool_diff = m_pool->side_chain().difficulty();
			bool first = true;

			for (const StratumClient* client = static_cast<StratumClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<StratumClient*>(client->m_next)) {
				if (!first) {
					s << ',';
				}
				difficulty_type diff = pool_diff;
				if (client->m_lastJobTarget > 1) {
					uint64_t r;
					diff.lo = udiv128(1, 0, client->m_lastJobTarget, &r);
					diff.hi = 0;
					if (r) {
						++diff.lo;
					}
				}

				s 	<< '"' << static_cast<const char*>(client->m_addrString) << ','
					<< (timestamp - client->m_connectedTime) << ','
					<< diff << ','
					<< (client->m_autoDiff.lo / AUTO_DIFF_TARGET_TIME) << ','
					<< (client->m_rpcId ? client->m_customUser : "not logged in")
					<< '"';

				first = false;
			}

			s	<< "]}";
		});
	});
}

} // namespace p2pool

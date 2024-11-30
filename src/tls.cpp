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
#include "tls.h"

LOG_CATEGORY(TLS)

namespace p2pool {

static bssl::UniquePtr<EVP_PKEY> init_evp_pkey()
{
	bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());

	if (!evp_pkey.get()) {
		return nullptr;
	}

	bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

	if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
		return nullptr;
	}

	if (!EVP_PKEY_assign_EC_KEY(evp_pkey.get(), ec_key.release())) {
		return nullptr;
	}

	//FILE* fp;
	//if (fopen_s(&fp, "cert_key.pem", "wb") == 0) {
	//	PEM_write_PrivateKey(fp, evp_pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
	//	fclose(fp);
	//}

	return evp_pkey;
}

static bssl::UniquePtr<EVP_PKEY> s_evp_pkey = init_evp_pkey();

static bssl::UniquePtr<X509> init_cert()
{
	bssl::UniquePtr<X509> x509(X509_new());

	if (!x509.get()) {
		return nullptr;
	}

	if (!X509_set_version(x509.get(), X509_VERSION_3)) {
		return nullptr;
	}

	std::mt19937_64 rng(RandomDeviceSeed::instance);
	rng.discard(10000);

	const uint64_t serial = rng();

	if (!ASN1_INTEGER_set_uint64(X509_get_serialNumber(x509.get()), serial)) {
		return nullptr;
	}

	constexpr int64_t YEAR = 31557600;

	const time_t cur_time = time(nullptr);

	const time_t t0 = cur_time - (cur_time % YEAR);
	const time_t t1 = t0 - YEAR * 10;
	const time_t t2 = t0 + YEAR * 10;

	if (!ASN1_TIME_set(X509_get_notBefore(x509.get()), t1) || !ASN1_TIME_set(X509_get_notAfter(x509.get()), t2)) {
		return nullptr;
	}

	X509_NAME* subject = X509_get_subject_name(x509.get());

	if (!X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, reinterpret_cast<const uint8_t*>("US"), -1, -1, 0) ||
		!X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, reinterpret_cast<const uint8_t*>("BoringSSL"), -1, -1, 0) ||
		!X509_set_issuer_name(x509.get(), subject)) {
		return nullptr;
	}

	bssl::UniquePtr<STACK_OF(ASN1_OBJECT)> ekus(sk_ASN1_OBJECT_new_null());

	if (!ekus || !sk_ASN1_OBJECT_push(ekus.get(), OBJ_nid2obj(NID_server_auth)) || !X509_add1_ext_i2d(x509.get(), NID_ext_key_usage, ekus.get(), 1, 0)) {
		return nullptr;
	}

	if (!X509_set_pubkey(x509.get(), s_evp_pkey.get())) {
		return nullptr;
	}

	if (!X509_sign(x509.get(), s_evp_pkey.get(), EVP_sha256())) {
		return nullptr;
	}

	//FILE* fp;
	//if (fopen_s(&fp, "cert.pem", "wb") == 0) {
	//	PEM_write_X509(fp, x509.get());
	//	fclose(fp);
	//}

	return x509;
}

static bssl::UniquePtr<X509> s_cert = init_cert();

static bssl::UniquePtr<SSL_CTX> init_ctx()
{
	if (!s_evp_pkey.get() || !s_cert.get()) {
		return nullptr;
	}

	bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

	if (!ctx.get()) {
		return nullptr;
	}

	if (!SSL_CTX_use_PrivateKey(ctx.get(), s_evp_pkey.get())) {
		return nullptr;
	}

	if (!SSL_CTX_use_certificate(ctx.get(), s_cert.get())) {
		return nullptr;
	}

	return ctx;
}

static bssl::UniquePtr<SSL_CTX> s_ctx = init_ctx();

bool ServerTls::load_from_files(const char* cert, const char* cert_key)
{
	if (!cert) {
		LOGERR(0, "No cert file specified");
		return false;
	}

	if (!cert_key) {
		LOGERR(0, "No cert_key file specified");
		return false;
	}

	bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

	if (!ctx.get()) {
		LOGERR(0, "Failed to create SSL context");
		return false;
	}

	if (SSL_CTX_use_certificate_chain_file(ctx.get(), cert) <= 0) {
		LOGERR(0, "Failed to load " << cert);
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx.get(), cert_key, SSL_FILETYPE_PEM) <= 0) {
		LOGERR(0, "Failed to load " << cert_key);
		return false;
	}

	SSL_CTX_set_options(ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);

	LOGINFO(1, log::LightCyan() << "Loaded " << cert << ", " << cert_key);

	s_ctx.reset(ctx.release());
	return true;
}

void ServerTls::reset()
{
	m_ssl.reset(nullptr);
}

bool ServerTls::init()
{
	if (!s_ctx.get()) {
		static std::atomic<uint32_t> ctx_error_shown = 0;
		if (ctx_error_shown.exchange(1) == 0) {
			LOGERR(0, "Failed to initialize an SSL context");
		}
		return false;
	}

	m_ssl.reset(SSL_new(s_ctx.get()));

	if (!m_ssl.get()) {
		return false;
	}

	SSL_set_accept_state(m_ssl.get());

	BIO* rbio = BIO_new(BIO_s_mem());
	BIO* wbio = BIO_new(BIO_s_mem());

	if (!rbio || !wbio) {
		BIO_free(rbio);
		BIO_free(wbio);

		m_ssl.reset(nullptr);
		return false;
	}

	SSL_set_bio(m_ssl.get(), rbio, wbio);
	return true;
}

bool ServerTls::on_read_internal(const char* data, uint32_t size, ReadCallback::Base&& read_callback, WriteCallback::Base&& write_callback)
{
	SSL* ssl = m_ssl.get();
	if (!ssl) {
		return false;
	}

	if (!BIO_write_all(SSL_get_rbio(ssl), data, size)) {
		return false;
	}

	if (!SSL_is_init_finished(ssl)) {
		const int result = SSL_do_handshake(ssl);

		if (!result) {
			// EOF
			return false;
		}

		// Send pending handshake data, if any
		BIO* wbio = SSL_get_wbio(ssl);
		if (!wbio) {
			return false;
		}

		const uint8_t* bio_data;
		size_t bio_len;

		if (!BIO_mem_contents(wbio, &bio_data, &bio_len)) {
			return false;
		}

		if (bio_len > 0) {
			if (!write_callback(bio_data, bio_len)) {
				return false;
			}
			if (!BIO_reset(wbio)) {
				return false;
			}
		}

		if ((result < 0) && (SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ)) {
			// Continue handshake, nothing to read yet
			return true;
		}
		else if (result == 1) {
			// Handshake finished, skip to "SSL_read" further down
		}
		else {
			// Some other error
			return false;
		}
	}

	int bytes_read;
	char buf[1024];

	while ((bytes_read = SSL_read(ssl, buf, sizeof(buf))) > 0) {
		if (!read_callback(buf, static_cast<uint32_t>(bytes_read))) {
			return false;
		}
	}

	return true;
}

bool ServerTls::on_write_internal(const uint8_t* data, size_t size, WriteCallback::Base&& write_callback)
{
	SSL* ssl = m_ssl.get();
	if (!ssl) {
		return false;
	}

	if (SSL_write(ssl, data, static_cast<int>(size)) <= 0) {
		return false;
	}

	BIO* wbio = SSL_get_wbio(ssl);
	if (!wbio) {
		return false;
	}

	const uint8_t* bio_data;
	size_t bio_len;

	if (!BIO_mem_contents(wbio, &bio_data, &bio_len)) {
		return false;
	}

	if (bio_len > 0) {
		if (!write_callback(bio_data, bio_len)) {
			return false;
		}
		if (!BIO_reset(wbio)) {
			return false;
		}
	}

	return true;
}

} // namespace p2pool

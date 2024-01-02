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
#include "wallet.h"
#include "gtest/gtest.h"

namespace p2pool {

TEST(wallet, input_output)
{
	// No data
	{
		Wallet w(nullptr);
		ASSERT_EQ(w.valid(), false);
	}

	// Wrong length
	{
		Wallet w("456");
		ASSERT_EQ(w.valid(), false);
	}

	// Symbol '0' is not from base-58
	{
		Wallet w("40ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");
		ASSERT_EQ(w.valid(), false);
	}

	// Invalid checksum
	{
		Wallet w("49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS7");
		ASSERT_EQ(w.valid(), false);
	}

	// 64-bit overflow
	{
		Wallet w("49ccoSmrBTPzzzzzzzzzzzh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");
		ASSERT_EQ(w.valid(), false);
	}

	// Subaddress (not supported)
	{
		Wallet w("8BE7uo9kWR6fFekhGHKJt87pkTzzNj2ikZMNmN7DUJf81y6Zygzbsk1CFzGMbS7fB7E2qr6A6EZfLYgxUfYvdDxEHrMPMA5");
		ASSERT_EQ(w.valid(), false);
	}

	auto check = [](NetworkType t, uint64_t prefix, uint32_t checksum, const char* address, const char* spendkey, const char* viewkey)
	{
		// Test Wallet::decode()
		Wallet w(address);
		ASSERT_EQ(w.type(), t);
		ASSERT_EQ(w.prefix(), prefix);
		ASSERT_EQ(w.checksum(), checksum);

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);

		s << w.spend_public_key();
		ASSERT_EQ(memcmp(buf, spendkey, HASH_SIZE * 2), 0);

		s.m_pos = 0;
		s << w.view_public_key();
		ASSERT_EQ(memcmp(buf, viewkey, HASH_SIZE * 2), 0);

		// Test Wallet::assign()
		Wallet w2(nullptr);
		w2.assign(w.spend_public_key(), w.view_public_key(), w.type());

		ASSERT_EQ(w2.prefix(),           w.prefix());
		ASSERT_EQ(w2.spend_public_key(), w.spend_public_key());
		ASSERT_EQ(w2.view_public_key(),  w.view_public_key());
		ASSERT_EQ(w2.checksum(),         w.checksum());
		ASSERT_EQ(w2.type(),             w.type());

		// Test Wallet::encode()
		const std::string s0 = address;
		const std::string s1 = w.encode();
		const std::string s2 = w2.encode();
		ASSERT_EQ(s1, s0);
		ASSERT_EQ(s2, s0);

		// Test Wallet::encode(buf)
		char buf1[Wallet::ADDRESS_LENGTH] = {};
		w.encode(buf1);
		ASSERT_EQ(memcmp(buf1, address, Wallet::ADDRESS_LENGTH), 0);

		char buf2[Wallet::ADDRESS_LENGTH] = {};
		w2.encode(buf2);
		ASSERT_EQ(memcmp(buf2, address, Wallet::ADDRESS_LENGTH), 0);
	};

	// Correct mainnet addresses
	check(
		NetworkType::Mainnet, 18, 0xA345C1C9UL, "49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6",
		"d2e232e441546a695b27187692d035ef7be5c54692700c9f470dcd706753a833", "06f68970da46f709e2b4d0ffabd0d1f78ea6717786b5766c25c259111f212490"
	);

	check(
		NetworkType::Mainnet, 18, 0x8C8FB6E6UL, "45JHuqGBSqUXUyZx95H4C2J5aEL4zFjM3jpTmMTESPXPa3jmtSQWYezHX7r4A2xPQNBGsQupJqmPhRZb2QgBcEWRDQ9ywwR",
		"60fe176eaf3cffb63df130bc25036b661b947900941052fffe6ff4b51fc4f2c5", "9387910b0a2e4f62c32621b77ddbeb3d6c0054e5ed9bc492d87bab1a1eef366d"
	);

	check(
		NetworkType::Mainnet, 18, 0x0E705A56UL, "43S5vhReDY4fJs99DBZtFS8JoJVNG17iaAVAARvRT8xzSYZqnJfXfTACLrZUzoBHQKhiJZCWCpqB4Kf3c64CEagdSRXd5D7",
		"2fc2f902659541e50753853ddb96912baf55f26bebe7d338b5c2239c437ddb98", "b814951166253543cfb0e1b8bdea58f366de824fddb8ef6f895fcf631873f6e1"
	);

	// Correct testnet addresses
	check(
		NetworkType::Testnet, 53, 0x6F896672UL, "9x6aEN1yd2WhPMPw89LV5LLK1ZFe6N8xiAm18Ay4q1U4LKMde7MpDdPRN6GiiGCJMVTHuptGGmfj2Qfp2vcKSRSG79HJrQn",
		"821623ac165f07f172c86980254a43737332fd89ca36d33a57dc02d8026d9173", "7c55413e672f8691a9211eac6003109d2fdf224ba72c4d8d82353427a02bc136"
	);

	check(
		NetworkType::Testnet, 53, 0x4124092AUL, "9zsJP6KFF6ZGern5UkR7gyRXHFRTba6jG8JKnfzDySeqEdwPZaD8MNYGkjyADdVpWs7rXgyeu712JdxhX2k7d9SNB4TdRdS",
		"cb366a3b44f6aa5d94e03db06325b6929b9e75dbf19dcf2ba2d14eb2efa53651", "8789afa33dca295e301baef826cec028fa22b831822c1bdcf8a847a43a3bff59"
	);

	check(
		NetworkType::Testnet, 53, 0x0AC6459FUL, "A1SqL5oPjh8Km1At7mao7U1fNjWkzeSwvQ39GimMqvhBF3FUoJhx1zxL2i6XbHzzAXDhKetiwSmYQeVwG6sUgwJuEqPyjWq",
		"da78298fb6eb8f702698bec873bad703f4a51e1377a66d89ba977ca7f43b8e53", "eeb348f70afad971c50aa062f1d1544be64ef9cdc12475e030f2d295305e6e7a"
	);

	// Correct stagenet addresses
	check(
		NetworkType::Stagenet, 24, 0x36E99D1DUL, "55AJ4jJBhV6JsoqrEsAazTLrJjg9SA1SFReLUoXDudrsA9tdL9i2VkJefEbx3zrFRt6swuibPVySPGNzsNvyshrRNZbSDnD",
		"57e0c2fef80a1d6adfa3189134009076ad0ddc4c4668709355cea98524e9fc36", "b94fafe59d5037e126557665f76cd3232504ebd82500e05bf25801d853d182bf"
	);

	check(
		NetworkType::Stagenet, 24, 0x16DF3958UL, "5BQqg4HTWuN3j4NzBHTK31eTaygRXYxWRQW9dTD7qMuJSiVtskraSErXQ24FUBeifiV6NaQPmxLS559vbUT4xYUoF2fiGvH",
		"fcd35a53cef9a1104ae556f01cee0cdff2f18f2f2f6bde8c833d5bd980fe8999", "be2b1142a046bfb5bb21e1f2a49bd1a7f46e1c18b009b218d5962f663938707c"
	);

	check(
		NetworkType::Stagenet, 24, 0xF17D6524UL, "53CFYfjzcouW95hQ7AHvqS3GZ2UAAaRLKc1ymmhHATQTZxhtakpYcfjiRVzrRdxVZ5F8p61KSpPEmFu9DVRULRDkK4v1TCU",
		"23fdd143264794ae367083791bb8fd0d8f719b27b7b858d15a2b67d6eddd60c5", "0ebafc1284ab1af7a5ff4ade682bcc54817a319a00eede591344855c420beba0"
	);
}

}

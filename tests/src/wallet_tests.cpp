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
#include "keccak.h"
#include "gtest/gtest.h"

namespace p2pool {

// Real wallet public keys: k*G, so always in the prime order subgroup
static constexpr hash valid_spend_pub("d2e232e441546a695b27187692d035ef7be5c54692700c9f470dcd706753a833");
static constexpr hash valid_view_pub("06f68970da46f709e2b4d0ffabd0d1f78ea6717786b5766c25c259111f212490");

// The same two keys plus a point of order 8: still valid curve points, but with torsion
static constexpr hash torsioned_spend_pub("bd5886e258615b51bdff73f8ae3b9947cf021162325ee8a7f0c787f6f6889836");
static constexpr hash torsioned_view_pub("33504b48a8074c5af955e83cf125f8462b1abfe3b5084efa67cc07ec2bcd5b50");

static constexpr hash identity_pub("0100000000000000000000000000000000000000000000000000000000000000");
static constexpr hash order2_pub("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
static constexpr hash order8_pub("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");

TEST(wallet, input_output)
{
	// No data
	{
		Wallet w(nullptr);
		ASSERT_FALSE(w.valid());
	}

	// Wrong length
	{
		Wallet w("456");
		ASSERT_FALSE(w.valid());
	}

	// Symbol '0' is not from base-58
	{
		Wallet w("40ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");
		ASSERT_FALSE(w.valid());
	}

	// Invalid checksum
	{
		Wallet w("49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS7");
		ASSERT_FALSE(w.valid());
	}

	// 64-bit overflow
	{
		Wallet w("49ccoSmrBTPzzzzzzzzzzzh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");
		ASSERT_FALSE(w.valid());
	}

	// Invalid pubkey
	{
		Wallet w("47wU9Pe8Ez8anN3jf2XjqfXQfxmoqT4Pw1h4msNWyynMBiwjCtkQFAvBoR7sQJR4Khhcq8Nmgufa6JKLm8yWEu9R1g6B9jj");
		ASSERT_FALSE(w.valid());
	}

	// Invalid pubkeys
	{
		Wallet w(nullptr);

		constexpr hash invalid_spend_pub = keccak("invalid spend pub key 1");
		constexpr hash invalid_view_pub = keccak("invalid view pub key 3");

		ASSERT_TRUE(w.assign(valid_spend_pub, valid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(invalid_spend_pub, valid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(valid_spend_pub, invalid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(invalid_spend_pub, invalid_view_pub, NetworkType::Mainnet, false));
	}

	// Public keys which are valid points, but are not in the prime order subgroup.
	//
	// FCMP++ rejects coinbase outputs with torsion, and K_o = K_s + k^o_g G + k^o_t T has torsion
	// if and only if K_s does, so these must never make it into a share.
	{
		Wallet w(nullptr);

		ASSERT_FALSE(w.assign(torsioned_spend_pub, valid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(valid_spend_pub, torsioned_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(torsioned_spend_pub, torsioned_view_pub, NetworkType::Mainnet, false));

		// Points of small order are rejected too (they don't even satisfy the pre-condition of the torsion check)
		for (const hash& k : { identity_pub, order2_pub, order8_pub }) {
			ASSERT_FALSE(w.assign(k, valid_view_pub, NetworkType::Mainnet, false));
			ASSERT_FALSE(w.assign(valid_spend_pub, k, NetworkType::Mainnet, false));
		}

		// A rejected key pair must leave the wallet untouched
		ASSERT_TRUE(w.assign(valid_spend_pub, valid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(w.assign(torsioned_spend_pub, torsioned_view_pub, NetworkType::Mainnet, false));
		ASSERT_TRUE(w.valid());
		ASSERT_EQ(w.spend_public_key(), valid_spend_pub);
		ASSERT_EQ(w.view_public_key(), valid_view_pub);
		ASSERT_TRUE(w.torsion_check());
	}

	// The same thing through decode(). The control address is built by exactly the same generator as the
	// three bad ones, so if it decodes then their base58 and checksums are good and torsion is what fails.
	{
		Wallet control("491sZoncdcwTUw6rax1Tqv7yx7TYdXTovDYHJwPu8zQTg51VCT72NZyTownPHbLpBseNitWzgxdJt32eD45VwddEHDTwBjm");
		ASSERT_TRUE(control.valid());
		ASSERT_TRUE(control.torsion_check());
		ASSERT_EQ(control.spend_public_key(), hash("c3134df7b4f43c9e52b942080a9b8d29bdf723ada386194af7bf36a6a9766ce9"));
		ASSERT_EQ(control.view_public_key(), hash("9435e4a23dc4f4a048698c41b11f2adf7299e46fcbb5850c205d65cd85e1b58f"));

		// Same address, with the spend key, the view key, or both replaced by a torsioned point
		Wallet w1("48oH9tLdYrvEg169xBenuvD1dkVCYog9VV6EZ1cAxC15A38dQNCmyjc2euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HHp2hoP");
		Wallet w2("49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Zi6Cdm4u9uGDZZgZcMZ7DCjipxX8BJ53itFJaLR4ME2A5KG1db");
		Wallet w3("48oH9tLdYrvEg169xBenuvD1dkVCYog9VV6EZ1cAxC15A4p7F4DYixTGDZZgZcMZ7DCjipxX8BJ53itFJaLR4ME2A3GMGUm");

		ASSERT_FALSE(w1.valid());
		ASSERT_FALSE(w2.valid());
		ASSERT_FALSE(w3.valid());

		// All three are well formed addresses whose keys are unusable, which is what lets
		// Params::valid() tell the user that instead of "Invalid wallet address"
		ASSERT_TRUE(w1.is_torsioned());
		ASSERT_TRUE(w2.is_torsioned());
		ASSERT_TRUE(w3.is_torsioned());

		ASSERT_FALSE(control.is_torsioned());

		// A damaged address must not be reported as torsioned: its keys are whatever the broken
		// base58 happened to decode to, so torsion says nothing about what the user typed
		{
			char buf[Wallet::ADDRESS_LENGTH + 1] = {};
			memcpy(buf, "48oH9tLdYrvEg169xBenuvD1dkVCYog9VV6EZ1cAxC15A38dQNCmyjc2euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HHp2hoP", Wallet::ADDRESS_LENGTH);
			buf[Wallet::ADDRESS_LENGTH - 1] = (buf[Wallet::ADDRESS_LENGTH - 1] == 'P') ? 'Q' : 'P';

			Wallet broken(buf);
			ASSERT_FALSE(broken.valid());
			ASSERT_FALSE(broken.is_torsioned());
		}

		// The flag survives a copy, and assign() clears it
		Wallet copy(w1);
		ASSERT_TRUE(copy.is_torsioned());
		ASSERT_FALSE(copy.valid());

		ASSERT_TRUE(copy.assign(valid_spend_pub, valid_view_pub, NetworkType::Mainnet, false));
		ASSERT_FALSE(copy.is_torsioned());
		ASSERT_TRUE(copy.valid());
	}

	// Invalid prefix
	{
		Wallet w1("4KKHpFbLniuJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");
		Wallet w2("49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6");

		ASSERT_TRUE(w2.assign(w2.spend_public_key(), w2.view_public_key(), NetworkType::Invalid, false));

		ASSERT_FALSE(w1.valid());
		ASSERT_FALSE(w2.valid());
	}

	auto check = [](NetworkType t, bool subaddress, uint64_t prefix, uint32_t checksum, const char* address, const char* spendkey, const char* viewkey)
	{
		// Test Wallet::decode()
		Wallet w(address);
		ASSERT_TRUE(w.valid());
		ASSERT_EQ(w.get_type(), t);
		ASSERT_EQ(w.is_subaddress(), subaddress);
		ASSERT_EQ(w.prefix(), prefix);
		ASSERT_EQ(w.checksum(), checksum);

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);

		s << w.spend_public_key();
		ASSERT_EQ(memcmp(buf, spendkey, HASH_SIZE * 2), 0);

		s.m_pos = 0;
		s << w.view_public_key();
		ASSERT_EQ(memcmp(buf, viewkey, HASH_SIZE * 2), 0);

		// Test Wallet copy
		Wallet w1(w);

		ASSERT_EQ(w1.prefix(),           w.prefix());
		ASSERT_EQ(w1.spend_public_key(), w.spend_public_key());
		ASSERT_EQ(w1.view_public_key(),  w.view_public_key());
		ASSERT_EQ(w1.checksum(),         w.checksum());
		ASSERT_EQ(w1.get_type(),         w.get_type());
		ASSERT_EQ(w1.is_subaddress(),    w.is_subaddress());

		// Test Wallet::assign()
		Wallet w2(nullptr);
		ASSERT_TRUE(w2.assign(w.spend_public_key(), w.view_public_key(), w.get_type(), w.is_subaddress()));

		ASSERT_EQ(w2.prefix(),           w.prefix());
		ASSERT_EQ(w2.spend_public_key(), w.spend_public_key());
		ASSERT_EQ(w2.view_public_key(),  w.view_public_key());
		ASSERT_EQ(w2.checksum(),         w.checksum());
		ASSERT_EQ(w2.get_type(),         w.get_type());
		ASSERT_EQ(w2.is_subaddress(),    w.is_subaddress());

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
		NetworkType::Mainnet, false, 18, 0xA345C1C9UL, "49ccoSmrBTPJd5yf8VYCULh4J5rHQaXP1TeC8Cnqhd5H9Y2cMwkJ9w42euLmMghKtCiQcgZEiGYW1K6Ae4biZ7w1HLSexS6",
		"d2e232e441546a695b27187692d035ef7be5c54692700c9f470dcd706753a833", "06f68970da46f709e2b4d0ffabd0d1f78ea6717786b5766c25c259111f212490"
	);

	check(
		NetworkType::Mainnet, false, 18, 0x8C8FB6E6UL, "45JHuqGBSqUXUyZx95H4C2J5aEL4zFjM3jpTmMTESPXPa3jmtSQWYezHX7r4A2xPQNBGsQupJqmPhRZb2QgBcEWRDQ9ywwR",
		"60fe176eaf3cffb63df130bc25036b661b947900941052fffe6ff4b51fc4f2c5", "9387910b0a2e4f62c32621b77ddbeb3d6c0054e5ed9bc492d87bab1a1eef366d"
	);

	check(
		NetworkType::Mainnet, false, 18, 0x0E705A56UL, "43S5vhReDY4fJs99DBZtFS8JoJVNG17iaAVAARvRT8xzSYZqnJfXfTACLrZUzoBHQKhiJZCWCpqB4Kf3c64CEagdSRXd5D7",
		"2fc2f902659541e50753853ddb96912baf55f26bebe7d338b5c2239c437ddb98", "b814951166253543cfb0e1b8bdea58f366de824fddb8ef6f895fcf631873f6e1"
	);

	check(
		NetworkType::Mainnet, true, 42, 0x832DB4D1UL, "86eQxzSW4AZfvsWRSop755WZUsog6L3x32NRZukeeShnS4mBGVpcqQhS6pCNxj44usPKNwesZ45ooHyjDku6nVZdT3Q9qrz",
		"6ea1b3ea41038ee8bd793d4d31851cb0ba4e4605213fe8082fdb51393c51b995", "da5d41e01f57c6961083bd6a0f779e856c8054e7cea82265815714b0bd7aece6"
	);

	// Correct testnet addresses
	check(
		NetworkType::Testnet, false, 53, 0x6F896672UL, "9x6aEN1yd2WhPMPw89LV5LLK1ZFe6N8xiAm18Ay4q1U4LKMde7MpDdPRN6GiiGCJMVTHuptGGmfj2Qfp2vcKSRSG79HJrQn",
		"821623ac165f07f172c86980254a43737332fd89ca36d33a57dc02d8026d9173", "7c55413e672f8691a9211eac6003109d2fdf224ba72c4d8d82353427a02bc136"
	);

	check(
		NetworkType::Testnet, false, 53, 0x4124092AUL, "9zsJP6KFF6ZGern5UkR7gyRXHFRTba6jG8JKnfzDySeqEdwPZaD8MNYGkjyADdVpWs7rXgyeu712JdxhX2k7d9SNB4TdRdS",
		"cb366a3b44f6aa5d94e03db06325b6929b9e75dbf19dcf2ba2d14eb2efa53651", "8789afa33dca295e301baef826cec028fa22b831822c1bdcf8a847a43a3bff59"
	);

	check(
		NetworkType::Testnet, false, 53, 0x0AC6459FUL, "A1SqL5oPjh8Km1At7mao7U1fNjWkzeSwvQ39GimMqvhBF3FUoJhx1zxL2i6XbHzzAXDhKetiwSmYQeVwG6sUgwJuEqPyjWq",
		"da78298fb6eb8f702698bec873bad703f4a51e1377a66d89ba977ca7f43b8e53", "eeb348f70afad971c50aa062f1d1544be64ef9cdc12475e030f2d295305e6e7a"
	);

	check(
		NetworkType::Testnet, true, 63, 0x2232C90AUL, "BfPfAxrFBbLJiMzVGyNmgJbejtcZEMELsbWSv5h3xTc3LSvKpwJetPrNk4fMSZ4bYCA4o93yGdVqjUpZSqUGxWkZ5HwBzrM",
		"be4e4f17b8e00f69e661683116f7bfcf29b2c96fccbe84ce4ede5e58de0fd074", "43ecfeedf706b181fd5e5a321db3f13632df743113480aa6532973bf06b5da26"
	);

	// Correct stagenet addresses
	check(
		NetworkType::Stagenet, false, 24, 0x36E99D1DUL, "55AJ4jJBhV6JsoqrEsAazTLrJjg9SA1SFReLUoXDudrsA9tdL9i2VkJefEbx3zrFRt6swuibPVySPGNzsNvyshrRNZbSDnD",
		"57e0c2fef80a1d6adfa3189134009076ad0ddc4c4668709355cea98524e9fc36", "b94fafe59d5037e126557665f76cd3232504ebd82500e05bf25801d853d182bf"
	);

	check(
		NetworkType::Stagenet, false, 24, 0x16DF3958UL, "5BQqg4HTWuN3j4NzBHTK31eTaygRXYxWRQW9dTD7qMuJSiVtskraSErXQ24FUBeifiV6NaQPmxLS559vbUT4xYUoF2fiGvH",
		"fcd35a53cef9a1104ae556f01cee0cdff2f18f2f2f6bde8c833d5bd980fe8999", "be2b1142a046bfb5bb21e1f2a49bd1a7f46e1c18b009b218d5962f663938707c"
	);

	check(
		NetworkType::Stagenet, false, 24, 0xF17D6524UL, "53CFYfjzcouW95hQ7AHvqS3GZ2UAAaRLKc1ymmhHATQTZxhtakpYcfjiRVzrRdxVZ5F8p61KSpPEmFu9DVRULRDkK4v1TCU",
		"23fdd143264794ae367083791bb8fd0d8f719b27b7b858d15a2b67d6eddd60c5", "0ebafc1284ab1af7a5ff4ade682bcc54817a319a00eede591344855c420beba0"
	);

	check(
		NetworkType::Stagenet, true, 36, 0xE5250D95UL, "77jhPoqpvTnGqds2oAWGVmiZv5fiQb2E8BizTL3oh7ia54sQRSEQ7SAAyRj9TpvwgHGuX1cYNDCHP7WHJCBXHcLqSnmApfe",
		"90e6541963cd1d5eb1459f6f546db8f8840fa31ea09cfd401d4d519f48e56318", "50317de0182c133b9fb6958d1787f65f17b5366aff7b9226e3d205cf22844ae4"
	);
}

}

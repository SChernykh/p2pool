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
#include "util.h"
extern "C" {
#include "crypto-ops.h"
}
#include "gtest/gtest.h"

namespace p2pool {

TEST(util, varint)
{
	std::vector<uint8_t> v;
	v.reserve(16);

	uint64_t check;

	// 0...2^7 - 1
	for (uint64_t value = 0; value < 0x80; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 1);
		ASSERT_EQ(v[0], value);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^7...2^14 - 1
	for (uint64_t value = 0x80; value < 0x4000; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 2);
		ASSERT_EQ(v[0], (value & 0x7F) | 0x80);
		ASSERT_EQ(v[1], value >> 7);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^14...2^21 - 1
	for (uint64_t value = 0x4000; value < 0x200000; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 3);
		ASSERT_EQ(v[0], (value & 0x7F) | 0x80);
		ASSERT_EQ(v[1], ((value >> 7) & 0x7F) | 0x80);
		ASSERT_EQ(v[2], value >> 14);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^64 - 1
	v.clear();
	writeVarint(std::numeric_limits<uint64_t>::max(), v);
	ASSERT_EQ(v.size(), 10);
	for (int i = 0; i < 9; ++i) {
		ASSERT_EQ(v[i], 0xFF);
	}
	ASSERT_EQ(v[9], 1);
	ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
	ASSERT_EQ(check, std::numeric_limits<uint64_t>::max());

	// Invalid value 1
	uint8_t buf[16];
	memset(buf, -1, sizeof(buf));
	ASSERT_EQ(readVarint(buf, buf + sizeof(buf), check), nullptr);

	// Invalid value 2
	uint8_t buf2[1] = { 0x80 };
	ASSERT_EQ(readVarint(buf2, buf2 + 1, check), nullptr);

	// Invalid value 3
	uint8_t buf3[16];
	memset(buf3, 128, sizeof(buf3));
	ASSERT_EQ(readVarint(buf3, buf3 + sizeof(buf3), check), nullptr);

	// Invalid value 4
	uint32_t check2;
	uint8_t buf4[] = {255, 255, 255, 255, 127};
	ASSERT_EQ(readVarint(buf4, buf4 + sizeof(buf4), check2), nullptr);

	// Invalid value 5
	uint8_t buf5[] = {128, 0};
	ASSERT_EQ(readVarint(buf5, buf5 + sizeof(buf5), check), nullptr);

	// Invalid value 6 (2^64)
	uint8_t buf6[] = {128, 128, 128, 128, 128, 128, 128, 128, 128, 2};
	ASSERT_EQ(readVarint(buf6, buf6 + sizeof(buf6), check), nullptr);
}

TEST(util, bsr)
{
	for (uint64_t i = 0, x = 1; i <= 63; ++i, x <<= 1) {
		ASSERT_EQ(bsr(x), i);
		ASSERT_EQ(bsr_reference(x), i);

		const uint64_t y = x | (x - 1);
		ASSERT_EQ(bsr(y), i);
		ASSERT_EQ(bsr_reference(y), i);
	}
}

TEST(util, onion)
{
	const std::string tests[] = {
		"yucmgsbw7nknw7oi3bkuwudvc657g2xcqahhbjyewazusyytapqo4xid.onion",
		"p2pool2giz2r5cpqicajwoazjcxkfujxswtk3jolfk2ubilhrkqam2id.onion",
		"p2pseeds5qoenuuseyuqxhzzefzxpbhiq4z4h5hfbry5dxd5y2fwudyd.onion",
		"testhrjytc63cnmcgff5tlcz2phd4sixeogfkjq6uinihwcs2awm3oad.onion",
		"testsao5qh4qz4ne3iqytyve6a6ijbzmrok6wbauwxfzplv4g276elyd.onion",
		"testaohgecnzvl6k25fvhkqaizc3vu6e6dxg62qgbtzqmoflnj5bk6id.onion",
		"testgamrbpyy5e6kogd5kk4cdzvr6qzd6w3fj5eyxa5ccyaudwuwx3ad.onion",
		"testdriz2m4xh6czzkjmbsnicqoyqyyiilhkogp3n6if7x5qaairetid.onion",
		"testc7rluz33af3wlypoiwamwzti6gup3il2kqkf7ly7td5qggpvknyd.onion",
		"testlxqch2dtemlwjc4bt3y6fj3vvknjksywugceibnhscybw4vlnlyd.onion",
		"testbbx66qk4cgy342mm32jrod6k6zi4gu6bfvyjxsx3m6mf4khvuyqd.onion",
		"testpita5yopwhs4utuk5ylfndzkijxv3lh7d6gjifxjg7oriuhn3mqd.onion",
		"testdtmzbyzi47b677ocnoyi7w6oylcnyqh77pl2yv5q22qla7agz7qd.onion",
		"testv3qobc33v3gfjnccs24eorkrtdzh5e4jbth5yag32sd5d24xazid.onion",
		"testgwoazhovosqn2yfqaewkd6snynwm66qb5egcbenh3m54yi3ur4yd.onion",
		"testu2oufhxgp6qqehf2ytpxqvmr3qm6dit3k7p3ixhnxjbxwqmfooyd.onion",
		"testvi6s6dp5reui35lv6lnu3tzxmu4h3dofejjmmttr6ax3eshvefid.onion",
		"testsap5p4lorjlvo4ovs6yxmn4lb3lgehsjyolqfcm7l53rqeswvnid.onion",
		"testexfa567ampq3dkw5smfmofci6qvicl3niaoe6pneekcheqdsbfad.onion",
		"testhnodrpe2qukswkp5554csphtq325pnnpm7uqs4ats5es7gcujhqd.onion",
		"testneyu3idcjyvgmdylszcebkw5xsl5bnxyfwdu27fcbb2cm7pcs3id.onion",
		"test5y4it65r5lnm3w4en4lj3bmy35nypmbgshkawt2h2ep3f75yuwyd.onion",
		"testknxevfffltpt2iq5xioye3z52eoh4aefy3aegfmhogqf7w6xtnqd.onion",
		"testshitk3xpt5aex3doyepmbvpsbzptjr6ujso6gahz4arryp7s6vyd.onion",
		"testfin66dkzp7ozolfu7exjxi3cuck35xunt4a56xfanivs4xqsfbqd.onion",
		"testec5noqmo2javrlye5higddskhvsialohrwwi2naoqkxrrwhucaid.onion",
		"testbo2fncb7mblktg23a77clp4pdqfdje7g6axohcegle46bk64hnad.onion",
		"testd7rzyebdtzpx3fjalkqmeuppbmqs4pbx5pxusyq57m73fyjwgxyd.onion",
		"testmw3wweekyz7ui7uodlgq3zbv23hehkusrb257yerlpsizhylswyd.onion",
		"testspzmswow3rc3x6ymbbsfuovcia3umhzribfcpnry7xw66lyjysad.onion",
		"test635ior3cpu4hd4e4ogd3kzy2pugyv3gkfp3q5u4x2riojbhrvtid.onion",
		"testn3vi7q5c5j5dqiq3hd3wtkazpxhfaxg2s6kxe6q75hvjnu62iiqd.onion",
		"testjmo662avqobpfukplqt4bg5jd2dqu6rdr53a6jyju6jf72iavbyd.onion",
		"testertyaowcvevhjdjwqr3jjvqkzzc2vrmp5hvd3iecukgjbla5xnqd.onion",
		"testivnwlanaiqoxbcsmlsgpswpx72c5zifljfwta444mtkfk476pmad.onion",
		"test7u4feuytc3gulkk2mdrmobkqjs6kc5tqxc32qv2v565ybm3kvsyd.onion",
		"testmcndo5ahfvfnlxefpc3325drm4xfgtgx42hj7p7we7ppyursrbyd.onion",
		"testtcr5xoqnirota5v5aonhn6gpzulewfbzb7kduld73jx353drjpyd.onion",
		"testc4biea6pwrya56s2vtus33c3bhrx6pnt3gfwwwoclhkuujvcwhyd.onion",
		"testbjeyc5bizi7ys7cjgklkpeq3bhadaukk6sx3r6pycfxx35ksipyd.onion",
		"testvvumkf5b7k3vaagl54yujefrwsr7iuldkepzewwdiwyogkzzwyyd.onion",
		"testiysaar7h25477y7ee7xhz4foyrjkmtoxbh3kiiazvuehlp7ubiid.onion",
		"test7zh6zfacxeyrt3qkbelnfpf4sepmcypvl33vkbbeylbk3ddf4qad.onion",
		"testebbxturu56qaxvlr7dqbrdjigga7mlmjanq4suc7j5h77h5iszyd.onion",
		"testob7j77x3qmy6dd6ja6wvofhbedzloxae6rrxrf7hv5fpi2aotayd.onion",
		"testgy24eidqv7wgaqtsucvqnagcyohpmzdmox2cpztd5eukmm6ubkid.onion",
		"testtdslb2etamcxo7pklesyqxnidy6m5b5qu3yzcfhafajrnm5rotyd.onion",
		"testha6wehnus7v4qb5cxbuf232fomz7ge6idrrenjewvmcl2fneffid.onion",
		"testmp7u2cxnnjqsjcfz3ydd6gpiqbym5r5rxykqhz3h6ks6nsnthuad.onion",
		"tests3xay2zjfkzzpfzl7s3kpnjftfwxmo7e3v5p657pfxbuqxt5e3id.onion",
		"test6zfam4nauxtjkckvkd6fp55bjuikaj5wevftsfhdromu7wuj2pyd.onion",
		"testssyxuohidxfvtma4wxpiot5qqkmukqcrjw7t2ngfltidzxo6eyid.onion",
		"testmcfwamtj4adtz46izavwrddkp7fbu2swtapuyt5eyfupnztsd6qd.onion",
		"testcycabwxf7em7hu2css5aax7up3opds6twra7hmpjnxi6fdmgs3yd.onion",
		"testaev2vumiarnfrr4x4japjc2xtvvlp65gt4vwwqf3q4zolvprs5id.onion",
		"testkynjqkj65t6wvuwajm55xzninrap4piqek5ao6jiwewvqwezalqd.onion",
		"testnfxt6eemmiwhlme7ys7rj647jv46razwdf6whiwyjoruw4xceyad.onion",
		"testrbutgvilidnf55thbo4pye4jn322ugmepc37celxvazal5uugoid.onion",
		"test7xcn36xbr6raxldgh3kf2xk36gyor3hx3gzy2guhxzntxlvf3iid.onion",
		"testsdjiq77anfffxus3utsmykucoqexpeojaklbmzhab3vow3ozfdqd.onion",
		"testggm7oruqsw3sr2fd4nq4b3nh2fdd7rgw76p6gpz6pu6nsffv6byd.onion",
		"testk5b5gjpsc5jkvqnd24aujh25ksvorjrcw457eremkynzoaxjrhad.onion",
		"testc6mexahgqsbqkxoso5t77nitwwumqn5ucdzbsntgkvuwpxzv4mqd.onion",
		"testcbsvi6v7h2avabs74osdnifiszdlygi4sljxohvuugf24hadjvid.onion",
		"testfbhecs2llswxsgjuuqvq5boo6se3gni7ygjtbnagt4x5qt7sppid.onion",
		"test7gjc7xb7ynoa5nzqrceqvo3fsotmtw2k5tj7ie2okvkmxuejobad.onion",
		"testmskkbp3ikvsfvtfekm5hmjc4ou4hqlerx45qchm5yrwd56m6stad.onion",
		"testv52txxzvdmi5kuuhwbzyrbzrhqnxr6ltvycgavt3wb5uyxcbrqqd.onion",
		"test7nsiyeg2hsmuvi7uhqbaoygf4lfa6ysihaqicrkzwulp7shsh3ad.onion",
		"testu2p6psiaw7qnhvi3v7tjgawbf6zpmjajmbfdofimv3wpniaqleyd.onion",
		"testkqcq6qg3yibtnwxgm2qceti2k74suvgqet2wdqmcoluzu4b3fkqd.onion",
		"test2i4762wcfcl5wgjf7ofnkorsq6l6buuet7ldddezeqgd372sysyd.onion",
		"testftqmujq6h5rhey73mmqlhpuh5zs5cipqqxwbzihiqgw6gnfpp6id.onion",
		"test5hua7kwnsnv3uiwathv3khq4nmhbwsayl6uzj2gs6pmimork2iid.onion",
		"test7tdanour43exhioddlji7jgsgiibi5hg3jhu47wxaszbvtwat2ad.onion",
		"testd26wxq4q44wmvplnngh5onomax5f3brjrocazz56mj7qylogy6id.onion",
		"testyuwguibjovaw2mmzvpxqh2r3dhjddeaez6242pmro37gxivknrqd.onion",
		"testi5lokj4wrawmihfqmic74wac6a4asy6o7erzxjosuyedzsscdeid.onion",
		"testbuwdono434jdgv76u7jjczd7sweu36ga55vo66tdcsjscov5dfad.onion",
		"testor6cqxswpeomtnsqhc73knjftqchalz5whatqddaxguwm5s2fhad.onion",
		"test2tz52bpiib5zbxt2bfg77ika54cfvz3p6ovkqbqiyu6d5ecaetyd.onion",
		"testc5wvnm55zfk3ihkebuf4kxkhaandcqwizkehb6fpfgs2f4tfxvqd.onion",
		"testpxuiq5dgkvhwynsyzrtdsxtthrt4lhjtb2egs34ypwzcvsrgbhqd.onion",
		"testgpc7h7f6tmo6lrz6to5svh6gw2mxgelbo5du6kakuuco5oyu2pad.onion",
		"test7vlusiy2t5e2dpwf4ttlajpefxqpbj274l25iml3ltjf6dwgzhyd.onion",
		"testcaq5d3ehqqwdkdcux4db57lbbcfcl5wfebg7jxwl5gpv7aavxfyd.onion",
		"testaqtkrclsz3ehn4i3i4maqoxniivmdl5gnefelzva6ts2yrx5vyyd.onion",
		"testgkfz4a2ir44r6pacf3fvyrldjk6n4u3odbyveseo2jatze6euxyd.onion",
		"testsrinaqfbsh22gjlkabcwn4rbypsb3nmtutqnjr37tvqmhdc2ysqd.onion",
		"testyo5bximqrzkkeppmr5mopciote6wx6wcnus6wnuanl5c2zztuwad.onion",
		"testmgjjfxt5frdpvfqchrgmoohxnba63q6wt3spva7kvgiae36jjuqd.onion",
		"testn2qrokp2v4vtjjdrrlzosa6iz2v322ntsrguj6t4d2hguouhpzad.onion",
		"test3njq3v3rp4sy5uhyulvl3eus34hev4cybkernrgvlmqonadxalid.onion",
		"testylx25ok4zwlm5myjgvlbudigeqxyvxy2hhk7kvwub4uqsfaawbyd.onion",
		"test4zcne6f7w6xstprxyhwp2gbl4exvvltewrnjhtsss4bu74faokqd.onion",
		"testddleenrfxcbpsqrugj3ugnpjgd2xeneznzopzcndqebmavo65sqd.onion",
		"testoq3eqrragrjpwiegwokzukqd2p73ffy6dcgnc6nerxtodsfotkad.onion",
		"testyivcoaauwqekzux66r2ao4j2hizka4kdeyb5lyvmdzsrw3uybeid.onion",
		"testz5tgehn7i3myjdobvjlnbax7yd2e3ra27gyiprzicvksm5r6i5yd.onion",
		"testc4vbagkuxee3pkgvlb7w2pqgdq3rlaru2ipgpox5xzssejhfizad.onion",
		"testq4ryujfitfcxabcjde6m7uqdztdep6mzd32e4wbtqna4jyponaad.onion",
		"test2muitbvopcoducxb6d5bqry5dmxdatupvh34anzjdeav6xiigead.onion",
		"test76ais6k5t4bmap4uyl2eleh6o4g423cxuvifcoke4gtgd6pjtpqd.onion",
		"TEST76ais6k5t4bmap4uyl2eleh6o4g423cxuvifcoke4gtgd6pjtpqd.onion",
	};

	for (const std::string& address : tests) {
		const hash h = from_onion_v3(address);
		ASSERT_TRUE(!h.empty());

		const std::string s1 = to_onion_v3(h);

		std::string s2 = address;
		for (char& c : s2) {
			c = std::tolower(c);
		}

		ASSERT_EQ(s1, s2);
	}

	ASSERT_TRUE(from_onion_v3("tooshort.onion").empty());
	ASSERT_TRUE(from_onion_v3("inval1dcharacter777777777777777777777777777777777777777d.onion").empty());
	ASSERT_TRUE(from_onion_v3("wrongchecksum777777777777777777777777777777777777777777d.onion").empty());
	ASSERT_TRUE(from_onion_v3("yucmgsbw7nknw7oi3bkuwudvc657g2xcqahhbjyewazusyytapqo4xid.xnion").empty());

	// Invalid pubkey
	ASSERT_TRUE(from_onion_v3("civ5tgldg3yx73ytse6hvvk3nm6q3zctbqvytpszihm35b33ze73kxad.onion").empty());
}

}

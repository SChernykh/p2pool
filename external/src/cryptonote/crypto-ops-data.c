// Copyright (c) 2014-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifdef _MSC_VER
#pragma warning(disable: 4146 4242 4244 4668 4710 4711 5045)
#endif

#include <stdint.h>

#include "crypto-ops.h"

#if FE_RADIX_51

const fe fe_d = {0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029, 0x739c663a03cbb, 0x52036cee2b6ff}; /* d */
const fe fe_sqrtm1 = {0x61b274a0ea0b0, 0x0d5a5fc8f189d, 0x7ef5e9cbd0c60, 0x78595a6804c9e, 0x2b8324804fc1d}; /* sqrt(-1) */
const fe fe_d2 = {0x69b9426b2f159, 0x35050762add7a, 0x3cf44c0038052, 0x6738cc7407977, 0x2406d9dc56dff}; /* 2 * d */
const fe fe_a_sub_d = {0x4b235eca68749, 0x657d7c4ea9142, 0x2185d9ffe3fd6, 0x0c6399c5fc344, 0x2dfc9311d4900}; /* a - d */
const fe fe_a0 = {0x69b9426b2f157, 0x35050762add7a, 0x3cf44c0038052, 0x6738cc7407977, 0x2406d9dc56dff}; /* A0 = 2 * (a + d) */
const fe fe_ap = {0x2c8d7b29a1d3f, 0x15f5f13aa450a, 0x061767ff8ff5b, 0x318e6717f0d11, 0x37f24c4752400}; /* Ap = -2 * A0 */
const fe fe_msqrt2b = {0x73ec897eb404c, 0x5dfcb1c812353, 0x2192e3772f923, 0x36ff667d3f230, 0x184e375b980a7};

const fe fe_ma2 = {0x7ffc8db3de3c9, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff}; /* -A^2 */
const fe fe_ma = {0x7fffffff892e7, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff}; /* -A */
const fe fe_fffb1 = {0x76975321c41ee, 0x517254e71a454, 0x7ec678f465012, 0x58b9054e29ba0, 0x7e71fbefdad61}; /* sqrt(-2 * A * (A + 2)) */
const fe fe_fffb2 = {0x66483607c9ae0, 0x0c08adefbfa5b, 0x0597ef947780d, 0x67b48ea28dbe0, 0x4d061e0a045a2}; /* sqrt(2 * A * (A + 2)) */
const fe fe_fffb3 = {0x37d8717302c66, 0x1d4b2c8452b03, 0x4368bb50093fd, 0x477dc4aa3201f, 0x674a110d14c20}; /* sqrt(-sqrt(-1) * A * (A + 2)) */
const fe fe_fffb4 = {0x51903b6b39186, 0x11427e94930a7, 0x3dd0cbbb91bf0, 0x5fc93607a443f, 0x1a43f3031067d}; /* sqrt(sqrt(-1) * A * (A + 2)) */
const fe fe_a_inv_3 = {0x2aaaaaaad2451, 0x5555555555555, 0x2aaaaaaaaaaaa, 0x5555555555555, 0x2aaaaaaaaaaaa}; /* A / 3 */
const fe fe_c = {0x1fb5500ba81e7, 0x5d6905cafa672, 0x00ec204e978b0, 0x4a216c27b91fe, 0x70d9120b9f5ff}; /* sqrt(-(A + 2)) */
const fe fe_one = {0x0000000000001, 0x0000000000000, 0x0000000000000, 0x0000000000000, 0x0000000000000};
const fe fe_m1 = {0x7ffffffffffec, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff};
const fe fe_inv2 = {0x7fffffffffff7, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff, 0x3ffffffffffff}; /* 1 / 2 */

const ge_p3 ge_p3_identity = { {0}, {1, 0}, {1, 0}, {0} };
const ge_p3 ge_p3_H = {
  {0x46649386fd873, 0x1d0c4fddf4d0e, 0x73cddc5ab32b3, 0x65c2eab55bf7c, 0x6188ae4072004},
  {0x137157059658b, 0x633fb9d4555f3, 0x545c9b3ab42b7, 0x39654e7aa20ea, 0x141f9cd30d3a1},
  {0x0000000000001, 0x0000000000000, 0x0000000000000, 0x0000000000000, 0x0000000000000},
  {0x6c8160965b85d, 0x6f6cb437a16a2, 0x47e1f8869205f, 0x0c82358720e9a, 0x6391430de06ee}
};

#else

/* sqrt(x) is such an integer y that 0 <= y <= p - 1, y % 2 = 0, and y^2 = x (mod p). */
/* d = -121665 / 121666 */
const fe fe_d = {-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116}; /* d */
const fe fe_sqrtm1 = {-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482}; /* sqrt(-1) */
const fe fe_d2 = {-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199}; /* 2 * d */

/* a = -1 */
// TODO: double check these consts
const fe fe_a_sub_d = {10913609, -13857413, 15372611, -6949391, -114729, 8787816, 6275908, 3247719, 18696448, 12055116}; /* a - d */
const fe fe_a0 = {-21827241, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199}; /* A0 = 2 * (a + d) */
const fe fe_ap = {-23454401, 11679213, -5618422, 5756869, -458917, 1596832, 25103633, 12990876, 7676928, 14666033}; /* Ap = -2 * A0 */
const fe fe_msqrt2b = {-1359796, -3165658, 8463188, -8916281, -9242332, 8801166, -2887120, 14417306, 28934311, 6371549};

/* A = 2 * (1 - d) / (1 + d) = 486662 */
const fe fe_ma2 = {-12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0}; /* -A^2 */
const fe fe_ma = {-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0}; /* -A */
const fe fe_fffb1 = {-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568}; /* sqrt(-2 * A * (A + 2)) */
const fe fe_fffb2 = {8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080}; /* sqrt(2 * A * (A + 2)) */
const fe fe_fffb3 = {-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756}; /* sqrt(-sqrt(-1) * A * (A + 2)) */
const fe fe_fffb4 = {-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324}; /* sqrt(sqrt(-1) * A * (A + 2)) */
const fe fe_a_inv_3 = {-22207407, 11184811, 22369621, -11184811, -22369621, 11184811, 22369621, -11184811, -22369621, 11184811}; /* A / 3*/
const fe fe_c = {12222970, 8312128, 11511410, -9067497, 15300785, 241793, -25456130, -14121551, 12187136, -3972024}; /* sqrt(-(A + 2))*/
const fe fe_one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const fe fe_m1 = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const fe fe_inv2 = {10, 0, 0, 0, 0, 0, 0, 0, 0, -16777216}; /* 1 / 2 */
const ge_p3 ge_p3_identity = { {0}, {1, 0}, {1, 0}, {0} };
const ge_p3 ge_p3_H = {
  {7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503},
  {5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251},
  {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  {23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428}
};

#endif /* FE_RADIX_51 */

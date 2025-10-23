// Copyright (c) 2024, The Monero Project
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

#ifdef _MSC_VER
#pragma warning(disable: 4800)
#endif

extern "C" {
#include "crypto-ops.h"
}

#include "fcmp_pp_crypto.h"
#include <cstring>

static bool fe_compare(const fe a, const fe b)
{
    unsigned char a_bytes[32];
    unsigned char b_bytes[32];

    fe_tobytes(a_bytes, a);
    fe_tobytes(b_bytes, b);

    return memcmp(a_bytes, b_bytes, sizeof(a_bytes)) == 0;
}

static bool sqrt_ext(fe y, const fe x)
{
    fe y_res;

    fe x2;
    fe_dbl(x2, x);

    fe b;
    fe_pow22523(b, x2);

    fe b_sq;
    fe_sq(b_sq, b);

    fe c;
    fe_mul(c, x2, b_sq);

    if (fe_compare(c, fe_one) || fe_compare(c, fe_m1))
    {
        fe_0(c);
        c[0] = 3;
    }

    fe c_sub_1;
    fe_sub(c_sub_1, c, fe_one);

    fe_mul(y_res, x, b);
    fe_mul(y_res, y_res, c_sub_1);

    if (fe_isnegative(y_res)) {
        fe_neg(y_res, y_res);
    }

    fe y_sq;
    fe_sq(y_sq, y_res);
    bool r = fe_compare(x, y_sq);

    fe_copy(y, y_res);
    return r;
};

namespace fcmp_pp
{
    // TODO: impl faster sqrt
    bool sqrt(fe y, const fe x)
    {
        return sqrt_ext(y, x);
    };
} // namespace fcmp_pp

static void inv_iso(fe u_out, fe w_out, const fe u, const fe w)
{
    // 4u
    fe_dbl(u_out, u);
    fe_dbl(u_out, u_out);
    // 2w
    fe_dbl(w_out, w);
};

static void inv_psi1(fe e_out, fe u_out, fe w_out, const fe e, const fe u, const fe w)
{
    fe e_res, u_res, w_res;

    fe tt;
    bool cc = sqrt_ext(tt, u);
    fe_copy(w_res, tt);
    fe w_;
    fe_copy(w_, w);
    fe_copy(e_res, e);

    if (!cc)
    {
        fe tt_sq;
        fe_sq(tt_sq, tt);
        fe neg_u_dbl;
        fe_dbl(neg_u_dbl, u);
        fe_neg(neg_u_dbl, neg_u_dbl);
        if (fe_compare(tt_sq, neg_u_dbl)) {
            fe_mul(tt, tt, fe_sqrtm1);
        }

        fe_mul(w_, w, tt);

        fe e_sq;
        fe_sq(e_sq, e);
        fe_mul(w_res, fe_msqrt2b, e_sq);

        fe_mul(e_res, e_res, tt);
    }

    fe w_res_sq;
    fe_sq(w_res_sq, w_res);

    fe e_res_sq;
    fe_sq(e_res_sq, e_res);

    fe A_e_sq;
    fe_mul(A_e_sq, fe_a0, e_res_sq);

    fe w_res_w;
    fe_mul(w_res_w, w_res, w_);

    fe_sub(u_res, w_res_sq, A_e_sq);
    fe_reduce(u_res, u_res);
    fe_sub(u_res, u_res, w_res_w);
    fe_mul(u_res, u_res, fe_inv2);

    fe_copy(e_out, e_res);
    fe_copy(u_out, u_res);
    fe_copy(w_out, w_res);
};

static bool inv_psi2(fe u_out, fe w_out, const fe e, const fe u, const fe w)
{
    fe u_res, w_res;

    if (!fcmp_pp::sqrt(w_res, u))
        return false;
    fe e_sq;
    fe_sq(e_sq, e);
    fe Ap_e_sq;
    fe_mul(Ap_e_sq, fe_ap, e_sq);

    fe w_res_w;
    fe_mul(w_res_w, w_res, w);

    fe_sub(u_res, u, Ap_e_sq);
    fe_reduce(u_res, u_res);
    fe_sub(u_res, u_res, w_res_w);
    fe_mul(u_res, u_res, fe_inv2);

    fe_copy(u_out, u_res);
    fe_copy(w_out, w_res);

    return true;
};

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
bool mul8_is_identity(const ge_p3 &point) {
    ge_p2 point_ge_p2;
    ge_p3_to_p2(&point_ge_p2, &point);
    ge_p1p1 point_mul8;
    ge_mul8(&point_mul8, &point_ge_p2);
    ge_p3 point_mul8_p3;
    ge_p1p1_to_p3(&point_mul8_p3, &point_mul8);
    return ge_p3_is_point_at_infinity_vartime(&point_mul8_p3);
}
//----------------------------------------------------------------------------------------------------------------------
// https://github.com/kayabaNerve/fcmp-plus-plus/blob/94744c5324e869a9483bbbd93a864e108304bf76/crypto/divisors/src/tests/torsion_check.rs
// Returns true if point is torsion free
// Pre-condition: point is a valid point and point*8 not equal to identity
// WARNING1: this approach needs to be carefully vetted academically and audited
// before it can be used in production.
// WARNING2: since fe_add and fe_sub expect the input fe's to be within a
// smaller domain than the output fe, we sometimes need to "reduce" a field elem
// to chain calls to fe_add and fe_sub. Notice all calls to fe_reduce.
bool torsion_check_vartime(const ge_p3 &point) {
    //assert(!mul8_is_identity(point));

    // ed to wei
    fe e, u, w;
    {
        fe z_plus_ed_y, z_minus_ed_y;
        fe_add(z_plus_ed_y, fe_one, point.Y);
        fe_sub(z_minus_ed_y, fe_one, point.Y);

        // e
        fe_mul(e, z_minus_ed_y, point.X);
        // u
        fe_mul(u, fe_a_sub_d, z_plus_ed_y);
        fe_mul(u, u, point.X);
        fe_mul(u, u, e);
        // w
        fe_dbl(w, z_minus_ed_y);
    }

    //assert(check_e_u_w(e, u, w));

    // Torsion check
    for (int i = 0; i < 2; ++i) {
        inv_iso(u, w, u, w);
        if (!inv_psi2(u, w, e, u, w)) {
            return false;
        }
        inv_psi1(e, u, w, e, u, w);
        //assert(check_e_u_w(e, u, w));
    }

    fe _;
    inv_iso(u, _, u, w);

    if (!sqrt(u, u)) {
        return false;
    }

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp

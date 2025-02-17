/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest.h"
#include "faest_aes.h"
#include "fields.h"
#include "vole.h"
#include "universal_hashing.h"
#include "utils.h"
#include "parameters.h"

#include <string.h>
#include <stdlib.h>

#include <stdio.h>

#define FAEST_128_NK (FAEST_128_LAMBDA / 32)
#define FAEST_192_NK (FAEST_192_LAMBDA / 32)
#define FAEST_256_NK (FAEST_256_LAMBDA / 32)

#define FAEST_128_R FAEST_128S_R
#define FAEST_192_R FAEST_192S_R
#define FAEST_256_R FAEST_256S_R

static_assert(FAEST_128_LAMBDA == FAEST_128S_LAMBDA, "Invalid parameters");
static_assert(FAEST_128F_ELL == FAEST_128S_ELL, "Invalid parameters");
static_assert(FAEST_128F_LAMBDA == FAEST_128S_LAMBDA, "Invalid parameters");
static_assert(FAEST_128F_Lke == FAEST_128S_Lke, "Invalid parameters");
static_assert(FAEST_128F_Nst == FAEST_128S_Nst, "Invalid parameters");
static_assert(FAEST_128_R == FAEST_128S_R, "Invalid parameters");
static_assert(FAEST_128F_R == FAEST_128S_R, "Invalid parameters");
static_assert(FAEST_128F_Senc == FAEST_128S_Senc, "Invalid parameters");
static_assert(FAEST_128F_Ske == FAEST_128S_Ske, "Invalid parameters");

static_assert(FAEST_192_LAMBDA == FAEST_192S_LAMBDA, "Invalid parameters");
static_assert(FAEST_192F_ELL == FAEST_192S_ELL, "Invalid parameters");
static_assert(FAEST_192F_LAMBDA == FAEST_192S_LAMBDA, "Invalid parameters");
static_assert(FAEST_192F_Lke == FAEST_192S_Lke, "Invalid parameters");
static_assert(FAEST_192F_Nst == FAEST_192S_Nst, "Invalid parameters");
static_assert(FAEST_192_R == FAEST_192S_R, "Invalid parameters");
static_assert(FAEST_192F_R == FAEST_192S_R, "Invalid parameters");
static_assert(FAEST_192F_Senc == FAEST_192S_Senc, "Invalid parameters");
static_assert(FAEST_192F_Ske == FAEST_192S_Ske, "Invalid parameters");

static_assert(FAEST_256_LAMBDA == FAEST_256S_LAMBDA, "Invalid parameters");
static_assert(FAEST_256F_ELL == FAEST_256S_ELL, "Invalid parameters");
static_assert(FAEST_256F_LAMBDA == FAEST_256S_LAMBDA, "Invalid parameters");
static_assert(FAEST_256F_Lke == FAEST_256S_Lke, "Invalid parameters");
static_assert(FAEST_256F_Nst == FAEST_256S_Nst, "Invalid parameters");
static_assert(FAEST_256_R == FAEST_256S_R, "Invalid parameters");
static_assert(FAEST_256F_R == FAEST_256S_R, "Invalid parameters");
static_assert(FAEST_256F_Senc == FAEST_256S_Senc, "Invalid parameters");
static_assert(FAEST_256F_Ske == FAEST_256S_Ske, "Invalid parameters");

static_assert(FAEST_128_LAMBDA == FAEST_EM_128S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_128F_LAMBDA == FAEST_EM_128S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_128F_Lenc == FAEST_EM_128S_Lenc, "Invalid parameters");
static_assert(FAEST_EM_128F_Nst == FAEST_EM_128S_Nst, "Invalid parameters");
static_assert(FAEST_128_R == FAEST_EM_128S_R, "Invalid parameters");
static_assert(FAEST_EM_128F_R == FAEST_EM_128S_R, "Invalid parameters");
static_assert(FAEST_EM_128F_Senc == FAEST_EM_128S_Senc, "Invalid parameters");
// for scan-build
static_assert(FAEST_EM_128F_LAMBDA * (FAEST_EM_128F_R + 1) / 8 ==
                  sizeof(aes_word_t) * FAEST_EM_128F_Nst * (FAEST_EM_128F_R + 1),
              "Invalid parameters");

static_assert(FAEST_192_LAMBDA == FAEST_EM_192S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_192F_LAMBDA == FAEST_EM_192S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_192F_Lenc == FAEST_EM_192S_Lenc, "Invalid parameters");
static_assert(FAEST_EM_192F_Nst == FAEST_EM_192S_Nst, "Invalid parameters");
static_assert(FAEST_192_R == FAEST_EM_192S_R, "Invalid parameters");
static_assert(FAEST_EM_192F_R == FAEST_EM_192S_R, "Invalid parameters");
static_assert(FAEST_EM_192F_Senc == FAEST_EM_192S_Senc, "Invalid parameters");
// for scan-build
static_assert(FAEST_EM_192F_LAMBDA * (FAEST_EM_192F_R + 1) / 8 ==
                  sizeof(aes_word_t) * FAEST_EM_192F_Nst * (FAEST_EM_192F_R + 1),
              "Invalid parameters");

static_assert(FAEST_256_LAMBDA == FAEST_EM_256S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_256F_LAMBDA == FAEST_EM_256S_LAMBDA, "Invalid parameters");
static_assert(FAEST_EM_256F_Lenc == FAEST_EM_256S_Lenc, "Invalid parameters");
static_assert(FAEST_EM_256F_Nst == FAEST_EM_256S_Nst, "Invalid parameters");
static_assert(FAEST_256_R == FAEST_EM_256S_R, "Invalid parameters");
static_assert(FAEST_EM_256F_R == FAEST_EM_256S_R, "Invalid parameters");
static_assert(FAEST_EM_256F_Senc == FAEST_EM_256S_Senc, "Invalid parameters");
// for scan-build
static_assert(FAEST_EM_256F_LAMBDA * (FAEST_EM_256F_R + 1) / 8 ==
                  sizeof(aes_word_t) * FAEST_EM_256F_Nst * (FAEST_EM_256F_R + 1),
              "Invalid parameters");

/* pad sizes to multiples of some value; assumes that a is a power of 2 */
#define PAD_TO(s, a) (((s) + (a) - 1) & ~((a) - 1))

#define BF128_ALLOC(s) faest_aligned_alloc(BF128_ALIGN, PAD_TO((s) * sizeof(bf128_t), BF128_ALIGN))
#define BF192_ALLOC(s) faest_aligned_alloc(BF192_ALIGN, PAD_TO((s) * sizeof(bf192_t), BF192_ALIGN))
#define BF256_ALLOC(s) faest_aligned_alloc(BF256_ALIGN, PAD_TO((s) * sizeof(bf256_t), BF256_ALIGN))

static const bf8_t Rcon[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

// ADD ROUND KEY
/*
Called in EncCstrnts, takes in owf_in (bits) and their tags (0 for prover, owf_in (bit) * delta for
verifier)
*/
static void aes_128_add_round_key_prover(uint8_t* out, bf128_t* out_tag, const uint8_t* in,
                                         const bf128_t* in_tag, const uint8_t* k,
                                         const bf128_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  xor_u8_array(in, k, out, Nstbits / 8);
  for (unsigned int i = 0; i < Nstbits; i++) {
    out_tag[i] = bf128_add(in_tag[i], k_tag[i]);
  }
}

static void aes_192_add_round_key_prover(uint8_t* out, bf192_t* out_tag, const uint8_t* in,
                                         const bf192_t* in_tag, const uint8_t* k,
                                         const bf192_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  xor_u8_array(in, k, out, Nstbits / 8);
  for (unsigned int i = 0; i < Nstbits; i++) {
    out_tag[i] = bf192_add(in_tag[i], k_tag[i]);
  }
}

static void aes_256_add_round_key_prover(uint8_t* out, bf256_t* out_tag, const uint8_t* in,
                                         const bf256_t* in_tag, const uint8_t* k,
                                         const bf256_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  xor_u8_array(in, k, out, Nstbits / 8);
  for (unsigned int i = 0; i < Nstbits; i++) {
    out_tag[i] = bf256_add(in_tag[i], k_tag[i]);
  }
}

static void aes_128_add_round_key_verifier(bf128_t* out_key, const bf128_t* in_key,
                                           const bf128_t* k_key, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  for (unsigned int i = 0; i < Nstbits; i++) {
    out_key[i] = bf128_add(in_key[i], k_key[i]);
  }
}

static void aes_192_add_round_key_verifier(bf192_t* out_key, const bf192_t* in_key,
                                           const bf192_t* k_key, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  for (unsigned int i = 0; i < Nstbits; i++) {
    out_key[i] = bf192_add(in_key[i], k_key[i]);
  }
}

static void aes_256_add_round_key_verifier(bf256_t* out_key, const bf256_t* in_key,
                                           const bf256_t* k_key, const faest_paramset_t* params) {
  const unsigned int Nst     = params->Nst;
  const unsigned int Nstbits = Nst * 32;

  for (unsigned int i = 0; i < Nstbits; i++) {
    out_key[i] = bf256_add(in_key[i], k_key[i]);
  }
}

// F256/F2.CONJUGATES
static void aes_128_f256_f2_conjugates_1(bf128_t* y, const uint8_t* state,
                                         const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    uint8_t x0 = state[i];
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf128_byte_combine_bits(x0);
      x0           = bits_sq(x0);
    }
    y[i * 8 + 7] = bf128_byte_combine_bits(x0);
  }
}

static void aes_192_f256_f2_conjugates_1(bf192_t* y, const uint8_t* state,
                                         const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    uint8_t x0 = state[i];
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf192_byte_combine_bits(x0);
      x0           = bits_sq(x0);
    }
    y[i * 8 + 7] = bf192_byte_combine_bits(x0);
  }
}

static void aes_256_f256_f2_conjugates_1(bf256_t* y, const uint8_t* state,
                                         const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    uint8_t x0 = state[i];
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf256_byte_combine_bits(x0);
      x0           = bits_sq(x0);
    }
    y[i * 8 + 7] = bf256_byte_combine_bits(x0);
  }
}

static void aes_128_f256_f2_conjugates_128(bf128_t* y, const bf128_t* state,
                                           const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    bf128_t x[8];
    memcpy(x, state + i * 8, sizeof(x));
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf128_byte_combine(x);
      bf128_sq_bit_inplace(x);
    }
    y[i * 8 + 7] = bf128_byte_combine(x);
  }
}

static void aes_192_f256_f2_conjugates_192(bf192_t* y, const bf192_t* state,
                                           const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    bf192_t x[8];
    memcpy(x, state + i * 8, sizeof(x));
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf192_byte_combine(x);
      bf192_sq_bit_inplace(x);
    }
    y[i * 8 + 7] = bf192_byte_combine(x);
  }
}

static void aes_256_f256_f2_conjugates_256(bf256_t* y, const bf256_t* state,
                                           const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i != Nst_bytes; ++i) {
    bf256_t x[8];
    memcpy(x, state + (i * 8), sizeof(x));
    for (unsigned int j = 0; j != 7; ++j) {
      y[i * 8 + j] = bf256_byte_combine(x);
      bf256_sq_bit_inplace(x);
    }
    y[i * 8 + 7] = bf256_byte_combine(x);
  }
}

// INV NORM TO CONJUGATES

static const bf128_t bf128_beta_squares[5] = {
    BF128C(UINT64_C(0xaca8c2a7190f676b), UINT64_C(0xdb4a932e2cae3d8b)),
    BF128C(UINT64_C(0x34d2f7fba603e341), UINT64_C(0x500317bd159d73bb)),
    BF128C(UINT64_C(0xcbc26e38bdbd6c62), UINT64_C(0xf210539fd8dd2772)),
    BF128C(UINT64_C(0x53b85b6402b1e849), UINT64_C(0x7959d70ce1ee6942)),
    BF128C(UINT64_C(0xaca8c2a7190f676b), UINT64_C(0xdb4a932e2cae3d8b)),
};
static const bf128_t bf128_beta_cubes[4] = {
    BF128C(UINT64_C(0x53b85b6402b1e849), UINT64_C(0x7959d70ce1ee6942)),
    BF128C(UINT64_C(0xaca8c2a7190f676b), UINT64_C(0xdb4a932e2cae3d8b)),
    BF128C(UINT64_C(0x34d2f7fba603e341), UINT64_C(0x500317bd159d73bb)),
    BF128C(UINT64_C(0xcbc26e38bdbd6c62), UINT64_C(0xf210539fd8dd2772)),
};

static const bf192_t bf192_beta_squares[5] = {
    BF192C(UINT64_C(0x4a2fe80a53fe16e7), UINT64_C(0x89bfb5055f8ff266),
           UINT64_C(0x6c4aecc3fdd0f812)),
    BF192C(UINT64_C(0xf061255c52e359d4), UINT64_C(0x125a337e5e808579),
           UINT64_C(0x54ed13a2d09da6a4)),
    BF192C(UINT64_C(0x941080db88d09584), UINT64_C(0x62217a15d25ec520),
           UINT64_C(0xee0fc537c5a9cb74)),
    BF192C(UINT64_C(0x2e5e4d8d89cddab6), UINT64_C(0xf9c4fc6ed351b23f),
           UINT64_C(0xd6a83a56e8e495c2)),
    BF192C(UINT64_C(0x4a2fe80a53fe16e7), UINT64_C(0x89bfb5055f8ff266),
           UINT64_C(0x6c4aecc3fdd0f812)),
};
static const bf192_t bf192_beta_cubes[4] = {
    BF192C(UINT64_C(0x2e5e4d8d89cddab6), UINT64_C(0xf9c4fc6ed351b23f),
           UINT64_C(0xd6a83a56e8e495c2)),
    BF192C(UINT64_C(0x4a2fe80a53fe16e7), UINT64_C(0x89bfb5055f8ff266),
           UINT64_C(0x6c4aecc3fdd0f812)),
    BF192C(UINT64_C(0xf061255c52e359d4), UINT64_C(0x125a337e5e808579),
           UINT64_C(0x54ed13a2d09da6a4)),
    BF192C(UINT64_C(0x941080db88d09584), UINT64_C(0x62217a15d25ec520),
           UINT64_C(0xee0fc537c5a9cb74)),
};

static const bf256_t bf256_beta_squares[5] = {
    BF256C(UINT64_C(0x4074aaa06e5faade), UINT64_C(0xd9ca3e577cc14c4a), UINT64_C(0xda065d89ba07bf41),
           UINT64_C(0x96ff78f99e8ca1cb)),
    BF256C(UINT64_C(0xfc8046a8eaa315e8), UINT64_C(0x3cd447937f790879), UINT64_C(0x2adc5a08c13f1cfb),
           UINT64_C(0x67dbaeb2ec4abc7c)),
    BF256C(UINT64_C(0x4074aaa16e5eabeb), UINT64_C(0xd9ca3e577cc14c4b), UINT64_C(0xda065d89ba07bf40),
           UINT64_C(0x96ff78f99e8ca1cb)),
    BF256C(UINT64_C(0xfc8046a9eaa214dc), UINT64_C(0x3cd447937f790878), UINT64_C(0x2adc5a08c13f1cfa),
           UINT64_C(0x67dbaeb2ec4abc7c)),
    BF256C(UINT64_C(0x4074aaa06e5faade), UINT64_C(0xd9ca3e577cc14c4a), UINT64_C(0xda065d89ba07bf41),
           UINT64_C(0x96ff78f99e8ca1cb)),
};
static const bf256_t bf256_beta_cubes[4] = {
    BF256C(UINT64_C(0xfc8046a9eaa214dc), UINT64_C(0x3cd447937f790878), UINT64_C(0x2adc5a08c13f1cfa),
           UINT64_C(0x67dbaeb2ec4abc7c)),
    BF256C(UINT64_C(0x4074aaa06e5faade), UINT64_C(0xd9ca3e577cc14c4a), UINT64_C(0xda065d89ba07bf41),
           UINT64_C(0x96ff78f99e8ca1cb)),
    BF256C(UINT64_C(0xfc8046a8eaa315e8), UINT64_C(0x3cd447937f790879), UINT64_C(0x2adc5a08c13f1cfb),
           UINT64_C(0x67dbaeb2ec4abc7c)),
    BF256C(UINT64_C(0x4074aaa16e5eabeb), UINT64_C(0xd9ca3e577cc14c4b), UINT64_C(0xda065d89ba07bf40),
           UINT64_C(0x96ff78f99e8ca1cb)),
};

static void aes_128_inv_norm_to_conjugates_prover(bf128_t* y_val, bf128_t* y_tag,
                                                  const uint8_t x_val, const bf128_t* x_tag) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_val[i] = bf128_add(bf128_add(bf128_from_bit(get_bit(x_val, 0)),
                                   bf128_mul_bit(bf128_beta_squares[i], get_bit(x_val, 1))),
                         bf128_add(bf128_mul_bit(bf128_beta_squares[i + 1], get_bit(x_val, 2)),
                                   bf128_mul_bit(bf128_beta_cubes[i], get_bit(x_val, 3))));
    y_tag[i] = bf128_add(bf128_add(x_tag[0], bf128_mul(bf128_beta_squares[i], x_tag[1])),
                         bf128_add(bf128_mul(bf128_beta_squares[i + 1], x_tag[2]),
                                   bf128_mul(bf128_beta_cubes[i], x_tag[3])));
  }
}

static void aes_192_inv_norm_to_conjugates_prover(bf192_t* y_val, bf192_t* y_tag,
                                                  const uint8_t x_val, const bf192_t* x_tag) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_val[i] = bf192_add(bf192_add(bf192_from_bit(get_bit(x_val, 0)),
                                   bf192_mul_bit(bf192_beta_squares[i], get_bit(x_val, 1))),
                         bf192_add(bf192_mul_bit(bf192_beta_squares[i + 1], get_bit(x_val, 2)),
                                   bf192_mul_bit(bf192_beta_cubes[i], get_bit(x_val, 3))));
    y_tag[i] = bf192_add(bf192_add(x_tag[0], bf192_mul(bf192_beta_squares[i], x_tag[1])),
                         bf192_add(bf192_mul(bf192_beta_squares[i + 1], x_tag[2]),
                                   bf192_mul(bf192_beta_cubes[i], x_tag[3])));
  }
}

static void aes_256_inv_norm_to_conjugates_prover(bf256_t* y_val, bf256_t* y_tag,
                                                  const uint8_t x_val, const bf256_t* x_tag) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_val[i] = bf256_add(bf256_add(bf256_from_bit(get_bit(x_val, 0)),
                                   bf256_mul_bit(bf256_beta_squares[i], get_bit(x_val, 1))),
                         bf256_add(bf256_mul_bit(bf256_beta_squares[i + 1], get_bit(x_val, 2)),
                                   bf256_mul_bit(bf256_beta_cubes[i], get_bit(x_val, 3))));
    y_tag[i] = bf256_add(bf256_add(x_tag[0], bf256_mul(bf256_beta_squares[i], x_tag[1])),
                         bf256_add(bf256_mul(bf256_beta_squares[i + 1], x_tag[2]),
                                   bf256_mul(bf256_beta_cubes[i], x_tag[3])));
  }
}

static void aes_128_inv_norm_to_conjugates_verifier(bf128_t* y_eval, const bf128_t* x_eval) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_eval[i] = bf128_add(bf128_add(x_eval[0], bf128_mul(bf128_beta_squares[i], x_eval[1])),
                          bf128_add(bf128_mul(bf128_beta_squares[i + 1], x_eval[2]),
                                    bf128_mul(bf128_beta_cubes[i], x_eval[3])));
  }
}

static void aes_192_inv_norm_to_conjugates_verifier(bf192_t* y_eval, const bf192_t* x_eval) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_eval[i] = bf192_add(bf192_add(x_eval[0], bf192_mul(bf192_beta_squares[i], x_eval[1])),
                          bf192_add(bf192_mul(bf192_beta_squares[i + 1], x_eval[2]),
                                    bf192_mul(bf192_beta_cubes[i], x_eval[3])));
  }
}

static void aes_256_inv_norm_to_conjugates_verifier(bf256_t* y_eval, const bf256_t* x_eval) {
  // :1-2
  for (unsigned int i = 0; i != 4; ++i) {
    y_eval[i] = bf256_add(bf256_add(x_eval[0], bf256_mul(bf256_beta_squares[i], x_eval[1])),
                          bf256_add(bf256_mul(bf256_beta_squares[i + 1], x_eval[2]),
                                    bf256_mul(bf256_beta_cubes[i], x_eval[3])));
  }
}

// // INV NORM CONSTRAINTS
static void aes_128_inv_norm_constraints_prover(zk_hash_128_3_ctx* hasher,
                                                const bf128_t* conjugates,
                                                const bf128_t* conjugates_tag, const bf128_t* y,
                                                const bf128_t* y_tag) {
  zk_hash_128_3_update(
      hasher, bf128_mul(bf128_mul(*y_tag, conjugates_tag[1]), conjugates_tag[4]),
      bf128_add(bf128_add(bf128_mul(bf128_mul(*y, conjugates_tag[1]), conjugates_tag[4]),
                          bf128_mul(bf128_mul(*y_tag, conjugates_tag[1]), conjugates[4])),
                bf128_mul(bf128_mul(*y_tag, conjugates[1]), conjugates_tag[4])),
      bf128_add(bf128_add(bf128_add(bf128_mul(bf128_mul(*y, conjugates[1]), conjugates_tag[4]),
                                    bf128_mul(bf128_mul(*y, conjugates_tag[1]), conjugates[4])),
                          bf128_mul(bf128_mul(*y_tag, conjugates[1]), conjugates[4])),
                conjugates_tag[0]));
}

static void aes_192_inv_norm_constraints_prover(zk_hash_192_3_ctx* hasher,
                                                const bf192_t* conjugates,
                                                const bf192_t* conjugates_tag, const bf192_t* y,
                                                const bf192_t* y_tag) {
  zk_hash_192_3_update(
      hasher, bf192_mul(bf192_mul(*y_tag, conjugates_tag[1]), conjugates_tag[4]),
      bf192_add(bf192_add(bf192_mul(bf192_mul(*y, conjugates_tag[1]), conjugates_tag[4]),
                          bf192_mul(bf192_mul(*y_tag, conjugates_tag[1]), conjugates[4])),
                bf192_mul(bf192_mul(*y_tag, conjugates[1]), conjugates_tag[4])),
      bf192_add(bf192_add(bf192_add(bf192_mul(bf192_mul(*y, conjugates[1]), conjugates_tag[4]),
                                    bf192_mul(bf192_mul(*y, conjugates_tag[1]), conjugates[4])),
                          bf192_mul(bf192_mul(*y_tag, conjugates[1]), conjugates[4])),
                conjugates_tag[0]));
}

static void aes_256_inv_norm_constraints_prover(zk_hash_256_3_ctx* hasher,
                                                const bf256_t* conjugates,
                                                const bf256_t* conjugates_tag, const bf256_t* y,
                                                const bf256_t* y_tag) {
  zk_hash_256_3_update(
      hasher, bf256_mul(bf256_mul(*y_tag, conjugates_tag[1]), conjugates_tag[4]),
      bf256_add(bf256_add(bf256_mul(bf256_mul(*y, conjugates_tag[1]), conjugates_tag[4]),
                          bf256_mul(bf256_mul(*y_tag, conjugates_tag[1]), conjugates[4])),
                bf256_mul(bf256_mul(*y_tag, conjugates[1]), conjugates_tag[4])),
      bf256_add(bf256_add(bf256_add(bf256_mul(bf256_mul(*y, conjugates[1]), conjugates_tag[4]),
                                    bf256_mul(bf256_mul(*y, conjugates_tag[1]), conjugates[4])),
                          bf256_mul(bf256_mul(*y_tag, conjugates[1]), conjugates[4])),
                conjugates_tag[0]));
}

static void aes_128_inv_norm_constraints_verifier(zk_hash_128_ctx* hasher,
                                                  const bf128_t* conjugates_eval,
                                                  const bf128_t* y_eval, const bf128_t delta) {
  zk_hash_128_update(
      hasher, bf128_add(bf128_mul(bf128_mul(*y_eval, conjugates_eval[1]), conjugates_eval[4]),
                        bf128_mul(conjugates_eval[0], bf128_mul(delta, delta))));
}

static void aes_192_inv_norm_constraints_verifier(zk_hash_192_ctx* hasher,
                                                  const bf192_t* conjugates_eval,
                                                  const bf192_t* y_eval, const bf192_t delta) {
  zk_hash_192_update(
      hasher, bf192_add(bf192_mul(bf192_mul(*y_eval, conjugates_eval[1]), conjugates_eval[4]),
                        bf192_mul(conjugates_eval[0], bf192_mul(delta, delta))));
}

static void aes_256_inv_norm_constraints_verifier(zk_hash_256_ctx* hasher,
                                                  const bf256_t* conjugates_eval,
                                                  const bf256_t* y_eval, const bf256_t delta) {
  zk_hash_256_update(
      hasher, bf256_add(bf256_mul(bf256_mul(*y_eval, conjugates_eval[1]), conjugates_eval[4]),
                        bf256_mul(conjugates_eval[0], bf256_mul(delta, delta))));
}

// STATE TO BYTES
static void aes_128_state_to_bytes_prover(bf128_t* out, bf128_t* out_tag, const uint8_t* k,
                                          const bf128_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out[i]     = bf128_byte_combine_bits(k[i]);
    out_tag[i] = bf128_byte_combine(k_tag + i * 8);
  }
}

static void aes_192_state_to_bytes_prover(bf192_t* out, bf192_t* out_tag, const uint8_t* k,
                                          const bf192_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out[i]     = bf192_byte_combine_bits(k[i]);
    out_tag[i] = bf192_byte_combine(k_tag + i * 8);
  }
}

static void aes_256_state_to_bytes_prover(bf256_t* out, bf256_t* out_tag, const uint8_t* k,
                                          const bf256_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out[i]     = bf256_byte_combine_bits(k[i]);
    out_tag[i] = bf256_byte_combine(k_tag + i * 8);
  }
}

static void aes_128_state_to_bytes_verifier(bf128_t* out_key, const bf128_t* k_key,
                                            const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out_key[i] = bf128_byte_combine(k_key + i * 8);
  }
}

static void aes_192_state_to_bytes_verifier(bf192_t* out_key, const bf192_t* k_key,
                                            const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out_key[i] = bf192_byte_combine(k_key + i * 8);
  }
}

static void aes_256_state_to_bytes_verifier(bf256_t* out_key, const bf256_t* k_key,
                                            const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    out_key[i] = bf256_byte_combine(k_key + i * 8);
  }
}

// SBOX AFFINE

static const bf128_t bf128_c[9] = {
    BF128C(UINT64_C(0xec7759ca3488aee0), UINT64_C(0x4cf4b7439cbfbb84)),
    BF128C(UINT64_C(0xbfcf02ae363946a9), UINT64_C(0x35ad604f7d51d2c6)),
    BF128C(UINT64_C(0x4c3607bab51b5aca), UINT64_C(0xb32fd29a04c0be08)),
    BF128C(UINT64_C(0xc95c10ed4f932c54), UINT64_C(0x186ca7a286376521)),
    BF128C(UINT64_C(0x1f8e5cdeb7aab282), UINT64_C(0xca760596e52ed74a)),
    BF128C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000)),
    BF128C(UINT64_C(0xd8a5ae31928b4da1), UINT64_C(0x1cf7a0fe8922c83f)),
    BF128C(UINT64_C(0x88fd3d5cb6e7dff9), UINT64_C(0x7534634307ce7cbe)),
    BF128C(UINT64_C(0x433f53640b5ab39a), UINT64_C(0x872430dcdf135bcc)),
};
static const bf128_t bf128_c_squares[9] = {
    BF128C(UINT64_C(0x6b8330483c2e9848), UINT64_C(0x0dcb364640a222fe)),
    BF128C(UINT64_C(0xc72bf2ef2521ff23), UINT64_C(0xd681a5686c0c1f75)),
    BF128C(UINT64_C(0x4d48b16661e860ed), UINT64_C(0x49c9321635282198)),
    BF128C(UINT64_C(0xda3bd0e460a50d97), UINT64_C(0xf68b54c3d7c88a6c)),
    BF128C(UINT64_C(0xe1e073c178e70787), UINT64_C(0x9283a13819861c13)),
    BF128C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000)),
    BF128C(UINT64_C(0xa0415e708193f42a), UINT64_C(0xffdb65d9987f058c)),
    BF128C(UINT64_C(0x4fd6cfb393c620db), UINT64_C(0xa3b5c62b6bc263cb)),
    BF128C(UINT64_C(0x1c6e94d79177c893), UINT64_C(0xdaec11278a2c0a89)),
};

static const bf192_t bf192_c[9] = {
    BF192C(UINT64_C(0xb233619e7cf450ba), UINT64_C(0x7bf61f19d5633f26),
           UINT64_C(0xda933726d491db34)),
    BF192C(UINT64_C(0x9c6d2c13f5398a0c), UINT64_C(0x8232e37706328d19),
           UINT64_C(0x0c3b0d703c754ef6)),
    BF192C(UINT64_C(0xfb039539490f3262), UINT64_C(0x638227a707652828),
           UINT64_C(0x7170a38d85840211)),
    BF192C(UINT64_C(0x6ae66d7cf63a7b42), UINT64_C(0x73e093aeb2bd81a2),
           UINT64_C(0x0cee234c9f37ab71)),
    BF192C(UINT64_C(0xd55dd8b4c0c2e8d5), UINT64_C(0x9a46dbc9d4349a17),
           UINT64_C(0xa7d899db6d6097d3)),
    BF192C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000)),
    BF192C(UINT64_C(0x425244c22e17096e), UINT64_C(0x69ac2c678be3ba5f),
           UINT64_C(0x8e7e2484040c7d90)),
    BF192C(UINT64_C(0x1702b39a83f3c8a5), UINT64_C(0x7fb8d6607c39e606),
           UINT64_C(0x20dfa416e9086710)),
    BF192C(UINT64_C(0x831233410b235d20), UINT64_C(0x1d99ac75ae672326),
           UINT64_C(0xced061212ca1ac64)),
};
static const bf192_t bf192_c_squares[9] = {
    BF192C(UINT64_C(0xdd20747cbd2bf75c), UINT64_C(0x7a5542ab0058d22e),
           UINT64_C(0x45ec519c94bc1251)),
    BF192C(UINT64_C(0x970f9c76eed5e1bb), UINT64_C(0xf3eaf7ae5fd72048),
           UINT64_C(0x29a6bd5f696cea43)),
    BF192C(UINT64_C(0x7efbc24b13ccc7d9), UINT64_C(0x9d93c875430d82cc),
           UINT64_C(0xeb98ff32dafaed56)),
    BF192C(UINT64_C(0xbca4a96550fde7a8), UINT64_C(0x786dc5dceb00fedd),
           UINT64_C(0x6c9fc2ff5e921d95)),
    BF192C(UINT64_C(0x34d42a414032d13f), UINT64_C(0x142c7d701c8270aa),
           UINT64_C(0x87d213f1272a1544)),
    BF192C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000)),
    BF192C(UINT64_C(0x4930f4a735fb62d8), UINT64_C(0x187438bed206170e),
           UINT64_C(0xabe394ab5115d925)),
    BF192C(UINT64_C(0x800d2fec6d26291f), UINT64_C(0x8c5221ce23eec64e),
           UINT64_C(0x0979194980648d53)),
    BF192C(UINT64_C(0xae536261e4ebf3a8), UINT64_C(0x7596dda0f0bf7471),
           UINT64_C(0xdfd1231f68801891)),
};

static const bf256_t bf256_c[9] = {
    BF256C(UINT64_C(0xa95af52ad52289c0), UINT64_C(0x2ba5c48d2c42072f), UINT64_C(0xd14a0d376c00b0ea),
           UINT64_C(0x064e4d699c5b4af1)),
    BF256C(UINT64_C(0x55dab3833f809d1c), UINT64_C(0x1771831e533b0f57), UINT64_C(0xfb96573fad3fac10),
           UINT64_C(0x6195e3db7011f68d)),
    BF256C(UINT64_C(0x372f5a920b67efff), UINT64_C(0x8748a24b4ab3a892), UINT64_C(0x214b28089e99af95),
           UINT64_C(0xc6737a464da16302)),
    BF256C(UINT64_C(0x319800033ca8b976), UINT64_C(0x30611f596cb383ad), UINT64_C(0xfef404a31149196b),
           UINT64_C(0x24694604ed0c050d)),
    BF256C(UINT64_C(0xcbaf1c3be1c5fb22), UINT64_C(0xbb9ce5d835caa0ea), UINT64_C(0x0b9772005fa6b36f),
           UINT64_C(0xa1a8d4f4a1ebdf7e)),
    BF256C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000)),
    BF256C(UINT64_C(0x55dab3823f819c28), UINT64_C(0x1771831e533b0f56), UINT64_C(0xfb96573fad3fac11),
           UINT64_C(0x6195e3db7011f68d)),
    BF256C(UINT64_C(0xd0547873524e02b1), UINT64_C(0xd0350e7dfa862912), UINT64_C(0xda9be967cd26e8d5),
           UINT64_C(0x702cec741ee89ff7)),
    BF256C(UINT64_C(0x9020d2d23c10a95b), UINT64_C(0x09ff302a86476559), UINT64_C(0x009db4ee77215795),
           UINT64_C(0xe6d3948d80643e3c)),
};
static const bf256_t bf256_c_squares[9] = {
    BF256C(UINT64_C(0xde010519b01bcdd4), UINT64_C(0x752758911a30e3f6), UINT64_C(0x2a0778b6489ea03f),
           UINT64_C(0x56c24fd64f768838)),
    BF256C(UINT64_C(0x9e75afb9de44670a), UINT64_C(0xaced66c666f1afbc), UINT64_C(0xf001253ff2991f7e),
           UINT64_C(0xc03d372fd1fa29f3)),
    BF256C(UINT64_C(0x3fcd7d68defc7727), UINT64_C(0x957349b58c054948), UINT64_C(0x0e68957294f15180),
           UINT64_C(0x0287e5a6bc9212c2)),
    BF256C(UINT64_C(0x243619206d778eb5), UINT64_C(0xfedaa2104349c0b0), UINT64_C(0xdf640e1506710a3a),
           UINT64_C(0xd303dd260391524b)),
    BF256C(UINT64_C(0x7fb9d7c8b0a3ddf8), UINT64_C(0x4cb977e2f0c40502), UINT64_C(0xd46ec8fb2ef6eec1),
           UINT64_C(0x94789d5f221eb309)),
    BF256C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000)),
    BF256C(UINT64_C(0x9e75afb8de45663f), UINT64_C(0xaced66c666f1afbd), UINT64_C(0xf001253ff2991f7f),
           UINT64_C(0xc03d372fd1fa29f3)),
    BF256C(UINT64_C(0x4e21d7ca8c0a65ba), UINT64_C(0x7cd868bb9c7786ae), UINT64_C(0x2a9acc583fbff7ab),
           UINT64_C(0xb011db5bcf12b604)),
    BF256C(UINT64_C(0xb2a1916366a87167), UINT64_C(0x400c2f28e30e8ed6), UINT64_C(0x00469650fe80eb51),
           UINT64_C(0xd7ca75e923580a78)),
};

static void aes_128_sbox_affine_prover(bf128_t* out_deg0, bf128_t* out_deg1, bf128_t* out_deg2,
                                       const bf128_t* in_deg0, const bf128_t* in_deg1,
                                       const bf128_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf128_t* C = dosq ? bf128_c_squares : bf128_c;
  uint8_t t        = dosq ? 1 : 0;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg2[i] = bf128_add(out_deg2[i], bf128_mul(C[Cidx], in_deg2[i * 8 + (Cidx + t) % 8]));
      out_deg1[i] = bf128_add(out_deg1[i], bf128_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
      out_deg0[i] = bf128_add(out_deg0[i], bf128_mul(C[Cidx], in_deg0[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] to the highest coefficient
    out_deg2[i] = bf128_add(out_deg2[i], C[8]);
  }
}

static void aes_192_sbox_affine_prover(bf192_t* out_deg0, bf192_t* out_deg1, bf192_t* out_deg2,
                                       const bf192_t* in_deg0, const bf192_t* in_deg1,
                                       const bf192_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf192_t* C = dosq ? bf192_c_squares : bf192_c;
  uint8_t t        = dosq ? 1 : 0;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg2[i] = bf192_add(out_deg2[i], bf192_mul(C[Cidx], in_deg2[i * 8 + (Cidx + t) % 8]));
      out_deg1[i] = bf192_add(out_deg1[i], bf192_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
      out_deg0[i] = bf192_add(out_deg0[i], bf192_mul(C[Cidx], in_deg0[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] to the highest coefficient
    out_deg2[i] = bf192_add(out_deg2[i], C[8]);
  }
}

static void aes_256_sbox_affine_prover(bf256_t* out_deg0, bf256_t* out_deg1, bf256_t* out_deg2,
                                       const bf256_t* in_deg0, const bf256_t* in_deg1,
                                       const bf256_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf256_t* C = dosq ? bf256_c_squares : bf256_c;
  uint8_t t        = dosq ? 1 : 0;

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg2[i] = bf256_add(out_deg2[i], bf256_mul(C[Cidx], in_deg2[i * 8 + (Cidx + t) % 8]));
      out_deg1[i] = bf256_add(out_deg1[i], bf256_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
      out_deg0[i] = bf256_add(out_deg0[i], bf256_mul(C[Cidx], in_deg0[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] to the highest coefficient
    out_deg2[i] = bf256_add(out_deg2[i], C[8]);
  }
}

static void aes_128_sbox_affine_verifier(bf128_t* out_deg1, const bf128_t* in_deg1, bf128_t delta,
                                         bool dosq, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf128_t* C            = dosq ? bf128_c_squares : bf128_c;
  uint8_t t                   = dosq ? 1 : 0;
  const bf128_t delta_squared = bf128_mul(delta, delta);

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg1[i] = bf128_add(out_deg1[i], bf128_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] by multiplying with delta^2
    out_deg1[i] = bf128_add(out_deg1[i], bf128_mul(C[8], delta_squared));
  }
}

static void aes_192_sbox_affine_verifier(bf192_t* out_deg1, const bf192_t* in_deg1, bf192_t delta,
                                         bool dosq, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf192_t* C            = dosq ? bf192_c_squares : bf192_c;
  uint8_t t                   = dosq ? 1 : 0;
  const bf192_t delta_squared = bf192_mul(delta, delta);

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg1[i] = bf192_add(out_deg1[i], bf192_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] by multiplying with delta^2
    out_deg1[i] = bf192_add(out_deg1[i], bf192_mul(C[8], delta_squared));
  }
}

static void aes_256_sbox_affine_verifier(bf256_t* out_deg1, const bf256_t* in_deg1, bf256_t delta,
                                         bool dosq, const faest_paramset_t* params) {
  const unsigned int Nst_bytes = params->Nst * 4;

  // ::5-6
  const bf256_t* C            = dosq ? bf256_c_squares : bf256_c;
  uint8_t t                   = dosq ? 1 : 0;
  const bf256_t delta_squared = bf256_mul(delta, delta);

  for (unsigned int i = 0; i < Nst_bytes; i++) {
    for (unsigned int Cidx = 0; Cidx < 8; Cidx++) {
      out_deg1[i] = bf256_add(out_deg1[i], bf256_mul(C[Cidx], in_deg1[i * 8 + (Cidx + t) % 8]));
    }
    // add the constant C[8] by multiplying with delta^2
    out_deg1[i] = bf256_add(out_deg1[i], bf256_mul(C[8], delta_squared));
  }
}

// SHIFT ROWS
static void aes_128_shiftrows_prover(bf128_t* out_deg0, bf128_t* out_deg1, bf128_t* out_deg2,
                                     const bf128_t* in_deg0, const bf128_t* in_deg1,
                                     const bf128_t* in_deg2, const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r) % Nst) + r];
      } else {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r + 1) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r + 1) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r + 1) % Nst) + r];
      }
    }
  }
}

static void aes_192_shiftrows_prover(bf192_t* out_deg0, bf192_t* out_deg1, bf192_t* out_deg2,
                                     const bf192_t* in_deg0, const bf192_t* in_deg1,
                                     const bf192_t* in_deg2, const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r) % Nst) + r];
      } else {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r + 1) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r + 1) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r + 1) % Nst) + r];
      }
    }
  }
}

static void aes_256_shiftrows_prover(bf256_t* out_deg0, bf256_t* out_deg1, bf256_t* out_deg2,
                                     const bf256_t* in_deg0, const bf256_t* in_deg1,
                                     const bf256_t* in_deg2, const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r) % Nst) + r];
      } else {
        out_deg2[4 * c + r] = in_deg2[4 * ((c + r + 1) % Nst) + r];
        out_deg1[4 * c + r] = in_deg1[4 * ((c + r + 1) % Nst) + r];
        out_deg0[4 * c + r] = in_deg0[4 * ((c + r + 1) % Nst) + r];
      }
    }
  }
}

static void aes_128_shiftrows_verifier(bf128_t* out_deg1, const bf128_t* in_deg1,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r) % Nst) + r)];
      } else {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r + 1) % Nst) + r)];
      }
    }
  }
}

static void aes_192_shiftrows_verifier(bf192_t* out_deg1, const bf192_t* in_deg1,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r) % Nst) + r)];
      } else {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r + 1) % Nst) + r)];
      }
    }
  }
}

static void aes_256_shiftrows_verifier(bf256_t* out_deg1, const bf256_t* in_deg1,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      if ((Nst != 8) || (r <= 1)) {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r) % Nst) + r)];
      } else {
        out_deg1[4 * c + r] = in_deg1[(4 * ((c + r + 1) % Nst) + r)];
      }
    }
  }
}

// MIX COLOUMNS

static const bf128_t bf128_bc_2 =
    BF128C(UINT64_C(0xa13fe8ac5560ce0d), UINT64_C(0x053d8555a9979a1c));
static const bf128_t bf128_bc_3 =
    BF128C(UINT64_C(0xa13fe8ac5560ce0c), UINT64_C(0x053d8555a9979a1c));
static const bf128_t bf128_bc_2_sq =
    BF128C(UINT64_C(0xec7759ca3488aee1), UINT64_C(0x4cf4b7439cbfbb84));
static const bf128_t bf128_bc_3_sq =
    BF128C(UINT64_C(0xec7759ca3488aee0), UINT64_C(0x4cf4b7439cbfbb84));

static const bf192_t bf192_bc_2 = BF192C(UINT64_C(0xccc8a3d56f389763), UINT64_C(0xe665d76c966ebdea),
                                         UINT64_C(0x310bc8140e6b3662));
static const bf192_t bf192_bc_3 = BF192C(UINT64_C(0xccc8a3d56f389762), UINT64_C(0xe665d76c966ebdea),
                                         UINT64_C(0x310bc8140e6b3662));
static const bf192_t bf192_bc_2_sq = BF192C(
    UINT64_C(0xb233619e7cf450bb), UINT64_C(0x7bf61f19d5633f26), UINT64_C(0xda933726d491db34));
static const bf192_t bf192_bc_3_sq = BF192C(
    UINT64_C(0xb233619e7cf450ba), UINT64_C(0x7bf61f19d5633f26), UINT64_C(0xda933726d491db34));

static const bf256_t bf256_bc_2 =
    BF256C(UINT64_C(0x969788420bdefee7), UINT64_C(0xbed68d38a0474e67), UINT64_C(0xdf229845f8f1e16a),
           UINT64_C(0x04c9a8cf20c95833));
static const bf256_t bf256_bc_3 =
    BF256C(UINT64_C(0x969788420bdefee6), UINT64_C(0xbed68d38a0474e67), UINT64_C(0xdf229845f8f1e16a),
           UINT64_C(0x04c9a8cf20c95833));
static const bf256_t bf256_bc_2_sq =
    BF256C(UINT64_C(0xa95af52ad52289c1), UINT64_C(0x2ba5c48d2c42072f), UINT64_C(0xd14a0d376c00b0ea),
           UINT64_C(0x064e4d699c5b4af1));
static const bf256_t bf256_bc_3_sq =
    BF256C(UINT64_C(0xa95af52ad52289c0), UINT64_C(0x2ba5c48d2c42072f), UINT64_C(0xd14a0d376c00b0ea),
           UINT64_C(0x064e4d699c5b4af1));

static void aes_128_mix_columns_prover(bf128_t* y_deg0, bf128_t* y_deg1, bf128_t* y_deg2,
                                       const bf128_t* in_deg0, const bf128_t* in_deg1,
                                       const bf128_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf128_t v2 = dosq ? bf128_bc_2_sq : bf128_bc_2;
  const bf128_t v3 = dosq ? bf128_bc_3_sq : bf128_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;
    bf128_t tmp1, tmp2, tmp3, tmp4;

    // ::7
    tmp1       = bf128_mul(in_deg2[i0], v2);
    tmp2       = bf128_mul(in_deg2[i1], v3);
    tmp3       = in_deg2[i2];
    tmp4       = in_deg2[i3];
    y_deg2[i0] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = bf128_mul(in_deg1[i0], v2);
    tmp2       = bf128_mul(in_deg1[i1], v3);
    tmp3       = in_deg1[i2];
    tmp4       = in_deg1[i3];
    y_deg1[i0] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = bf128_mul(in_deg0[i0], v2);
    tmp2       = bf128_mul(in_deg0[i1], v3);
    tmp3       = in_deg0[i2];
    tmp4       = in_deg0[i3];
    y_deg0[i0] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    // ::8
    tmp1       = in_deg2[i0];
    tmp2       = bf128_mul(in_deg2[i1], v2);
    tmp3       = bf128_mul(in_deg2[i2], v3);
    tmp4       = in_deg2[i3];
    y_deg2[i1] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = bf128_mul(in_deg1[i1], v2);
    tmp3       = bf128_mul(in_deg1[i2], v3);
    tmp4       = in_deg1[i3];
    y_deg1[i1] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = bf128_mul(in_deg0[i1], v2);
    tmp3       = bf128_mul(in_deg0[i2], v3);
    tmp4       = in_deg0[i3];
    y_deg0[i1] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    // ::9
    tmp1       = in_deg2[i0];
    tmp2       = in_deg2[i1];
    tmp3       = bf128_mul(in_deg2[i2], v2);
    tmp4       = bf128_mul(in_deg2[i3], v3);
    y_deg2[i2] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = in_deg1[i1];
    tmp3       = bf128_mul(in_deg1[i2], v2);
    tmp4       = bf128_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = in_deg0[i1];
    tmp3       = bf128_mul(in_deg0[i2], v2);
    tmp4       = bf128_mul(in_deg0[i3], v3);
    y_deg0[i2] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    // ::10
    tmp1       = bf128_mul(in_deg2[i0], v3);
    tmp2       = in_deg2[i1];
    tmp3       = in_deg2[i2];
    tmp4       = bf128_mul(in_deg2[i3], v2);
    y_deg2[i3] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = bf128_mul(in_deg1[i0], v3);
    tmp2       = in_deg1[i1];
    tmp3       = in_deg1[i2];
    tmp4       = bf128_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));

    tmp1       = bf128_mul(in_deg0[i0], v3);
    tmp2       = in_deg0[i1];
    tmp3       = in_deg0[i2];
    tmp4       = bf128_mul(in_deg0[i3], v2);
    y_deg0[i3] = bf128_add(bf128_add(tmp1, tmp2), bf128_add(tmp3, tmp4));
  }
}

static void aes_192_mix_columns_prover(bf192_t* y_deg0, bf192_t* y_deg1, bf192_t* y_deg2,
                                       const bf192_t* in_deg0, const bf192_t* in_deg1,
                                       const bf192_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf192_t v2 = dosq ? bf192_bc_2_sq : bf192_bc_2;
  const bf192_t v3 = dosq ? bf192_bc_3_sq : bf192_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;
    bf192_t tmp1, tmp2, tmp3, tmp4;

    // ::7
    tmp1       = bf192_mul(in_deg2[i0], v2);
    tmp2       = bf192_mul(in_deg2[i1], v3);
    tmp3       = in_deg2[i2];
    tmp4       = in_deg2[i3];
    y_deg2[i0] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = bf192_mul(in_deg1[i0], v2);
    tmp2       = bf192_mul(in_deg1[i1], v3);
    tmp3       = in_deg1[i2];
    tmp4       = in_deg1[i3];
    y_deg1[i0] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = bf192_mul(in_deg0[i0], v2);
    tmp2       = bf192_mul(in_deg0[i1], v3);
    tmp3       = in_deg0[i2];
    tmp4       = in_deg0[i3];
    y_deg0[i0] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    // ::8
    tmp1       = in_deg2[i0];
    tmp2       = bf192_mul(in_deg2[i1], v2);
    tmp3       = bf192_mul(in_deg2[i2], v3);
    tmp4       = in_deg2[i3];
    y_deg2[i1] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = bf192_mul(in_deg1[i1], v2);
    tmp3       = bf192_mul(in_deg1[i2], v3);
    tmp4       = in_deg1[i3];
    y_deg1[i1] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = bf192_mul(in_deg0[i1], v2);
    tmp3       = bf192_mul(in_deg0[i2], v3);
    tmp4       = in_deg0[i3];
    y_deg0[i1] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    // ::9
    tmp1       = in_deg2[i0];
    tmp2       = in_deg2[i1];
    tmp3       = bf192_mul(in_deg2[i2], v2);
    tmp4       = bf192_mul(in_deg2[i3], v3);
    y_deg2[i2] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = in_deg1[i1];
    tmp3       = bf192_mul(in_deg1[i2], v2);
    tmp4       = bf192_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = in_deg0[i1];
    tmp3       = bf192_mul(in_deg0[i2], v2);
    tmp4       = bf192_mul(in_deg0[i3], v3);
    y_deg0[i2] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    // ::10
    tmp1       = bf192_mul(in_deg2[i0], v3);
    tmp2       = in_deg2[i1];
    tmp3       = in_deg2[i2];
    tmp4       = bf192_mul(in_deg2[i3], v2);
    y_deg2[i3] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = bf192_mul(in_deg1[i0], v3);
    tmp2       = in_deg1[i1];
    tmp3       = in_deg1[i2];
    tmp4       = bf192_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));

    tmp1       = bf192_mul(in_deg0[i0], v3);
    tmp2       = in_deg0[i1];
    tmp3       = in_deg0[i2];
    tmp4       = bf192_mul(in_deg0[i3], v2);
    y_deg0[i3] = bf192_add(bf192_add(tmp1, tmp2), bf192_add(tmp3, tmp4));
  }
}

static void aes_256_mix_columns_prover(bf256_t* y_deg0, bf256_t* y_deg1, bf256_t* y_deg2,
                                       const bf256_t* in_deg0, const bf256_t* in_deg1,
                                       const bf256_t* in_deg2, bool dosq,
                                       const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf256_t v2 = dosq ? bf256_bc_2_sq : bf256_bc_2;
  const bf256_t v3 = dosq ? bf256_bc_3_sq : bf256_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;
    bf256_t tmp1, tmp2, tmp3, tmp4;

    // ::7
    tmp1       = bf256_mul(in_deg2[i0], v2);
    tmp2       = bf256_mul(in_deg2[i1], v3);
    tmp3       = in_deg2[i2];
    tmp4       = in_deg2[i3];
    y_deg2[i0] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = bf256_mul(in_deg1[i0], v2);
    tmp2       = bf256_mul(in_deg1[i1], v3);
    tmp3       = in_deg1[i2];
    tmp4       = in_deg1[i3];
    y_deg1[i0] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = bf256_mul(in_deg0[i0], v2);
    tmp2       = bf256_mul(in_deg0[i1], v3);
    tmp3       = in_deg0[i2];
    tmp4       = in_deg0[i3];
    y_deg0[i0] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    // ::8
    tmp1       = in_deg2[i0];
    tmp2       = bf256_mul(in_deg2[i1], v2);
    tmp3       = bf256_mul(in_deg2[i2], v3);
    tmp4       = in_deg2[i3];
    y_deg2[i1] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = bf256_mul(in_deg1[i1], v2);
    tmp3       = bf256_mul(in_deg1[i2], v3);
    tmp4       = in_deg1[i3];
    y_deg1[i1] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = bf256_mul(in_deg0[i1], v2);
    tmp3       = bf256_mul(in_deg0[i2], v3);
    tmp4       = in_deg0[i3];
    y_deg0[i1] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    // ::9
    tmp1       = in_deg2[i0];
    tmp2       = in_deg2[i1];
    tmp3       = bf256_mul(in_deg2[i2], v2);
    tmp4       = bf256_mul(in_deg2[i3], v3);
    y_deg2[i2] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = in_deg1[i0];
    tmp2       = in_deg1[i1];
    tmp3       = bf256_mul(in_deg1[i2], v2);
    tmp4       = bf256_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = in_deg0[i0];
    tmp2       = in_deg0[i1];
    tmp3       = bf256_mul(in_deg0[i2], v2);
    tmp4       = bf256_mul(in_deg0[i3], v3);
    y_deg0[i2] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    // ::10
    tmp1       = bf256_mul(in_deg2[i0], v3);
    tmp2       = in_deg2[i1];
    tmp3       = in_deg2[i2];
    tmp4       = bf256_mul(in_deg2[i3], v2);
    y_deg2[i3] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = bf256_mul(in_deg1[i0], v3);
    tmp2       = in_deg1[i1];
    tmp3       = in_deg1[i2];
    tmp4       = bf256_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));

    tmp1       = bf256_mul(in_deg0[i0], v3);
    tmp2       = in_deg0[i1];
    tmp3       = in_deg0[i2];
    tmp4       = bf256_mul(in_deg0[i3], v2);
    y_deg0[i3] = bf256_add(bf256_add(tmp1, tmp2), bf256_add(tmp3, tmp4));
  }
}

static void aes_128_mix_columns_verifier(bf128_t* y_deg1, const bf128_t* in_deg1, bool dosq,
                                         const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf128_t v2 = dosq ? bf128_bc_2_sq : bf128_bc_2;
  const bf128_t v3 = dosq ? bf128_bc_3_sq : bf128_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;

    bf128_t tmp1_tag = bf128_mul(in_deg1[i0], v2);
    bf128_t tmp2_tag = bf128_mul(in_deg1[i1], v3);
    bf128_t tmp3_tag = in_deg1[i2];
    bf128_t tmp4_tag = in_deg1[i3];
    y_deg1[i0]       = bf128_add(bf128_add(tmp1_tag, tmp2_tag), bf128_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = bf128_mul(in_deg1[i1], v2);
    tmp3_tag   = bf128_mul(in_deg1[i2], v3);
    tmp4_tag   = in_deg1[i3];
    y_deg1[i1] = bf128_add(bf128_add(tmp1_tag, tmp2_tag), bf128_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = bf128_mul(in_deg1[i2], v2);
    tmp4_tag   = bf128_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf128_add(bf128_add(tmp1_tag, tmp2_tag), bf128_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = bf128_mul(in_deg1[i0], v3);
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = in_deg1[i2];
    tmp4_tag   = bf128_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf128_add(bf128_add(tmp1_tag, tmp2_tag), bf128_add(tmp3_tag, tmp4_tag));
  }
}

static void aes_192_mix_columns_verifier(bf192_t* y_deg1, const bf192_t* in_deg1, bool dosq,
                                         const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf192_t v2 = dosq ? bf192_bc_2_sq : bf192_bc_2;
  const bf192_t v3 = dosq ? bf192_bc_3_sq : bf192_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;

    bf192_t tmp1_tag = bf192_mul(in_deg1[i0], v2);
    bf192_t tmp2_tag = bf192_mul(in_deg1[i1], v3);
    bf192_t tmp3_tag = in_deg1[i2];
    bf192_t tmp4_tag = in_deg1[i3];
    y_deg1[i0]       = bf192_add(bf192_add(tmp1_tag, tmp2_tag), bf192_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = bf192_mul(in_deg1[i1], v2);
    tmp3_tag   = bf192_mul(in_deg1[i2], v3);
    tmp4_tag   = in_deg1[i3];
    y_deg1[i1] = bf192_add(bf192_add(tmp1_tag, tmp2_tag), bf192_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = bf192_mul(in_deg1[i2], v2);
    tmp4_tag   = bf192_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf192_add(bf192_add(tmp1_tag, tmp2_tag), bf192_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = bf192_mul(in_deg1[i0], v3);
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = in_deg1[i2];
    tmp4_tag   = bf192_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf192_add(bf192_add(tmp1_tag, tmp2_tag), bf192_add(tmp3_tag, tmp4_tag));
  }
}

static void aes_256_mix_columns_verifier(bf256_t* y_deg1, const bf256_t* in_deg1, bool dosq,
                                         const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  //  ::2-4
  const bf256_t v2 = dosq ? bf256_bc_2_sq : bf256_bc_2;
  const bf256_t v3 = dosq ? bf256_bc_3_sq : bf256_bc_3;

  for (unsigned int c = 0; c < Nst; c++) {
    unsigned int i0 = 4 * c;
    unsigned int i1 = 4 * c + 1;
    unsigned int i2 = 4 * c + 2;
    unsigned int i3 = 4 * c + 3;

    bf256_t tmp1_tag = bf256_mul(in_deg1[i0], v2);
    bf256_t tmp2_tag = bf256_mul(in_deg1[i1], v3);
    bf256_t tmp3_tag = in_deg1[i2];
    bf256_t tmp4_tag = in_deg1[i3];
    y_deg1[i0]       = bf256_add(bf256_add(tmp1_tag, tmp2_tag), bf256_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = bf256_mul(in_deg1[i1], v2);
    tmp3_tag   = bf256_mul(in_deg1[i2], v3);
    tmp4_tag   = in_deg1[i3];
    y_deg1[i1] = bf256_add(bf256_add(tmp1_tag, tmp2_tag), bf256_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = in_deg1[i0];
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = bf256_mul(in_deg1[i2], v2);
    tmp4_tag   = bf256_mul(in_deg1[i3], v3);
    y_deg1[i2] = bf256_add(bf256_add(tmp1_tag, tmp2_tag), bf256_add(tmp3_tag, tmp4_tag));

    tmp1_tag   = bf256_mul(in_deg1[i0], v3);
    tmp2_tag   = in_deg1[i1];
    tmp3_tag   = in_deg1[i2];
    tmp4_tag   = bf256_mul(in_deg1[i3], v2);
    y_deg1[i3] = bf256_add(bf256_add(tmp1_tag, tmp2_tag), bf256_add(tmp3_tag, tmp4_tag));
  }
}

// ADD ROUND KEY BYTES
// on degree-2 state and degree-2 key
static void
aes_128_add_round_key_bytes_prover_degree_2(bf128_t* y_deg0, bf128_t* y_deg1, bf128_t* y_deg2,
                                            const bf128_t* in_deg0, const bf128_t* in_deg1,
                                            const bf128_t* in_deg2, const bf128_t* k_deg0,
                                            const bf128_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg0[i] = bf128_add(in_deg0[i], k_deg0[i]);
    y_deg1[i] = in_deg1[i]; // k_deg1[i] is 0
    y_deg2[i] = bf128_add(in_deg2[i], k_deg2[i]);
  }
}

static void
aes_192_add_round_key_bytes_prover_degree_2(bf192_t* y_deg0, bf192_t* y_deg1, bf192_t* y_deg2,
                                            const bf192_t* in_deg0, const bf192_t* in_deg1,
                                            const bf192_t* in_deg2, const bf192_t* k_deg0,
                                            const bf192_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg0[i] = bf192_add(in_deg0[i], k_deg0[i]);
    y_deg1[i] = in_deg1[i]; // k_deg1[i] is 0
    y_deg2[i] = bf192_add(in_deg2[i], k_deg2[i]);
  }
}

static void
aes_256_add_round_key_bytes_prover_degree_2(bf256_t* y_deg0, bf256_t* y_deg1, bf256_t* y_deg2,
                                            const bf256_t* in_deg0, const bf256_t* in_deg1,
                                            const bf256_t* in_deg2, const bf256_t* k_deg0,
                                            const bf256_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg0[i] = bf256_add(in_deg0[i], k_deg0[i]);
    y_deg1[i] = in_deg1[i]; // k_deg1[i] is 0
    y_deg2[i] = bf256_add(in_deg2[i], k_deg2[i]);
  }
}

static void
aes_128_add_round_key_bytes_prover_degree_1(bf128_t* y_deg0, bf128_t* y_deg1, bf128_t* y_deg2,
                                            const bf128_t* in_deg0, const bf128_t* in_deg1,
                                            const bf128_t* in_deg2, const bf128_t* k_deg1,
                                            const bf128_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg2[i] = bf128_add(in_deg2[i], k_deg2[i]);
    y_deg1[i] = bf128_add(in_deg1[i], k_deg1[i]);
    y_deg0[i] = in_deg0[i];
  }
}

static void
aes_192_add_round_key_bytes_prover_degree_1(bf192_t* y_deg0, bf192_t* y_deg1, bf192_t* y_deg2,
                                            const bf192_t* in_deg0, const bf192_t* in_deg1,
                                            const bf192_t* in_deg2, const bf192_t* k_deg1,
                                            const bf192_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg2[i] = bf192_add(in_deg2[i], k_deg2[i]);
    y_deg1[i] = bf192_add(in_deg1[i], k_deg1[i]);
    y_deg0[i] = in_deg0[i];
  }
}

static void
aes_256_add_round_key_bytes_prover_degree_1(bf256_t* y_deg0, bf256_t* y_deg1, bf256_t* y_deg2,
                                            const bf256_t* in_deg0, const bf256_t* in_deg1,
                                            const bf256_t* in_deg2, const bf256_t* k_deg1,
                                            const bf256_t* k_deg2, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    y_deg2[i] = bf256_add(in_deg2[i], k_deg2[i]);
    y_deg1[i] = bf256_add(in_deg1[i], k_deg1[i]);
    y_deg0[i] = in_deg0[i];
  }
}

// Use shift_tag if key is degree-1 instead of degree-2
static void aes_128_add_round_key_bytes_verifier(bf128_t* y_deg1, const bf128_t* in_tag,
                                                 const bf128_t* k_tag, bf128_t delta,
                                                 bool shift_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    if (shift_tag) {
      // Multiply tag by delta to align degrees
      y_deg1[i] = bf128_add(in_tag[i], bf128_mul(k_tag[i], delta));
    } else {
      y_deg1[i] = bf128_add(in_tag[i], k_tag[i]);
    }
  }
}

static void aes_192_add_round_key_bytes_verifier(bf192_t* y_deg1, const bf192_t* in_tag,
                                                 const bf192_t* k_tag, bf192_t delta,
                                                 bool shift_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    if (shift_tag) {
      // Multiply tag by delta to align degrees
      y_deg1[i] = bf192_add(in_tag[i], bf192_mul(k_tag[i], delta));
    } else {
      y_deg1[i] = bf192_add(in_tag[i], k_tag[i]);
    }
  }
}

static void aes_256_add_round_key_bytes_verifier(bf256_t* y_deg1, const bf256_t* in_tag,
                                                 const bf256_t* k_tag, bf256_t delta,
                                                 bool shift_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    if (shift_tag) {
      // Multiply tag by delta to align degrees
      y_deg1[i] = bf256_add(in_tag[i], bf256_mul(k_tag[i], delta));
    } else {
      y_deg1[i] = bf256_add(in_tag[i], k_tag[i]);
    }
  }
}

// INVERSE SHIFT ROWS
static void aes_128_inverse_shiftrows_prover(uint8_t* out, bf128_t* out_tag, const uint8_t* in,
                                             const bf128_t* in_tag,
                                             const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      out[4 * c + r] = in[i];
      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf128_t));
    }
  }
}

static void aes_192_inverse_shiftrows_prover(uint8_t* out, bf192_t* out_tag, const uint8_t* in,
                                             const bf192_t* in_tag,
                                             const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      out[4 * c + r] = in[i];
      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf192_t));
    }
  }
}

static void aes_256_inverse_shiftrows_prover(uint8_t* out, bf256_t* out_tag, const uint8_t* in,
                                             const bf256_t* in_tag,
                                             const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      out[4 * c + r] = in[i];
      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf256_t));
    }
  }
}

static void aes_128_inverse_shiftrows_verifier(bf128_t* out_tag, const bf128_t* in_tag,
                                               const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf128_t));
    }
  }
}

static void aes_192_inverse_shiftrows_verifier(bf192_t* out_tag, const bf192_t* in_tag,
                                               const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf192_t));
    }
  }
}

static void aes_256_inverse_shiftrows_verifier(bf256_t* out_tag, const bf256_t* in_tag,
                                               const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int r = 0; r < 4; r++) {
    for (unsigned int c = 0; c < Nst; c++) {
      unsigned int i;
      if ((Nst != 8) || (r <= 1)) {
        i = 4 * ((c + Nst - r) % Nst) + r;
      } else {
        i = 4 * ((c + Nst - r - 1) % Nst) + r;
      }

      memcpy(out_tag + 8 * (4 * c + r), in_tag + 8 * i, 8 * sizeof(bf256_t));
    }
  }
}

// BITWISE MIX COLUMNS
static void aes_128_bitwise_mix_column_prover(uint8_t* out, bf128_t* out_tag, const uint8_t* s,
                                              const bf128_t* s_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const uint8_t* a_bits     = &s[32 * c / 8];
    const bf128_t* a_bits_tag = &s_tag[32 * c];

    uint8_t b_bits[4];
    bf128_t b_bits_tag[4 * 8];

    // ::1
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits[r] = set_bit(get_bit(a_bits[r], 7), 0) ^
                  set_bit(get_bit(a_bits[r], 0) ^ get_bit(a_bits[r], 7), 1) ^
                  set_bit(get_bit(a_bits[r], 1), 2) ^
                  set_bit(get_bit(a_bits[r], 2) ^ get_bit(a_bits[r], 7), 3) ^
                  set_bit(get_bit(a_bits[r], 3) ^ get_bit(a_bits[r], 7), 4) ^
                  set_bit(get_bit(a_bits[r], 4), 5) ^ set_bit(get_bit(a_bits[r], 5), 6) ^
                  set_bit(get_bit(a_bits[r], 6), 7);

      b_bits_tag[r * 8 + 0] = a_bits_tag[r * 8 + 7];
      b_bits_tag[r * 8 + 1] = bf128_add(a_bits_tag[r * 8 + 0], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 2] = a_bits_tag[r * 8 + 1];
      b_bits_tag[r * 8 + 3] = bf128_add(a_bits_tag[r * 8 + 2], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 4] = bf128_add(a_bits_tag[r * 8 + 3], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 5] = a_bits_tag[r * 8 + 4];
      b_bits_tag[r * 8 + 6] = a_bits_tag[r * 8 + 5];
      b_bits_tag[r * 8 + 7] = a_bits_tag[r * 8 + 6];
    }

    out[c * 4]     = b_bits[0] ^ a_bits[3] ^ a_bits[2] ^ b_bits[1] ^ a_bits[1];
    out[c * 4 + 1] = b_bits[1] ^ a_bits[0] ^ a_bits[3] ^ b_bits[2] ^ a_bits[2];
    out[c * 4 + 2] = b_bits[2] ^ a_bits[1] ^ a_bits[0] ^ b_bits[3] ^ a_bits[3];
    out[c * 4 + 3] = b_bits[3] ^ a_bits[2] ^ a_bits[1] ^ b_bits[0] ^ a_bits[0];

    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_tag[8 * (c * 4) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_tag[0 * 8 + i_bit], a_bits_tag[3 * 8 + i_bit]),
                              bf128_add(a_bits_tag[2 * 8 + i_bit], b_bits_tag[1 * 8 + i_bit])),
                    a_bits_tag[1 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 1) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_tag[1 * 8 + i_bit], a_bits_tag[0 * 8 + i_bit]),
                              bf128_add(a_bits_tag[3 * 8 + i_bit], b_bits_tag[2 * 8 + i_bit])),
                    a_bits_tag[2 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 2) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_tag[2 * 8 + i_bit], a_bits_tag[1 * 8 + i_bit]),
                              bf128_add(a_bits_tag[0 * 8 + i_bit], b_bits_tag[3 * 8 + i_bit])),
                    a_bits_tag[3 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 3) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_tag[3 * 8 + i_bit], a_bits_tag[2 * 8 + i_bit]),
                              bf128_add(a_bits_tag[1 * 8 + i_bit], b_bits_tag[0 * 8 + i_bit])),
                    a_bits_tag[0 * 8 + i_bit]);
    }
  }
}

static void aes_192_bitwise_mix_column_prover(uint8_t* out, bf192_t* out_tag, const uint8_t* s,
                                              const bf192_t* s_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const uint8_t* a_bits     = &s[32 * c / 8];
    const bf192_t* a_bits_tag = &s_tag[32 * c];

    uint8_t b_bits[4];
    bf192_t b_bits_tag[4 * 8];

    // ::1
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits[r] = set_bit(get_bit(a_bits[r], 7), 0) ^
                  set_bit(get_bit(a_bits[r], 0) ^ get_bit(a_bits[r], 7), 1) ^
                  set_bit(get_bit(a_bits[r], 1), 2) ^
                  set_bit(get_bit(a_bits[r], 2) ^ get_bit(a_bits[r], 7), 3) ^
                  set_bit(get_bit(a_bits[r], 3) ^ get_bit(a_bits[r], 7), 4) ^
                  set_bit(get_bit(a_bits[r], 4), 5) ^ set_bit(get_bit(a_bits[r], 5), 6) ^
                  set_bit(get_bit(a_bits[r], 6), 7);

      b_bits_tag[r * 8 + 0] = a_bits_tag[r * 8 + 7];
      b_bits_tag[r * 8 + 1] = bf192_add(a_bits_tag[r * 8 + 0], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 2] = a_bits_tag[r * 8 + 1];
      b_bits_tag[r * 8 + 3] = bf192_add(a_bits_tag[r * 8 + 2], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 4] = bf192_add(a_bits_tag[r * 8 + 3], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 5] = a_bits_tag[r * 8 + 4];
      b_bits_tag[r * 8 + 6] = a_bits_tag[r * 8 + 5];
      b_bits_tag[r * 8 + 7] = a_bits_tag[r * 8 + 6];
    }

    out[c * 4]     = b_bits[0] ^ a_bits[3] ^ a_bits[2] ^ b_bits[1] ^ a_bits[1];
    out[c * 4 + 1] = b_bits[1] ^ a_bits[0] ^ a_bits[3] ^ b_bits[2] ^ a_bits[2];
    out[c * 4 + 2] = b_bits[2] ^ a_bits[1] ^ a_bits[0] ^ b_bits[3] ^ a_bits[3];
    out[c * 4 + 3] = b_bits[3] ^ a_bits[2] ^ a_bits[1] ^ b_bits[0] ^ a_bits[0];

    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_tag[8 * (c * 4) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_tag[0 * 8 + i_bit], a_bits_tag[3 * 8 + i_bit]),
                              bf192_add(a_bits_tag[2 * 8 + i_bit], b_bits_tag[1 * 8 + i_bit])),
                    a_bits_tag[1 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 1) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_tag[1 * 8 + i_bit], a_bits_tag[0 * 8 + i_bit]),
                              bf192_add(a_bits_tag[3 * 8 + i_bit], b_bits_tag[2 * 8 + i_bit])),
                    a_bits_tag[2 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 2) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_tag[2 * 8 + i_bit], a_bits_tag[1 * 8 + i_bit]),
                              bf192_add(a_bits_tag[0 * 8 + i_bit], b_bits_tag[3 * 8 + i_bit])),
                    a_bits_tag[3 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 3) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_tag[3 * 8 + i_bit], a_bits_tag[2 * 8 + i_bit]),
                              bf192_add(a_bits_tag[1 * 8 + i_bit], b_bits_tag[0 * 8 + i_bit])),
                    a_bits_tag[0 * 8 + i_bit]);
    }
  }
}

static void aes_256_bitwise_mix_column_prover(uint8_t* out, bf256_t* out_tag, const uint8_t* s,
                                              const bf256_t* s_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const uint8_t* a_bits     = &s[32 * c / 8];
    const bf256_t* a_bits_tag = &s_tag[32 * c];

    uint8_t b_bits[4];
    bf256_t b_bits_tag[4 * 8];

    // ::1
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits[r] = set_bit(get_bit(a_bits[r], 7), 0) ^
                  set_bit(get_bit(a_bits[r], 0) ^ get_bit(a_bits[r], 7), 1) ^
                  set_bit(get_bit(a_bits[r], 1), 2) ^
                  set_bit(get_bit(a_bits[r], 2) ^ get_bit(a_bits[r], 7), 3) ^
                  set_bit(get_bit(a_bits[r], 3) ^ get_bit(a_bits[r], 7), 4) ^
                  set_bit(get_bit(a_bits[r], 4), 5) ^ set_bit(get_bit(a_bits[r], 5), 6) ^
                  set_bit(get_bit(a_bits[r], 6), 7);

      b_bits_tag[r * 8 + 0] = a_bits_tag[r * 8 + 7];
      b_bits_tag[r * 8 + 1] = bf256_add(a_bits_tag[r * 8 + 0], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 2] = a_bits_tag[r * 8 + 1];
      b_bits_tag[r * 8 + 3] = bf256_add(a_bits_tag[r * 8 + 2], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 4] = bf256_add(a_bits_tag[r * 8 + 3], a_bits_tag[r * 8 + 7]);
      b_bits_tag[r * 8 + 5] = a_bits_tag[r * 8 + 4];
      b_bits_tag[r * 8 + 6] = a_bits_tag[r * 8 + 5];
      b_bits_tag[r * 8 + 7] = a_bits_tag[r * 8 + 6];
    }

    out[c * 4]     = b_bits[0] ^ a_bits[3] ^ a_bits[2] ^ b_bits[1] ^ a_bits[1];
    out[c * 4 + 1] = b_bits[1] ^ a_bits[0] ^ a_bits[3] ^ b_bits[2] ^ a_bits[2];
    out[c * 4 + 2] = b_bits[2] ^ a_bits[1] ^ a_bits[0] ^ b_bits[3] ^ a_bits[3];
    out[c * 4 + 3] = b_bits[3] ^ a_bits[2] ^ a_bits[1] ^ b_bits[0] ^ a_bits[0];

    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_tag[8 * (c * 4) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_tag[0 * 8 + i_bit], a_bits_tag[3 * 8 + i_bit]),
                              bf256_add(a_bits_tag[2 * 8 + i_bit], b_bits_tag[1 * 8 + i_bit])),
                    a_bits_tag[1 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 1) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_tag[1 * 8 + i_bit], a_bits_tag[0 * 8 + i_bit]),
                              bf256_add(a_bits_tag[3 * 8 + i_bit], b_bits_tag[2 * 8 + i_bit])),
                    a_bits_tag[2 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 2) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_tag[2 * 8 + i_bit], a_bits_tag[1 * 8 + i_bit]),
                              bf256_add(a_bits_tag[0 * 8 + i_bit], b_bits_tag[3 * 8 + i_bit])),
                    a_bits_tag[3 * 8 + i_bit]);
      out_tag[8 * (c * 4 + 3) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_tag[3 * 8 + i_bit], a_bits_tag[2 * 8 + i_bit]),
                              bf256_add(a_bits_tag[1 * 8 + i_bit], b_bits_tag[0 * 8 + i_bit])),
                    a_bits_tag[0 * 8 + i_bit]);
    }
  }
}

static void aes_128_bitwise_mix_column_verifier(bf128_t* out_key, bf128_t* s_keys_tag,
                                                const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const bf128_t* a_bits_key = &s_keys_tag[32 * c];

    // ::1
    bf128_t b_bits_key[4 * 8];
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits_key[r * 8 + 0] = a_bits_key[r * 8 + 7];
      b_bits_key[r * 8 + 1] = bf128_add(a_bits_key[r * 8 + 0], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 2] = a_bits_key[r * 8 + 1];
      b_bits_key[r * 8 + 3] = bf128_add(a_bits_key[r * 8 + 2], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 4] = bf128_add(a_bits_key[r * 8 + 3], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 5] = a_bits_key[r * 8 + 4];
      b_bits_key[r * 8 + 6] = a_bits_key[r * 8 + 5];
      b_bits_key[r * 8 + 7] = a_bits_key[r * 8 + 6];
    }

    // ::6-9
    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_key[8 * (c * 4) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_key[0 * 8 + i_bit], a_bits_key[3 * 8 + i_bit]),
                              bf128_add(a_bits_key[2 * 8 + i_bit], b_bits_key[1 * 8 + i_bit])),
                    a_bits_key[1 * 8 + i_bit]);
      out_key[8 * (c * 4 + 1) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_key[1 * 8 + i_bit], a_bits_key[0 * 8 + i_bit]),
                              bf128_add(a_bits_key[3 * 8 + i_bit], b_bits_key[2 * 8 + i_bit])),
                    a_bits_key[2 * 8 + i_bit]);
      out_key[8 * (c * 4 + 2) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_key[2 * 8 + i_bit], a_bits_key[1 * 8 + i_bit]),
                              bf128_add(a_bits_key[0 * 8 + i_bit], b_bits_key[3 * 8 + i_bit])),
                    a_bits_key[3 * 8 + i_bit]);
      out_key[8 * (c * 4 + 3) + i_bit] =
          bf128_add(bf128_add(bf128_add(b_bits_key[3 * 8 + i_bit], a_bits_key[2 * 8 + i_bit]),
                              bf128_add(a_bits_key[1 * 8 + i_bit], b_bits_key[0 * 8 + i_bit])),
                    a_bits_key[0 * 8 + i_bit]);
    }
  }
}

static void aes_192_bitwise_mix_column_verifier(bf192_t* out_key, bf192_t* s_keys_tag,
                                                const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const bf192_t* a_bits_key = &s_keys_tag[32 * c];

    // ::1
    bf192_t b_bits_key[4 * 8];
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits_key[r * 8 + 0] = a_bits_key[r * 8 + 7];
      b_bits_key[r * 8 + 1] = bf192_add(a_bits_key[r * 8 + 0], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 2] = a_bits_key[r * 8 + 1];
      b_bits_key[r * 8 + 3] = bf192_add(a_bits_key[r * 8 + 2], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 4] = bf192_add(a_bits_key[r * 8 + 3], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 5] = a_bits_key[r * 8 + 4];
      b_bits_key[r * 8 + 6] = a_bits_key[r * 8 + 5];
      b_bits_key[r * 8 + 7] = a_bits_key[r * 8 + 6];
    }

    // ::6-9
    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_key[8 * (c * 4) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_key[0 * 8 + i_bit], a_bits_key[3 * 8 + i_bit]),
                              bf192_add(a_bits_key[2 * 8 + i_bit], b_bits_key[1 * 8 + i_bit])),
                    a_bits_key[1 * 8 + i_bit]);
      out_key[8 * (c * 4 + 1) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_key[1 * 8 + i_bit], a_bits_key[0 * 8 + i_bit]),
                              bf192_add(a_bits_key[3 * 8 + i_bit], b_bits_key[2 * 8 + i_bit])),
                    a_bits_key[2 * 8 + i_bit]);
      out_key[8 * (c * 4 + 2) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_key[2 * 8 + i_bit], a_bits_key[1 * 8 + i_bit]),
                              bf192_add(a_bits_key[0 * 8 + i_bit], b_bits_key[3 * 8 + i_bit])),
                    a_bits_key[3 * 8 + i_bit]);
      out_key[8 * (c * 4 + 3) + i_bit] =
          bf192_add(bf192_add(bf192_add(b_bits_key[3 * 8 + i_bit], a_bits_key[2 * 8 + i_bit]),
                              bf192_add(a_bits_key[1 * 8 + i_bit], b_bits_key[0 * 8 + i_bit])),
                    a_bits_key[0 * 8 + i_bit]);
    }
  }
}

static void aes_256_bitwise_mix_column_verifier(bf256_t* out_key, bf256_t* s_keys_tag,
                                                const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;

  for (unsigned int c = 0; c < Nst; c++) {
    // ::2-3
    const bf256_t* a_bits_key = &s_keys_tag[32 * c];

    // ::1
    bf256_t b_bits_key[4 * 8];
    for (unsigned int r = 0; r < 4; r++) {
      // :5
      b_bits_key[r * 8 + 0] = a_bits_key[r * 8 + 7];
      b_bits_key[r * 8 + 1] = bf256_add(a_bits_key[r * 8 + 0], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 2] = a_bits_key[r * 8 + 1];
      b_bits_key[r * 8 + 3] = bf256_add(a_bits_key[r * 8 + 2], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 4] = bf256_add(a_bits_key[r * 8 + 3], a_bits_key[r * 8 + 7]);
      b_bits_key[r * 8 + 5] = a_bits_key[r * 8 + 4];
      b_bits_key[r * 8 + 6] = a_bits_key[r * 8 + 5];
      b_bits_key[r * 8 + 7] = a_bits_key[r * 8 + 6];
    }

    // ::6-9
    for (unsigned int i_bit = 0; i_bit < 8; ++i_bit) {
      out_key[8 * (c * 4) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_key[0 * 8 + i_bit], a_bits_key[3 * 8 + i_bit]),
                              bf256_add(a_bits_key[2 * 8 + i_bit], b_bits_key[1 * 8 + i_bit])),
                    a_bits_key[1 * 8 + i_bit]);
      out_key[8 * (c * 4 + 1) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_key[1 * 8 + i_bit], a_bits_key[0 * 8 + i_bit]),
                              bf256_add(a_bits_key[3 * 8 + i_bit], b_bits_key[2 * 8 + i_bit])),
                    a_bits_key[2 * 8 + i_bit]);
      out_key[8 * (c * 4 + 2) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_key[2 * 8 + i_bit], a_bits_key[1 * 8 + i_bit]),
                              bf256_add(a_bits_key[0 * 8 + i_bit], b_bits_key[3 * 8 + i_bit])),
                    a_bits_key[3 * 8 + i_bit]);
      out_key[8 * (c * 4 + 3) + i_bit] =
          bf256_add(bf256_add(bf256_add(b_bits_key[3 * 8 + i_bit], a_bits_key[2 * 8 + i_bit]),
                              bf256_add(a_bits_key[1 * 8 + i_bit], b_bits_key[0 * 8 + i_bit])),
                    a_bits_key[0 * 8 + i_bit]);
    }
  }
}

// CONSTANT TO VOLE
static void constant_to_vole_128_prover(bf128_t* tag, unsigned int n) {
  // the val stay the same as the val is a pub const!
  for (unsigned int i = 0; i < n; i++) {
    tag[i] = bf128_zero(); // for constant values the tag is zero
  }
}

static void constant_to_vole_192_prover(bf192_t* tag, unsigned int n) {
  // the val stay the same as the val is a pub const!
  for (unsigned int i = 0; i < n; i++) {
    tag[i] = bf192_zero(); // for constant values the tag is zero
  }
}

static void constant_to_vole_256_prover(bf256_t* tag, unsigned int n) {
  // the val stay the same as the val is a pub const!
  for (unsigned int i = 0; i < n; i++) {
    tag[i] = bf256_zero(); // for constant values the tag is zero
  }
}

static void constant_to_vole_128_verifier(bf128_t* key, const uint8_t* val, bf128_t delta,
                                          unsigned int n) {
  for (unsigned int i = 0; i < n; i++) {
    key[i] = bf128_mul_bit(delta, ptr_get_bit(val, i));
  }
}

static void constant_to_vole_192_verifier(bf192_t* key, const uint8_t* val, bf192_t delta,
                                          unsigned int n) {
  for (unsigned int i = 0; i < n; i++) {
    key[i] = bf192_mul_bit(delta, ptr_get_bit(val, i));
  }
}

static void constant_to_vole_256_verifier(bf256_t* key, const uint8_t* val, bf256_t delta,
                                          unsigned int n) {
  for (unsigned int i = 0; i < n; i++) {
    key[i] = bf256_mul_bit(delta, ptr_get_bit(val, i));
  }
}

// // INVERSE AFFINE
static void aes_128_inverse_affine_byte_prover(uint8_t* y_bits, bf128_t* y_bits_tag,
                                               const uint8_t x_bits, const bf128_t* x_bits_tag) {
  *y_bits = rotr8(x_bits, 7) ^ rotr8(x_bits, 5) ^ rotr8(x_bits, 2) ^ 0x5;

  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_tag[bit_i] =
        bf128_add(bf128_add(x_bits_tag[(bit_i - 1 + 8) % 8], x_bits_tag[(bit_i - 3 + 8) % 8]),
                  x_bits_tag[(bit_i - 6 + 8) % 8]);
  }
}

static void aes_192_inverse_affine_byte_prover(uint8_t* y_bits, bf192_t* y_bits_tag,
                                               const uint8_t x_bits, const bf192_t* x_bits_tag) {
  *y_bits = rotr8(x_bits, 7) ^ rotr8(x_bits, 5) ^ rotr8(x_bits, 2) ^ 0x5;

  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_tag[bit_i] =
        bf192_add(bf192_add(x_bits_tag[(bit_i - 1 + 8) % 8], x_bits_tag[(bit_i - 3 + 8) % 8]),
                  x_bits_tag[(bit_i - 6 + 8) % 8]);
  }
}

static void aes_256_inverse_affine_byte_prover(uint8_t* y_bits, bf256_t* y_bits_tag,
                                               const uint8_t x_bits, const bf256_t* x_bits_tag) {
  *y_bits = rotr8(x_bits, 7) ^ rotr8(x_bits, 5) ^ rotr8(x_bits, 2) ^ 0x5;

  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_tag[bit_i] =
        bf256_add(bf256_add(x_bits_tag[(bit_i - 1 + 8) % 8], x_bits_tag[(bit_i - 3 + 8) % 8]),
                  x_bits_tag[(bit_i - 6 + 8) % 8]);
  }
}

static void aes_128_inverse_affine_prover(uint8_t* y, bf128_t* y_tag, const uint8_t* x,
                                          const bf128_t* x_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_128_inverse_affine_byte_prover(y + i, y_tag + i * 8, x[i], x_tag + i * 8);
  }
}

static void aes_192_inverse_affine_prover(uint8_t* y, bf192_t* y_tag, const uint8_t* x,
                                          const bf192_t* x_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_192_inverse_affine_byte_prover(y + i, y_tag + i * 8, x[i], x_tag + i * 8);
  }
}

static void aes_256_inverse_affine_prover(uint8_t* y, bf256_t* y_tag, const uint8_t* x,
                                          const bf256_t* x_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_256_inverse_affine_byte_prover(y + i, y_tag + i * 8, x[i], x_tag + i * 8);
  }
}

static void aes_128_inverse_affine_byte_verifier(bf128_t* y_bits_key, const bf128_t* x_bits_key,
                                                 bf128_t delta) {
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    const uint8_t c = (bit_i == 0 || bit_i == 2) ? 1 : 0;

    y_bits_key[bit_i] =
        bf128_add(bf128_add(x_bits_key[(bit_i - 1 + 8) % 8], x_bits_key[(bit_i - 3 + 8) % 8]),
                  bf128_add(x_bits_key[(bit_i - 6 + 8) % 8], bf128_mul_bit(delta, c)));
  }
}

static void aes_192_inverse_affine_byte_verifier(bf192_t* y_bits_key, const bf192_t* x_bits_key,
                                                 bf192_t delta) {
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    const uint8_t c = (bit_i == 0 || bit_i == 2) ? 1 : 0;

    y_bits_key[bit_i] =
        bf192_add(bf192_add(x_bits_key[(bit_i - 1 + 8) % 8], x_bits_key[(bit_i - 3 + 8) % 8]),
                  bf192_add(x_bits_key[(bit_i - 6 + 8) % 8], bf192_mul_bit(delta, c)));
  }
}

static void aes_256_inverse_affine_byte_verifier(bf256_t* y_bits_key, const bf256_t* x_bits_key,
                                                 bf256_t delta) {
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    const uint8_t c = (bit_i == 0 || bit_i == 2) ? 1 : 0;

    y_bits_key[bit_i] =
        bf256_add(bf256_add(x_bits_key[(bit_i - 1 + 8) % 8], x_bits_key[(bit_i - 3 + 8) % 8]),
                  bf256_add(x_bits_key[(bit_i - 6 + 8) % 8], bf256_mul_bit(delta, c)));
  }
}

static void aes_128_inverse_affine_verifier(bf128_t* y_key, const bf128_t* x_key, bf128_t delta,
                                            const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_128_inverse_affine_byte_verifier(y_key + i * 8, x_key + i * 8, delta);
  }
}

static void aes_192_inverse_affine_verifier(bf192_t* y_key, const bf192_t* x_key, bf192_t delta,
                                            const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_192_inverse_affine_byte_verifier(y_key + i * 8, x_key + i * 8, delta);
  }
}

static void aes_256_inverse_affine_verifier(bf256_t* y_key, const bf256_t* x_key, bf256_t delta,
                                            const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbytes = Nst * 4;

  for (unsigned int i = 0; i < Nstbytes; i++) {
    aes_256_inverse_affine_byte_verifier(y_key + i * 8, x_key + i * 8, delta);
  }
}

// EncSctrnts internal functions end!!

// COLOUM TO ROW MAJOR
static bf128_t* column_to_row_major_and_shrink_V_128(uint8_t** v, unsigned int ell) {
  // V is \hat \ell times \lambda matrix over F_2
  // v has \hat \ell rows, \lambda columns, storing in column-major order, new_v has \ell + 2
  // \lambda rows and \lambda columns storing in row-major order
  bf128_t* new_v = BF128_ALLOC(ell + FAEST_128F_LAMBDA * 2);
  assert(new_v);
  for (unsigned int row = 0; row != ell + FAEST_128F_LAMBDA * 2; ++row) {
    uint8_t new_row[BF128_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != FAEST_128F_LAMBDA; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(v[column], row));
    }
    new_v[row] = bf128_load(new_row);
  }
  return new_v;
}

static bf192_t* column_to_row_major_and_shrink_V_192(uint8_t** v, unsigned int ell) {
  // V is \hat \ell times \lambda matrix over F_2
  // v has \hat \ell rows, \lambda columns, storing in column-major order, new_v has \ell + \lambda
  // rows and \lambda columns storing in row-major order
  bf192_t* new_v = BF192_ALLOC(ell + FAEST_192F_LAMBDA * 2);
  assert(new_v);
  for (unsigned int row = 0; row != ell + FAEST_192F_LAMBDA * 2; ++row) {
    uint8_t new_row[BF192_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != FAEST_192F_LAMBDA; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(v[column], row));
    }
    new_v[row] = bf192_load(new_row);
  }

  return new_v;
}

static bf256_t* column_to_row_major_and_shrink_V_256(uint8_t** v, unsigned int ell) {
  // V is \hat \ell times \lambda matrix over F_2
  // v has \hat \ell rows, \lambda columns, storing in column-major order, new_v has \ell + \lambda
  // rows and \lambda columns storing in row-major order
  bf256_t* new_v = BF256_ALLOC(ell + FAEST_256F_LAMBDA * 2);
  assert(new_v);
  for (unsigned int row = 0; row != ell + FAEST_256F_LAMBDA * 2; ++row) {
    uint8_t new_row[BF256_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != FAEST_256F_LAMBDA; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(v[column], row));
    }
    new_v[row] = bf256_load(new_row);
  }

  return new_v;
}

// // KEY EXP FWD / BKWD
static void aes_128_keyexp_backward_prover(uint8_t* y, bf128_t* y_tag, const uint8_t* x,
                                           const bf128_t* x_tag, const uint8_t* key,
                                           const bf128_t* key_tag, const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7-10
    // for the witness
    uint8_t x_tilde = x[j] ^ key[(iwd + (j % 4) * 8) / 8];
    // for the tags of each witness bit
    bf128_t x_tilde_tag[8];
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_tag[bit_i] = bf128_add(x_tag[j * 8 + bit_i], key_tag[iwd + (j % 4) * 8 + bit_i]);
    }

    if (rmvRcon == true && j % 4 == 0) {
      // adding round constant to the witness
      x_tilde ^= Rcon[j / 4];
    }

    // ::11
    aes_128_inverse_affine_byte_prover(y + j, y_tag + 8 * j, x_tilde, x_tilde_tag);

    // ::12-16 lines only relavant for aes-128
    if (j % 4 == 3) {
#if (FAEST_128_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_128_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_192_keyexp_backward_prover(uint8_t* y, bf192_t* y_tag, const uint8_t* x,
                                           const bf192_t* x_tag, const uint8_t* key,
                                           const bf192_t* key_tag, const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7-10
    // for the witness
    uint8_t x_tilde = x[j] ^ key[(iwd + (j % 4) * 8) / 8];
    // for the tags of each witness bit
    bf192_t x_tilde_tag[8];
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_tag[bit_i] = bf192_add(x_tag[j * 8 + bit_i], key_tag[iwd + (j % 4) * 8 + bit_i]);
    }

    if (rmvRcon == true && j % 4 == 0) {
      // adding round constant to the witness
      x_tilde ^= Rcon[j / 4];
    }

    // ::11
    aes_192_inverse_affine_byte_prover(y + j, y_tag + 8 * j, x_tilde, x_tilde_tag);

    // ::12-16
    if (j % 4 == 3) {
#if (FAEST_192_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_192_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_256_keyexp_backward_prover(uint8_t* y, bf256_t* y_tag, const uint8_t* x,
                                           const bf256_t* x_tag, const uint8_t* key,
                                           const bf256_t* key_tag, const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7-10
    // for the witness
    uint8_t x_tilde = x[j] ^ key[(iwd + (j % 4) * 8) / 8];
    // for the tags of each witness bit
    bf256_t x_tilde_tag[8];
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_tag[bit_i] = bf256_add(x_tag[j * 8 + bit_i], key_tag[iwd + (j % 4) * 8 + bit_i]);
    }

    if (rmvRcon == true && j % 4 == 0) {
      // adding round constant to the witness
      x_tilde ^= Rcon[j / 8];
    }

    // ::11
    aes_256_inverse_affine_byte_prover(y + j, y_tag + 8 * j, x_tilde, x_tilde_tag);

    // ::12-16
    if (j % 4 == 3) {
#if (FAEST_256_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_256_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_128_keyexp_backward_verifier(bf128_t* y_key, const bf128_t* x_key,
                                             const bf128_t* key_key, bf128_t delta,
                                             const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::2
  bf128_t x_tilde_key[8];
  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_key[bit_i] =
          bf128_add(x_key[j * 8 + bit_i],
                    key_key[iwd + (j % 4) * 8 + bit_i]); // for the tags of each witness bit
      // ::8-10
      if (rmvRcon == true && j % 4 == 0) {
        bf128_t rcon_key;
        const uint8_t c = (Rcon[j / 4] >> bit_i) & 1;
        constant_to_vole_128_verifier(&rcon_key, &c, delta, 1);
        x_tilde_key[bit_i] = bf128_add(x_tilde_key[bit_i], rcon_key);
      }
    }
    // ::11
    aes_128_inverse_affine_byte_verifier(y_key + 8 * j, x_tilde_key, delta);

    // ::12-16 lines only relavant for aes-128
    if (j % 4 == 3) {
#if (FAEST_128_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_128_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_192_keyexp_backward_verifier(bf192_t* y_key, const bf192_t* x_key, bf192_t* key_key,
                                             bf192_t delta, const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::2
  bf192_t x_tilde_key[8];
  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_key[bit_i] =
          bf192_add(x_key[j * 8 + bit_i],
                    key_key[iwd + (j % 4) * 8 + bit_i]); // for the tags of each witness bit
      // ::8-10
      if (rmvRcon == true && j % 4 == 0) {
        bf192_t rcon_key;
        const uint8_t c = (Rcon[j / 4] >> bit_i) & 1;
        constant_to_vole_192_verifier(&rcon_key, &c, delta, 1);
        x_tilde_key[bit_i] = bf192_add(x_tilde_key[bit_i], rcon_key);
      }
    }
    // ::11
    aes_192_inverse_affine_byte_verifier(y_key + 8 * j, x_tilde_key, delta);

    // ::12-16
    if (j % 4 == 3) {
#if (FAEST_192_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_192_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_256_keyexp_backward_verifier(bf256_t* y_key, const bf256_t* x_key, bf256_t* key_key,
                                             bf256_t delta, const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  // ::2
  bf256_t x_tilde_key[8];
  // ::3
  unsigned int iwd = 0;
  // ::4
  bool rmvRcon = true;
  // ::5-6
  for (unsigned int j = 0; j < Ske; j++) {
    // ::7
    for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
      x_tilde_key[bit_i] =
          bf256_add(x_key[j * 8 + bit_i],
                    key_key[iwd + (j % 4) * 8 + bit_i]); // for the tags of each witness bit
      // ::8-10
      if (rmvRcon == true && j % 4 == 0) {
        bf256_t rcon_key;
        const uint8_t c = (Rcon[j / 8] >> bit_i) & 1;
        constant_to_vole_256_verifier(&rcon_key, &c, delta, 1);
        x_tilde_key[bit_i] = bf256_add(x_tilde_key[bit_i], rcon_key);
      }
    }
    // ::11
    aes_256_inverse_affine_byte_verifier(y_key + 8 * j, x_tilde_key, delta);

    // ::12-16
    if (j % 4 == 3) {
#if (FAEST_256_LAMBDA == 192)
      iwd += 192;
#else
      iwd += 128;
#if FAEST_256_LAMBDA == 256
      rmvRcon = !rmvRcon;
#endif
#endif
    }
  }
}

static void aes_128_keyexp_forward_prover(uint8_t* y, bf128_t* y_tag, const uint8_t* w,
                                          const bf128_t* w_tag) {
  // ::1-2
  memcpy(y, w, FAEST_128_LAMBDA / 8);
  memcpy(y_tag, w_tag, FAEST_128_LAMBDA * sizeof(bf128_t));

  // ::3
  unsigned int i_wd = FAEST_128_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_128_NK; j < 4 * (FAEST_128_R + 1); j++) {
    // ::5
    if ((j % FAEST_128_NK == 0) || ((FAEST_128_NK > 6) && (j % FAEST_128_NK == 4))) {
      // ::6
      memcpy(&y[32 * j / 8], &w[i_wd / 8], 32 / 8);
      memcpy(&y_tag[32 * j], &w_tag[i_wd], 32 * sizeof(bf128_t));
      // ::7
      i_wd += 32;
      // ::8
    } else {
      // ::9-10
      xor_u8_array(&y[32 * (j - FAEST_128_NK) / 8], &y[32 * (j - 1) / 8], &y[32 * j / 8], 32 / 8);
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_tag[32 * j + word_idx] =
            bf128_add(y_tag[32 * (j - FAEST_128_NK) + word_idx], y_tag[32 * (j - 1) + word_idx]);
      }
    }
  }
}

static void aes_192_keyexp_forward_prover(uint8_t* y, bf192_t* y_tag, const uint8_t* w,
                                          const bf192_t* w_tag) {
  // ::1-2
  memcpy(y, w, FAEST_192_LAMBDA / 8);
  memcpy(y_tag, w_tag, FAEST_192_LAMBDA * sizeof(bf192_t));

  // ::3
  unsigned int i_wd = FAEST_192_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_192_NK; j < 4 * (FAEST_192_R + 1); j++) {
    // ::5
    if ((j % FAEST_192_NK == 0) || ((FAEST_192_NK > 6) && (j % FAEST_192_NK == 4))) {
      // ::6
      memcpy(&y[32 * j / 8], &w[i_wd / 8], 32 / 8);
      memcpy(&y_tag[32 * j], &w_tag[i_wd], 32 * sizeof(bf192_t));
      // ::7
      i_wd += 32;
      // ::8
    } else {
      // ::9-10
      xor_u8_array(&y[32 * (j - FAEST_192_NK) / 8], &y[32 * (j - 1) / 8], &y[32 * j / 8], 32 / 8);
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_tag[32 * j + word_idx] =
            bf192_add(y_tag[32 * (j - FAEST_192_NK) + word_idx], y_tag[32 * (j - 1) + word_idx]);
      }
    }
  }
}

static void aes_256_keyexp_forward_prover(uint8_t* y, bf256_t* y_tag, const uint8_t* w,
                                          const bf256_t* w_tag) {
  // ::1-2
  memcpy(y, w, FAEST_256_LAMBDA / 8);
  memcpy(y_tag, w_tag, FAEST_256_LAMBDA * sizeof(bf256_t));

  // ::3
  unsigned int i_wd = FAEST_256_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_256_NK; j < 4 * (FAEST_256_R + 1); j++) {
    // ::5
    if ((j % FAEST_256_NK == 0) || ((FAEST_256_NK > 6) && (j % FAEST_256_NK == 4))) {
      // ::6
      memcpy(&y[32 * j / 8], &w[i_wd / 8], 32 / 8);
      memcpy(&y_tag[32 * j], &w_tag[i_wd], 32 * sizeof(bf256_t));
      // ::7
      i_wd += 32;
      // ::8
    } else {
      // ::9-10
      xor_u8_array(&y[32 * (j - FAEST_256_NK) / 8], &y[32 * (j - 1) / 8], &y[32 * j / 8], 32 / 8);
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_tag[32 * j + word_idx] =
            bf256_add(y_tag[32 * (j - FAEST_256_NK) + word_idx], y_tag[32 * (j - 1) + word_idx]);
      }
    }
  }
}

static void aes_128_keyexp_forward_verifier(bf128_t* y_key, const bf128_t* w_key) {
  // ::1-2
  memcpy(y_key, w_key, FAEST_128_LAMBDA * sizeof(bf128_t));

  // ::3
  unsigned int i_wd = FAEST_128_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_128_NK; j < 4 * (FAEST_128_R + 1); j++) {
    // ::5
    if ((j % FAEST_128_NK == 0) || ((FAEST_128_NK > 6) && (j % FAEST_128_NK == 4))) {
      // ::6
      memcpy(&y_key[32 * j], &w_key[i_wd], 32 * sizeof(bf128_t));
      // ::7
      i_wd += 32; // 32 bits -> 4 words
      // ::8
    } else {
      // ::9-10
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_key[32 * j + word_idx] =
            bf128_add(y_key[32 * (j - FAEST_128_NK) + word_idx], y_key[32 * (j - 1) + word_idx]);
      }
    }
  }
}

static void aes_192_keyexp_forward_verifier(bf192_t* y_key, const bf192_t* w_key) {
  // ::1-2
  memcpy(y_key, w_key, FAEST_192_LAMBDA * sizeof(bf192_t));

  // ::3
  unsigned int i_wd = FAEST_192_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_192_NK; j < 4 * (FAEST_192_R + 1); j++) {
    // ::5
    if ((j % FAEST_192_NK == 0) || ((FAEST_192_NK > 6) && (j % FAEST_192_NK == 4))) {
      // ::6
      memcpy(&y_key[32 * j], &w_key[i_wd], 32 * sizeof(bf192_t));
      // ::7
      i_wd += 32; // 32 bits -> 4 words
      // ::8
    } else {
      // ::9-10
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_key[32 * j + word_idx] =
            bf192_add(y_key[32 * (j - FAEST_192_NK) + word_idx], y_key[32 * (j - 1) + word_idx]);
      }
    }
  }
}

static void aes_256_keyexp_forward_verifier(bf256_t* y_key, const bf256_t* w_key) {
  // ::1-2
  memcpy(y_key, w_key, FAEST_256_LAMBDA * sizeof(bf256_t));

  // ::3
  unsigned int i_wd = FAEST_256_LAMBDA;
  // ::4-10
  for (unsigned int j = FAEST_256_NK; j < 4 * (FAEST_256_R + 1); j++) {
    // ::5
    if ((j % FAEST_256_NK == 0) || ((FAEST_256_NK > 6) && (j % FAEST_256_NK == 4))) {
      // ::6
      memcpy(&y_key[32 * j], &w_key[i_wd], 32 * sizeof(bf256_t));
      // ::7
      i_wd += 32; // 32 bits -> 4 words
      // ::8
    } else {
      // ::9-10
      for (unsigned int word_idx = 0; word_idx < 32; word_idx++) {
        y_key[32 * j + word_idx] =
            bf256_add(y_key[32 * (j - FAEST_256_NK) + word_idx], y_key[32 * (j - 1) + word_idx]);
      }
    }
  }
}

// // KEY EXP CSTRNTS
static void aes_128_expkey_constraints_prover(zk_hash_128_3_ctx* hasher, uint8_t* k, bf128_t* k_tag,
                                              const uint8_t* w, const bf128_t* w_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_128_keyexp_forward_prover(k, k_tag, w, w_tag);
  // ::2
  uint8_t* w_flat     = malloc(Ske);
  bf128_t* w_flat_tag = BF128_ALLOC(8 * Ske);
  assert(w_flat);
  assert(w_flat_tag);
  aes_128_keyexp_backward_prover(w_flat, w_flat_tag, w + FAEST_128_LAMBDA / 8,
                                 w_tag + FAEST_128_LAMBDA, k, k_tag, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_128_NK - 1);
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf128_t k_hat[4];    // expnaded key witness
    bf128_t w_hat[4];    // inverse output
    bf128_t k_hat_sq[4]; // expanded key witness sq
    bf128_t w_hat_sq[4]; // inverse output sq

    bf128_t k_hat_tag[4];    // expanded key witness tag
    bf128_t w_hat_tag[4];    // inverse output tag
    bf128_t k_hat_tag_sq[4]; // expanded key tag sq
    bf128_t w_hat_tag_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat[r_prime]    = bf128_byte_combine_bits(k[(iwd + 8 * r) / 8]);    // lifted key witness
      k_hat_sq[r_prime] = bf128_byte_combine_bits_sq(k[(iwd + 8 * r) / 8]); // lifted key witness sq

      w_hat[r]    = bf128_byte_combine_bits(w_flat[(32 * j + 8 * r) / 8]);    // lifted output
      w_hat_sq[r] = bf128_byte_combine_bits_sq(w_flat[(32 * j + 8 * r) / 8]); // lifted output sq

      // done by both prover and verifier
      k_hat_tag[r_prime]    = bf128_byte_combine(k_tag + (iwd + 8 * r));    // lifted key tag
      k_hat_tag_sq[r_prime] = bf128_byte_combine_sq(k_tag + (iwd + 8 * r)); // lifted key tag sq

      w_hat_tag[r] = bf128_byte_combine(w_flat_tag + ((32 * j + 8 * r))); // lifted output tag
      w_hat_tag_sq[r] =
          bf128_byte_combine_sq(w_flat_tag + (32 * j + 8 * r)); // lifted output tag sq
    }

#if FAEST_128_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17
    for (unsigned int r = 0; r < 4; r++) {
      // ::18-19
      zk_hash_128_3_raise_and_update(hasher, bf128_mul(k_hat_tag_sq[r], w_hat_tag[r]),
                                     bf128_add(bf128_add(bf128_mul(k_hat_sq[r], w_hat_tag[r]),
                                                         bf128_mul(k_hat_tag_sq[r], w_hat[r])),
                                               k_hat_tag[r]));
      zk_hash_128_3_raise_and_update(hasher, bf128_mul(k_hat_tag[r], w_hat_tag_sq[r]),
                                     bf128_add(bf128_add(bf128_mul(k_hat[r], w_hat_tag_sq[r]),
                                                         bf128_mul(k_hat_tag[r], w_hat_sq[r])),
                                               w_hat_tag[r]));
    }
#if FAEST_128_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }
  free(w_flat);
  faest_aligned_free(w_flat_tag);
}

static void aes_192_expkey_constraints_prover(zk_hash_192_3_ctx* hasher, uint8_t* k, bf192_t* k_tag,
                                              const uint8_t* w, const bf192_t* w_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_192_keyexp_forward_prover(k, k_tag, w, w_tag);
  // ::2
  uint8_t* w_flat     = malloc(Ske);
  bf192_t* w_flat_tag = BF192_ALLOC(8 * Ske);
  assert(w_flat);
  assert(w_flat_tag);
  aes_192_keyexp_backward_prover(w_flat, w_flat_tag, w + FAEST_192_LAMBDA / 8,
                                 w_tag + FAEST_192_LAMBDA, k, k_tag, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_192_NK - 1);
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf192_t k_hat[4];    // expnaded key witness
    bf192_t w_hat[4];    // inverse output
    bf192_t k_hat_sq[4]; // expanded key witness sq
    bf192_t w_hat_sq[4]; // inverse output sq

    bf192_t k_hat_tag[4];    // expanded key witness tag
    bf192_t w_hat_tag[4];    // inverse output tag
    bf192_t k_hat_tag_sq[4]; // expanded key tag sq
    bf192_t w_hat_tag_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat[r_prime]    = bf192_byte_combine_bits(k[(iwd + 8 * r) / 8]);    // lifted key witness
      k_hat_sq[r_prime] = bf192_byte_combine_bits_sq(k[(iwd + 8 * r) / 8]); // lifted key witness sq

      w_hat[r]    = bf192_byte_combine_bits(w_flat[(32 * j + 8 * r) / 8]);    // lifted output
      w_hat_sq[r] = bf192_byte_combine_bits_sq(w_flat[(32 * j + 8 * r) / 8]); // lifted output sq

      // done by both prover and verifier
      k_hat_tag[r_prime]    = bf192_byte_combine(k_tag + (iwd + 8 * r));    // lifted key tag
      k_hat_tag_sq[r_prime] = bf192_byte_combine_sq(k_tag + (iwd + 8 * r)); // lifted key tag sq

      w_hat_tag[r] = bf192_byte_combine(w_flat_tag + ((32 * j + 8 * r))); // lifted output tag
      w_hat_tag_sq[r] =
          bf192_byte_combine_sq(w_flat_tag + (32 * j + 8 * r)); // lifted output tag sq
    }

#if FAEST_192_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17
    for (unsigned int r = 0; r < 4; r++) {
      // ::18-19
      zk_hash_192_3_raise_and_update(hasher, bf192_mul(k_hat_tag_sq[r], w_hat_tag[r]),
                                     bf192_add(bf192_add(bf192_mul(k_hat_sq[r], w_hat_tag[r]),
                                                         bf192_mul(k_hat_tag_sq[r], w_hat[r])),
                                               k_hat_tag[r]));
      zk_hash_192_3_raise_and_update(hasher, bf192_mul(k_hat_tag[r], w_hat_tag_sq[r]),
                                     bf192_add(bf192_add(bf192_mul(k_hat[r], w_hat_tag_sq[r]),
                                                         bf192_mul(k_hat_tag[r], w_hat_sq[r])),
                                               w_hat_tag[r]));
    }
#if FAEST_192_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }

  faest_aligned_free(w_flat_tag);
  free(w_flat);
}

static void aes_256_expkey_constraints_prover(zk_hash_256_3_ctx* hasher, uint8_t* k, bf256_t* k_tag,
                                              const uint8_t* w, const bf256_t* w_tag,
                                              const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_256_keyexp_forward_prover(k, k_tag, w, w_tag);
  // ::2
  uint8_t* w_flat     = malloc(Ske);
  bf256_t* w_flat_tag = BF256_ALLOC(8 * Ske);
  assert(w_flat);
  assert(w_flat_tag);
  aes_256_keyexp_backward_prover(w_flat, w_flat_tag, w + FAEST_256_LAMBDA / 8,
                                 w_tag + FAEST_256_LAMBDA, k, k_tag, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_256_NK - 1);
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf256_t k_hat[4];    // expnaded key witness
    bf256_t w_hat[4];    // inverse output
    bf256_t k_hat_sq[4]; // expanded key witness sq
    bf256_t w_hat_sq[4]; // inverse output sq

    bf256_t k_hat_tag[4];    // expanded key witness tag
    bf256_t w_hat_tag[4];    // inverse output tag
    bf256_t k_hat_tag_sq[4]; // expanded key tag sq
    bf256_t w_hat_tag_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat[r_prime]    = bf256_byte_combine_bits(k[(iwd + 8 * r) / 8]);    // lifted key witness
      k_hat_sq[r_prime] = bf256_byte_combine_bits_sq(k[(iwd + 8 * r) / 8]); // lifted key witness sq

      w_hat[r]    = bf256_byte_combine_bits(w_flat[(32 * j + 8 * r) / 8]);    // lifted output
      w_hat_sq[r] = bf256_byte_combine_bits_sq(w_flat[(32 * j + 8 * r) / 8]); // lifted output sq

      // done by both prover and verifier
      k_hat_tag[r_prime]    = bf256_byte_combine(k_tag + (iwd + 8 * r));    // lifted key tag
      k_hat_tag_sq[r_prime] = bf256_byte_combine_sq(k_tag + (iwd + 8 * r)); // lifted key tag sq

      w_hat_tag[r] = bf256_byte_combine(w_flat_tag + ((32 * j + 8 * r))); // lifted output tag
      w_hat_tag_sq[r] =
          bf256_byte_combine_sq(w_flat_tag + (32 * j + 8 * r)); // lifted output tag sq
    }

#if FAEST_256_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17
    for (unsigned int r = 0; r < 4; r++) {
      // ::18-19
      zk_hash_256_3_raise_and_update(hasher, bf256_mul(k_hat_tag_sq[r], w_hat_tag[r]),
                                     bf256_add(bf256_add(bf256_mul(k_hat_sq[r], w_hat_tag[r]),
                                                         bf256_mul(k_hat_tag_sq[r], w_hat[r])),
                                               k_hat_tag[r]));
      zk_hash_256_3_raise_and_update(hasher, bf256_mul(k_hat_tag[r], w_hat_tag_sq[r]),
                                     bf256_add(bf256_add(bf256_mul(k_hat[r], w_hat_tag_sq[r]),
                                                         bf256_mul(k_hat_tag[r], w_hat_sq[r])),
                                               w_hat_tag[r]));
    }
#if FAEST_256_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }
  free(w_flat);
  faest_aligned_free(w_flat_tag);
}

static void aes_128_expkey_constraints_verifier(zk_hash_128_ctx* hasher, bf128_t* k_key,
                                                const bf128_t* w_key, bf128_t delta,
                                                const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_128_keyexp_forward_verifier(k_key, w_key);
  // ::2
  bf128_t* w_flat_key = BF128_ALLOC(8 * Ske);
  assert(w_flat_key);
  aes_128_keyexp_backward_verifier(w_flat_key, w_key + FAEST_128_LAMBDA, k_key, delta, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_128_NK - 1); // as 1 unit8 has 8 bits
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf128_t k_hat_key[4];    // expanded key witness tag
    bf128_t w_hat_key[4];    // inverse output tag
    bf128_t k_hat_key_sq[4]; // expanded key tag sq
    bf128_t w_hat_key_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat_key[r_prime]    = bf128_byte_combine(k_key + (iwd + 8 * r));    // lifted key tag
      k_hat_key_sq[r_prime] = bf128_byte_combine_sq(k_key + (iwd + 8 * r)); // lifted key tag sq

      w_hat_key[r] = bf128_byte_combine(w_flat_key + ((32 * j + 8 * r))); // lifted output tag
      w_hat_key_sq[r] =
          bf128_byte_combine_sq(w_flat_key + (32 * j + 8 * r)); // lifted output tag sq
    }
#if FAEST_128_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17-20
    for (unsigned int r = 0; r < 4; r++) {
      // also raise degree
      zk_hash_128_update(hasher,
                         bf128_mul(delta, bf128_add(bf128_mul(k_hat_key_sq[r], w_hat_key[r]),
                                                    bf128_mul(delta, k_hat_key[r]))));
      zk_hash_128_update(hasher,
                         bf128_mul(delta, bf128_add(bf128_mul(k_hat_key[r], w_hat_key_sq[r]),
                                                    bf128_mul(delta, w_hat_key[r]))));
    }
#if FAEST_128_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }
  faest_aligned_free(w_flat_key);
}

static void aes_192_expkey_constraints_verifier(zk_hash_192_ctx* hasher, bf192_t* k_key,
                                                const bf192_t* w_key, bf192_t delta,
                                                const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_192_keyexp_forward_verifier(k_key, w_key);
  // ::2
  bf192_t* w_flat_key = BF192_ALLOC(8 * Ske);
  assert(w_flat_key);
  aes_192_keyexp_backward_verifier(w_flat_key, w_key + FAEST_192_LAMBDA, k_key, delta, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_192_NK - 1); // as 1 unit8 has 8 bits
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf192_t k_hat_key[4];    // expanded key witness tag
    bf192_t w_hat_key[4];    // inverse output tag
    bf192_t k_hat_key_sq[4]; // expanded key tag sq
    bf192_t w_hat_key_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat_key[r_prime]    = bf192_byte_combine(k_key + (iwd + 8 * r));    // lifted key tag
      k_hat_key_sq[r_prime] = bf192_byte_combine_sq(k_key + (iwd + 8 * r)); // lifted key tag sq

      w_hat_key[r] = bf192_byte_combine(w_flat_key + ((32 * j + 8 * r))); // lifted output tag
      w_hat_key_sq[r] =
          bf192_byte_combine_sq(w_flat_key + (32 * j + 8 * r)); // lifted output tag sq
    }
#if FAEST_192_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17-20
    for (unsigned int r = 0; r < 4; r++) {
      zk_hash_192_update(hasher,
                         bf192_mul(delta, bf192_add(bf192_mul(k_hat_key_sq[r], w_hat_key[r]),
                                                    bf192_mul(delta, k_hat_key[r]))));
      zk_hash_192_update(hasher,
                         bf192_mul(delta, bf192_add(bf192_mul(k_hat_key[r], w_hat_key_sq[r]),
                                                    bf192_mul(delta, w_hat_key[r]))));
    }
#if FAEST_192_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }
  faest_aligned_free(w_flat_key);
}

static void aes_256_expkey_constraints_verifier(zk_hash_256_ctx* hasher, bf256_t* k_key,
                                                const bf256_t* w_key, bf256_t delta,
                                                const faest_paramset_t* params) {
  const unsigned int Ske = params->Ske;

  bool do_rot_word = true;

  // ::1
  aes_256_keyexp_forward_verifier(k_key, w_key);
  // ::2
  bf256_t* w_flat_key = BF256_ALLOC(8 * Ske);
  assert(w_flat_key);
  aes_256_keyexp_backward_verifier(w_flat_key, w_key + FAEST_256_LAMBDA, k_key, delta, params);

  // ::3-5
  unsigned int iwd = 32 * (FAEST_256_NK - 1); // as 1 unit8 has 8 bits
  // ::6 Used only on AES-256
  // ::7
  for (unsigned int j = 0; j < Ske / 4; j++) {
    // ::8
    bf256_t k_hat_key[4];    // expanded key witness tag
    bf256_t w_hat_key[4];    // inverse output tag
    bf256_t k_hat_key_sq[4]; // expanded key tag sq
    bf256_t w_hat_key_sq[4]; // inverser output tag sq

    // ::9
    for (unsigned int r = 0; r < 4; r++) {
      // ::10
      unsigned int r_prime = r;
      // ::11
      if (do_rot_word) {
        r_prime = (r + 3) % 4;
      }
      // ::12-15
      k_hat_key[r_prime]    = bf256_byte_combine(k_key + (iwd + 8 * r));    // lifted key tag
      k_hat_key_sq[r_prime] = bf256_byte_combine_sq(k_key + (iwd + 8 * r)); // lifted key tag sq

      w_hat_key[r] = bf256_byte_combine(w_flat_key + ((32 * j + 8 * r))); // lifted output tag
      w_hat_key_sq[r] =
          bf256_byte_combine_sq(w_flat_key + (32 * j + 8 * r)); // lifted output tag sq
    }
#if FAEST_256_LAMBDA == 256
    // ::16 used only for AES-256
    do_rot_word = !do_rot_word;
#endif
    // ::17-20
    for (unsigned int r = 0; r < 4; r++) {
      // also raise degree
      zk_hash_256_update(hasher,
                         bf256_mul(delta, bf256_add(bf256_mul(k_hat_key_sq[r], w_hat_key[r]),
                                                    bf256_mul(delta, k_hat_key[r]))));
      zk_hash_256_update(hasher,
                         bf256_mul(delta, bf256_add(bf256_mul(k_hat_key[r], w_hat_key_sq[r]),
                                                    bf256_mul(delta, w_hat_key[r]))));
    }
#if FAEST_256_LAMBDA == 192
    iwd += 192;
#else
    iwd += 128;
#endif
  }
  faest_aligned_free(w_flat_key);
}

// // ENC CSTRNTS
static void aes_128_enc_constraints_prover(zk_hash_128_3_ctx* hasher, const uint8_t* owf_in,
                                           const bf128_t* owf_in_tag, const uint8_t* owf_out,
                                           const bf128_t* owf_out_tag, const uint8_t* w,
                                           const bf128_t* w_tag, const uint8_t* k,
                                           const bf128_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  /// ::1 AddFAEST_128_RoundKey
  uint8_t* state_bits     = malloc(Nstbytes);
  bf128_t* state_bits_tag = BF128_ALLOC(Nstbits);
  assert(state_bits);
  assert(state_bits_tag);

  aes_128_add_round_key_prover(state_bits, state_bits_tag, owf_in, owf_in_tag, k, k_tag, params);

  // for conjugates of state and s-box outputs
  bf128_t* state_conj     = BF128_ALLOC(8 * Nstbytes);
  bf128_t* state_conj_tag = BF128_ALLOC(8 * Nstbytes);
  bf128_t* st_dash_deg2   = BF128_ALLOC(8 * Nstbytes);
  bf128_t* st_dash_deg1   = BF128_ALLOC(8 * Nstbytes);
  bf128_t* st_dash_deg0   = BF128_ALLOC(8 * Nstbytes);
  assert(state_conj);
  assert(state_conj_tag);
  assert(st_dash_deg0);
  assert(st_dash_deg1);
  assert(st_dash_deg2);

  // ::2
  for (unsigned int r = 0; r < FAEST_128_R / 2; r++) {
    // ::3-4
    aes_128_f256_f2_conjugates_1(state_conj, state_bits, params);
    aes_128_f256_f2_conjugates_128(state_conj_tag, state_bits_tag, params);

    // ::5-6 : start of norms in witness
    const bf128_t* norm_tags_ptr = w_tag + 3 * Nstbits * r / 2;
    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::5-6 norms in witness
      const uint8_t norm = (w[(3 * Nstbits * r / 2 + 4 * i) / 8] >> ((i % 2) * 4)) & 0xf;

      // ::8-9
      bf128_t y[4];
      bf128_t y_tag[4];
      aes_128_inv_norm_to_conjugates_prover(y, y_tag, norm, norm_tags_ptr + 4 * i);

      // ::10-11
      aes_128_inv_norm_constraints_prover(hasher, state_conj + 8 * i, state_conj_tag + 8 * i, y,
                                          y_tag);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_deg2[i * 8 + j] = bf128_mul(state_conj[conj_index], y[y_index]);
        st_dash_deg1[i * 8 + j] = bf128_add(bf128_mul(state_conj[conj_index], y_tag[y_index]),
                                            bf128_mul(state_conj_tag[conj_index], y[y_index]));
        st_dash_deg0[i * 8 + j] = bf128_mul(state_conj_tag[conj_index], y_tag[y_index]);
      }
    }

    // ::15-16
    bf128_t k_0_deg0[FAEST_128_LAMBDA / 8];
    bf128_t k_0_deg1[FAEST_128_LAMBDA / 8];
    aes_128_state_to_bytes_prover(k_0_deg1, k_0_deg0, k + (2 * r + 1) * Nstbytes,
                                  k_tag + (2 * r + 1) * Nstbits, params);

    // ::17
    bf128_t k_1_deg0[FAEST_128_LAMBDA / 8];
    bf128_t k_1_deg2[FAEST_128_LAMBDA / 8];
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_deg0[byte_i] = bf128_mul(k_0_deg0[byte_i], k_0_deg0[byte_i]);
      k_1_deg2[byte_i] = bf128_mul(k_0_deg1[byte_i], k_0_deg1[byte_i]);
    }

    // ::18
    bf128_t st_b_deg0[2][FAEST_128_LAMBDA / 8];
    bf128_t st_b_deg1[2][FAEST_128_LAMBDA / 8];
    bf128_t st_b_deg2[2][FAEST_128_LAMBDA / 8];
    memset(st_b_deg0, 0x00, sizeof(st_b_deg0));
    memset(st_b_deg1, 0x00, sizeof(st_b_deg1));
    memset(st_b_deg2, 0x00, sizeof(st_b_deg2));
    for (unsigned int b = 0; b < 2; b++) {
      bf128_t st_b_deg0_tmp[FAEST_128_LAMBDA / 8];
      bf128_t st_b_deg1_tmp[FAEST_128_LAMBDA / 8];
      bf128_t st_b_deg2_tmp[FAEST_128_LAMBDA / 8];
      memset(st_b_deg0_tmp, 0x00, sizeof(st_b_deg0_tmp));
      memset(st_b_deg1_tmp, 0x00, sizeof(st_b_deg1_tmp));
      memset(st_b_deg2_tmp, 0x00, sizeof(st_b_deg2_tmp));

      // ::19
      aes_128_sbox_affine_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_dash_deg0,
                                 st_dash_deg1, st_dash_deg2, b, params);
      // ::20
      aes_128_shiftrows_prover(st_b_deg0_tmp, st_b_deg1_tmp, st_b_deg2_tmp, st_b_deg0[b],
                               st_b_deg1[b], st_b_deg2[b], params);
      // ::21
      aes_128_mix_columns_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_b_deg0_tmp,
                                 st_b_deg1_tmp, st_b_deg2_tmp, b, params);
      // ::22
      if (b == 0) {
        aes_128_add_round_key_bytes_prover_degree_1(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_0_deg0, k_0_deg1, params);
      } else {
        aes_128_add_round_key_bytes_prover_degree_2(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_1_deg0, k_1_deg2, params);
      }
    }

    // ::23-24
    uint8_t* s_tilde     = malloc(Nstbytes);
    bf128_t* s_tilde_tag = BF128_ALLOC(Nstbits);
    assert(s_tilde);
    assert(s_tilde_tag);
    if (r == FAEST_128_R / 2 - 1) {
      // ::25
      aes_128_add_round_key_prover(s_tilde, s_tilde_tag, owf_out, owf_out_tag,
                                   k + FAEST_128_R * Nstbytes, k_tag + FAEST_128_R * Nstbits,
                                   params);
    } else {
      // ::27-28
      memcpy(s_tilde, &w[((Nstbits / 2) + (Nstbits / 2) * 3 * r) / 8], Nstbytes);
      memcpy(s_tilde_tag, &w_tag[((Nstbits / 2) + (Nstbits / 2) * 3 * r)],
             Nstbits * sizeof(bf128_t));
    }

    // ::29
    uint8_t* s_dash_dash     = malloc(Nstbytes);
    bf128_t* s_dash_dash_tag = BF128_ALLOC(Nstbits);
    assert(s_dash_dash);
    assert(s_dash_dash_tag);
    aes_128_inverse_shiftrows_prover(s_dash_dash, s_dash_dash_tag, s_tilde, s_tilde_tag, params);
    // ::30
    uint8_t* s     = malloc(Nstbytes);
    bf128_t* s_tag = BF128_ALLOC(Nstbits);
    assert(s);
    assert(s_tag);
    aes_128_inverse_affine_prover(s, s_tag, s_dash_dash, s_dash_dash_tag, params);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      bf128_t s_deg1 = bf128_byte_combine_bits(s[byte_i]);
      bf128_t s_deg0 = bf128_byte_combine(s_tag + 8 * byte_i);
      // ::33
      bf128_t s_sq_deg1 = bf128_byte_combine_bits_sq(s[byte_i]);
      bf128_t s_sq_deg0 = bf128_byte_combine_sq(s_tag + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    deg0: s_sq[0] * st[0]
      //    deg1: s_sq[0] * st[1] + s_sq[1] * st[0]
      //    deg2: s_sq[0] * st[2] + s_sq[1] * st[1] + s[0]
      //
      zk_hash_128_3_update(hasher, bf128_mul(s_sq_deg0, st_b_deg0[0][byte_i]),
                           bf128_add(bf128_mul(s_sq_deg0, st_b_deg1[0][byte_i]),
                                     bf128_mul(s_sq_deg1, st_b_deg0[0][byte_i])),
                           bf128_add(bf128_add(bf128_mul(s_sq_deg0, st_b_deg2[0][byte_i]),
                                               bf128_mul(s_sq_deg1, st_b_deg1[0][byte_i])),
                                     s_deg0));

      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    deg0: s[0] * st_{1,i}[0]
      //    deg1: s[0] * st_{1,i}[1] + s[1] * st_{1,i}[0] + st_{0,i}[0]
      //    deg2: s[0] * st_{1,i}[2] + s[1] * st_{1,i}[1] + st_{0,i}[1]
      //
      zk_hash_128_3_update(hasher, bf128_mul(s_deg0, st_b_deg0[1][byte_i]),
                           bf128_add(bf128_add(bf128_mul(s_deg0, st_b_deg1[1][byte_i]),
                                               bf128_mul(s_deg1, st_b_deg0[1][byte_i])),
                                     st_b_deg0[0][byte_i]),
                           bf128_add(bf128_add(bf128_mul(s_deg0, st_b_deg2[1][byte_i]),
                                               bf128_mul(s_deg1, st_b_deg1[1][byte_i])),
                                     st_b_deg1[0][byte_i]));
    }
    if (r != (FAEST_128_R / 2) - 1) {
      uint8_t* tmp_state     = s;
      bf128_t* tmp_state_tag = s_tag;
      aes_128_bitwise_mix_column_prover(tmp_state, tmp_state_tag, s_tilde, s_tilde_tag, params);
      aes_128_add_round_key_prover(state_bits, state_bits_tag, tmp_state, tmp_state_tag,
                                   k + (2 * r + 2) * Nstbytes, k_tag + (2 * r + 2) * Nstbits,
                                   params);
    }

    faest_aligned_free(s_tilde_tag);
    faest_aligned_free(s_dash_dash_tag);
    faest_aligned_free(s_tag);
    free(s_tilde);
    free(s_dash_dash);
    free(s);
  }

  faest_aligned_free(st_dash_deg0);
  faest_aligned_free(st_dash_deg1);
  faest_aligned_free(st_dash_deg2);
  faest_aligned_free(state_conj_tag);
  faest_aligned_free(state_conj);
  faest_aligned_free(state_bits_tag);
  free(state_bits);
}

static void aes_192_enc_constraints_prover(zk_hash_192_3_ctx* hasher, const uint8_t* owf_in,
                                           const bf192_t* owf_in_tag, const uint8_t* owf_out,
                                           const bf192_t* owf_out_tag, const uint8_t* w,
                                           const bf192_t* w_tag, const uint8_t* k,
                                           const bf192_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  /// ::1 AddFAEST_192_RoundKey
  uint8_t* state_bits     = malloc(Nstbytes);
  bf192_t* state_bits_tag = BF192_ALLOC(Nstbits);
  assert(state_bits);
  assert(state_bits_tag);

  aes_192_add_round_key_prover(state_bits, state_bits_tag, owf_in, owf_in_tag, k, k_tag, params);

  // for conjugates of state and s-box outputs
  bf192_t* state_conj     = BF192_ALLOC(8 * Nstbytes);
  bf192_t* state_conj_tag = BF192_ALLOC(8 * Nstbytes);
  bf192_t* st_dash_deg2   = BF192_ALLOC(8 * Nstbytes);
  bf192_t* st_dash_deg1   = BF192_ALLOC(8 * Nstbytes);
  bf192_t* st_dash_deg0   = BF192_ALLOC(8 * Nstbytes);
  assert(state_conj);
  assert(state_conj_tag);
  assert(st_dash_deg2);
  assert(st_dash_deg1);
  assert(st_dash_deg0);

  // ::2
  for (unsigned int r = 0; r < FAEST_192_R / 2; r++) {
    // ::3-4
    aes_192_f256_f2_conjugates_1(state_conj, state_bits, params);
    aes_192_f256_f2_conjugates_192(state_conj_tag, state_bits_tag, params);

    // ::5-6 : start of norms in witness
    const bf192_t* norm_tags_ptr = w_tag + 3 * Nstbits * r / 2;
    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::5-6 norms in witness
      const uint8_t norm = (w[(3 * Nstbits * r / 2 + 4 * i) / 8] >> ((i % 2) * 4)) & 0xf;

      // ::8-9
      bf192_t y[4];
      bf192_t y_tag[4];
      aes_192_inv_norm_to_conjugates_prover(y, y_tag, norm, norm_tags_ptr + 4 * i);

      // ::10-11
      aes_192_inv_norm_constraints_prover(hasher, state_conj + 8 * i, state_conj_tag + 8 * i, y,
                                          y_tag);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_deg2[i * 8 + j] = bf192_mul(state_conj[conj_index], y[y_index]);
        st_dash_deg1[i * 8 + j] = bf192_add(bf192_mul(state_conj[conj_index], y_tag[y_index]),
                                            bf192_mul(state_conj_tag[conj_index], y[y_index]));
        st_dash_deg0[i * 8 + j] = bf192_mul(state_conj_tag[conj_index], y_tag[y_index]);
      }
    }

    // ::15-16
    bf192_t k_0_deg0[FAEST_192_LAMBDA / 8];
    bf192_t k_0_deg1[FAEST_192_LAMBDA / 8];
    aes_192_state_to_bytes_prover(k_0_deg1, k_0_deg0, k + (2 * r + 1) * Nstbytes,
                                  k_tag + (2 * r + 1) * Nstbits, params);

    // ::17
    bf192_t k_1_deg0[FAEST_192_LAMBDA / 8];
    bf192_t k_1_deg2[FAEST_192_LAMBDA / 8];
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_deg0[byte_i] = bf192_mul(k_0_deg0[byte_i], k_0_deg0[byte_i]);
      k_1_deg2[byte_i] = bf192_mul(k_0_deg1[byte_i], k_0_deg1[byte_i]);
    }

    // ::18
    bf192_t st_b_deg0[2][FAEST_192_LAMBDA / 8];
    bf192_t st_b_deg1[2][FAEST_192_LAMBDA / 8];
    bf192_t st_b_deg2[2][FAEST_192_LAMBDA / 8];
    memset(st_b_deg0, 0x00, sizeof(st_b_deg0));
    memset(st_b_deg1, 0x00, sizeof(st_b_deg1));
    memset(st_b_deg2, 0x00, sizeof(st_b_deg2));
    for (unsigned int b = 0; b < 2; b++) {
      bf192_t st_b_deg0_tmp[FAEST_192_LAMBDA / 8];
      bf192_t st_b_deg1_tmp[FAEST_192_LAMBDA / 8];
      bf192_t st_b_deg2_tmp[FAEST_192_LAMBDA / 8];
      memset(st_b_deg0_tmp, 0x00, sizeof(st_b_deg0_tmp));
      memset(st_b_deg1_tmp, 0x00, sizeof(st_b_deg1_tmp));
      memset(st_b_deg2_tmp, 0x00, sizeof(st_b_deg2_tmp));

      // ::19
      aes_192_sbox_affine_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_dash_deg0,
                                 st_dash_deg1, st_dash_deg2, b, params);
      // ::20
      aes_192_shiftrows_prover(st_b_deg0_tmp, st_b_deg1_tmp, st_b_deg2_tmp, st_b_deg0[b],
                               st_b_deg1[b], st_b_deg2[b], params);
      // ::21
      aes_192_mix_columns_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_b_deg0_tmp,
                                 st_b_deg1_tmp, st_b_deg2_tmp, b, params);
      // ::22
      if (b == 0) {
        aes_192_add_round_key_bytes_prover_degree_1(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_0_deg0, k_0_deg1, params);
      } else {
        aes_192_add_round_key_bytes_prover_degree_2(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_1_deg0, k_1_deg2, params);
      }
    }

    // ::23-24
    uint8_t* s_tilde     = malloc(Nstbytes);
    bf192_t* s_tilde_tag = BF192_ALLOC(Nstbits);
    assert(s_tilde);
    assert(s_tilde_tag);
    if (r == FAEST_192_R / 2 - 1) {
      // ::25
      aes_192_add_round_key_prover(s_tilde, s_tilde_tag, owf_out, owf_out_tag,
                                   k + FAEST_192_R * Nstbytes, k_tag + FAEST_192_R * Nstbits,
                                   params);
    } else {
      // ::27-28
      memcpy(s_tilde, &w[((Nstbits / 2) + (Nstbits / 2) * 3 * r) / 8], Nstbytes);
      memcpy(s_tilde_tag, &w_tag[((Nstbits / 2) + (Nstbits / 2) * 3 * r)],
             Nstbits * sizeof(bf192_t));
    }

    // ::29
    uint8_t* s_dash_dash     = malloc(Nstbytes);
    bf192_t* s_dash_dash_tag = BF192_ALLOC(Nstbits);
    assert(s_dash_dash);
    assert(s_dash_dash_tag);
    aes_192_inverse_shiftrows_prover(s_dash_dash, s_dash_dash_tag, s_tilde, s_tilde_tag, params);
    // ::30
    uint8_t* s     = malloc(Nstbytes);
    bf192_t* s_tag = BF192_ALLOC(Nstbits);
    assert(s);
    assert(s_tag);
    aes_192_inverse_affine_prover(s, s_tag, s_dash_dash, s_dash_dash_tag, params);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      bf192_t s_deg1 = bf192_byte_combine_bits(s[byte_i]);
      bf192_t s_deg0 = bf192_byte_combine(s_tag + 8 * byte_i);
      // ::33
      bf192_t s_sq_deg1 = bf192_byte_combine_bits_sq(s[byte_i]);
      bf192_t s_sq_deg0 = bf192_byte_combine_sq(s_tag + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    deg0: s_sq[0] * st[0]
      //    deg1: s_sq[0] * st[1] + s_sq[1] * st[0]
      //    deg2: s_sq[0] * st[2] + s_sq[1] * st[1] + s[0]
      //
      zk_hash_192_3_update(hasher, bf192_mul(s_sq_deg0, st_b_deg0[0][byte_i]),
                           bf192_add(bf192_mul(s_sq_deg0, st_b_deg1[0][byte_i]),
                                     bf192_mul(s_sq_deg1, st_b_deg0[0][byte_i])),
                           bf192_add(bf192_add(bf192_mul(s_sq_deg0, st_b_deg2[0][byte_i]),
                                               bf192_mul(s_sq_deg1, st_b_deg1[0][byte_i])),
                                     s_deg0));

      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    deg0: s[0] * st_{1,i}[0]
      //    deg1: s[0] * st_{1,i}[1] + s[1] * st_{1,i}[0] + st_{0,i}[0]
      //    deg2: s[0] * st_{1,i}[2] + s[1] * st_{1,i}[1] + st_{0,i}[1]
      //
      zk_hash_192_3_update(hasher, bf192_mul(s_deg0, st_b_deg0[1][byte_i]),
                           bf192_add(bf192_add(bf192_mul(s_deg0, st_b_deg1[1][byte_i]),
                                               bf192_mul(s_deg1, st_b_deg0[1][byte_i])),
                                     st_b_deg0[0][byte_i]),
                           bf192_add(bf192_add(bf192_mul(s_deg0, st_b_deg2[1][byte_i]),
                                               bf192_mul(s_deg1, st_b_deg1[1][byte_i])),
                                     st_b_deg1[0][byte_i]));
    }
    if (r != (FAEST_192_R / 2) - 1) {
      uint8_t* tmp_state     = s;
      bf192_t* tmp_state_tag = s_tag;
      aes_192_bitwise_mix_column_prover(tmp_state, tmp_state_tag, s_tilde, s_tilde_tag, params);
      aes_192_add_round_key_prover(state_bits, state_bits_tag, tmp_state, tmp_state_tag,
                                   k + (2 * r + 2) * Nstbytes, k_tag + (2 * r + 2) * Nstbits,
                                   params);
    }

    faest_aligned_free(s_tilde_tag);
    faest_aligned_free(s_dash_dash_tag);
    faest_aligned_free(s_tag);
    free(s_tilde);
    free(s_dash_dash);
    free(s);
  }

  faest_aligned_free(st_dash_deg0);
  faest_aligned_free(st_dash_deg1);
  faest_aligned_free(st_dash_deg2);
  faest_aligned_free(state_conj_tag);
  faest_aligned_free(state_conj);
  faest_aligned_free(state_bits_tag);
  free(state_bits);
}

static void aes_256_enc_constraints_prover(zk_hash_256_3_ctx* hasher, const uint8_t* owf_in,
                                           const bf256_t* owf_in_tag, const uint8_t* owf_out,
                                           const bf256_t* owf_out_tag, const uint8_t* w,
                                           const bf256_t* w_tag, const uint8_t* k,
                                           const bf256_t* k_tag, const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  /// ::1 AddFAEST_256_RoundKey
  uint8_t* state_bits     = malloc(Nstbytes);
  bf256_t* state_bits_tag = BF256_ALLOC(Nstbits);
  assert(state_bits);
  assert(state_bits_tag);

  aes_256_add_round_key_prover(state_bits, state_bits_tag, owf_in, owf_in_tag, k, k_tag, params);

  // for conjugates of state and s-box outputs
  bf256_t* state_conj     = BF256_ALLOC(8 * Nstbytes);
  bf256_t* state_conj_tag = BF256_ALLOC(8 * Nstbytes);
  bf256_t* st_dash_deg2   = BF256_ALLOC(8 * Nstbytes);
  bf256_t* st_dash_deg1   = BF256_ALLOC(8 * Nstbytes);
  bf256_t* st_dash_deg0   = BF256_ALLOC(8 * Nstbytes);
  assert(state_conj);
  assert(state_conj_tag);
  assert(st_dash_deg2);
  assert(st_dash_deg1);
  assert(st_dash_deg0);

  // ::2
  for (unsigned int r = 0; r < FAEST_256_R / 2; r++) {
    // ::3-4
    aes_256_f256_f2_conjugates_1(state_conj, state_bits, params);
    aes_256_f256_f2_conjugates_256(state_conj_tag, state_bits_tag, params);

    // ::5-6 : start of norms in witness
    const bf256_t* norm_tags_ptr = w_tag + 3 * Nstbits * r / 2;
    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::5-6 norms in witness
      const uint8_t norm = (w[(3 * Nstbits * r / 2 + 4 * i) / 8] >> ((i % 2) * 4)) & 0xf;

      // ::8-9
      bf256_t y[4];
      bf256_t y_tag[4];
      aes_256_inv_norm_to_conjugates_prover(y, y_tag, norm, norm_tags_ptr + 4 * i);

      // ::10-11
      aes_256_inv_norm_constraints_prover(hasher, state_conj + 8 * i, state_conj_tag + 8 * i, y,
                                          y_tag);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_deg2[i * 8 + j] = bf256_mul(state_conj[conj_index], y[y_index]);
        st_dash_deg1[i * 8 + j] = bf256_add(bf256_mul(state_conj[conj_index], y_tag[y_index]),
                                            bf256_mul(state_conj_tag[conj_index], y[y_index]));
        st_dash_deg0[i * 8 + j] = bf256_mul(state_conj_tag[conj_index], y_tag[y_index]);
      }
    }

    // ::15-16
    bf256_t k_0_deg0[FAEST_256_LAMBDA / 8];
    bf256_t k_0_deg1[FAEST_256_LAMBDA / 8];
    aes_256_state_to_bytes_prover(k_0_deg1, k_0_deg0, k + (2 * r + 1) * Nstbytes,
                                  k_tag + (2 * r + 1) * Nstbits, params);

    // ::17
    bf256_t k_1_deg0[FAEST_256_LAMBDA / 8];
    bf256_t k_1_deg2[FAEST_256_LAMBDA / 8];
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_deg0[byte_i] = bf256_mul(k_0_deg0[byte_i], k_0_deg0[byte_i]);
      k_1_deg2[byte_i] = bf256_mul(k_0_deg1[byte_i], k_0_deg1[byte_i]);
    }

    // ::18
    bf256_t st_b_deg0[2][FAEST_256_LAMBDA / 8];
    bf256_t st_b_deg1[2][FAEST_256_LAMBDA / 8];
    bf256_t st_b_deg2[2][FAEST_256_LAMBDA / 8];
    memset(st_b_deg0, 0x00, sizeof(st_b_deg0));
    memset(st_b_deg1, 0x00, sizeof(st_b_deg1));
    memset(st_b_deg2, 0x00, sizeof(st_b_deg2));

    for (unsigned int b = 0; b < 2; b++) {
      bf256_t st_b_deg0_tmp[FAEST_256_LAMBDA / 8];
      bf256_t st_b_deg1_tmp[FAEST_256_LAMBDA / 8];
      bf256_t st_b_deg2_tmp[FAEST_256_LAMBDA / 8];
      memset(st_b_deg0_tmp, 0x00, sizeof(st_b_deg0_tmp));
      memset(st_b_deg1_tmp, 0x00, sizeof(st_b_deg1_tmp));
      memset(st_b_deg2_tmp, 0x00, sizeof(st_b_deg2_tmp));

      // ::19
      aes_256_sbox_affine_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_dash_deg0,
                                 st_dash_deg1, st_dash_deg2, b, params);
      // ::20
      aes_256_shiftrows_prover(st_b_deg0_tmp, st_b_deg1_tmp, st_b_deg2_tmp, st_b_deg0[b],
                               st_b_deg1[b], st_b_deg2[b], params);
      // ::21
      aes_256_mix_columns_prover(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b], st_b_deg0_tmp,
                                 st_b_deg1_tmp, st_b_deg2_tmp, b, params);
      // ::22
      if (b == 0) {
        aes_256_add_round_key_bytes_prover_degree_1(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_0_deg0, k_0_deg1, params);
      } else {
        aes_256_add_round_key_bytes_prover_degree_2(st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    st_b_deg0[b], st_b_deg1[b], st_b_deg2[b],
                                                    k_1_deg0, k_1_deg2, params);
      }
    }

    // ::23-24
    uint8_t* s_tilde     = malloc(Nstbytes);
    bf256_t* s_tilde_tag = BF256_ALLOC(Nstbits);
    assert(s_tilde);
    assert(s_tilde_tag);

    if (r == FAEST_256_R / 2 - 1) {
      // ::25
      aes_256_add_round_key_prover(s_tilde, s_tilde_tag, owf_out, owf_out_tag,
                                   k + FAEST_256_R * Nstbytes, k_tag + FAEST_256_R * Nstbits,
                                   params);
    } else {
      // ::27-28
      memcpy(s_tilde, &w[((Nstbits / 2) + (Nstbits / 2) * 3 * r) / 8], Nstbytes);
      memcpy(s_tilde_tag, &w_tag[((Nstbits / 2) + (Nstbits / 2) * 3 * r)],
             Nstbits * sizeof(bf256_t));
    }

    // ::29
    uint8_t* s_dash_dash     = malloc(Nstbytes);
    bf256_t* s_dash_dash_tag = BF256_ALLOC(Nstbits);
    assert(s_dash_dash);
    assert(s_dash_dash_tag);
    aes_256_inverse_shiftrows_prover(s_dash_dash, s_dash_dash_tag, s_tilde, s_tilde_tag, params);
    // ::30
    uint8_t* s     = malloc(Nstbytes);
    bf256_t* s_tag = BF256_ALLOC(Nstbits);
    assert(s);
    assert(s_tag);
    aes_256_inverse_affine_prover(s, s_tag, s_dash_dash, s_dash_dash_tag, params);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      bf256_t s_deg1 = bf256_byte_combine_bits(s[byte_i]);
      bf256_t s_deg0 = bf256_byte_combine(s_tag + 8 * byte_i);
      // ::33
      bf256_t s_sq_deg1 = bf256_byte_combine_bits_sq(s[byte_i]);
      bf256_t s_sq_deg0 = bf256_byte_combine_sq(s_tag + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    deg0: s_sq[0] * st[0]
      //    deg1: s_sq[0] * st[1] + s_sq[1] * st[0]
      //    deg2: s_sq[0] * st[2] + s_sq[1] * st[1] + s[0]
      //
      zk_hash_256_3_update(hasher, bf256_mul(s_sq_deg0, st_b_deg0[0][byte_i]),
                           bf256_add(bf256_mul(s_sq_deg0, st_b_deg1[0][byte_i]),
                                     bf256_mul(s_sq_deg1, st_b_deg0[0][byte_i])),
                           bf256_add(bf256_add(bf256_mul(s_sq_deg0, st_b_deg2[0][byte_i]),
                                               bf256_mul(s_sq_deg1, st_b_deg1[0][byte_i])),
                                     s_deg0));

      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    deg0: s[0] * st_{1,i}[0]
      //    deg1: s[0] * st_{1,i}[1] + s[1] * st_{1,i}[0] + st_{0,i}[0]
      //    deg2: s[0] * st_{1,i}[2] + s[1] * st_{1,i}[1] + st_{0,i}[1]
      //
      zk_hash_256_3_update(hasher, bf256_mul(s_deg0, st_b_deg0[1][byte_i]),
                           bf256_add(bf256_add(bf256_mul(s_deg0, st_b_deg1[1][byte_i]),
                                               bf256_mul(s_deg1, st_b_deg0[1][byte_i])),
                                     st_b_deg0[0][byte_i]),
                           bf256_add(bf256_add(bf256_mul(s_deg0, st_b_deg2[1][byte_i]),
                                               bf256_mul(s_deg1, st_b_deg1[1][byte_i])),
                                     st_b_deg1[0][byte_i]));
    }
    if (r != (FAEST_256_R / 2) - 1) {
      uint8_t* tmp_state     = s;
      bf256_t* tmp_state_tag = s_tag;
      aes_256_bitwise_mix_column_prover(tmp_state, tmp_state_tag, s_tilde, s_tilde_tag, params);
      aes_256_add_round_key_prover(state_bits, state_bits_tag, tmp_state, tmp_state_tag,
                                   k + (2 * r + 2) * Nstbytes, k_tag + (2 * r + 2) * Nstbits,
                                   params);
    }

    faest_aligned_free(s_tilde_tag);
    faest_aligned_free(s_dash_dash_tag);
    faest_aligned_free(s_tag);
    free(s_tilde);
    free(s_dash_dash);
    free(s);
  }

  faest_aligned_free(st_dash_deg0);
  faest_aligned_free(st_dash_deg1);
  faest_aligned_free(st_dash_deg2);
  faest_aligned_free(state_conj_tag);
  faest_aligned_free(state_conj);
  faest_aligned_free(state_bits_tag);
  free(state_bits);
}

static void aes_128_enc_constraints_verifier(zk_hash_128_ctx* hasher, const bf128_t* owf_in_key,
                                             const bf128_t* owf_out_key, const bf128_t* w_key,
                                             const bf128_t* rkeys_key, const bf128_t delta,
                                             const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  bf128_t* state_bits_key = BF128_ALLOC(Nstbits);
  assert(state_bits_key);

  /// ::1 AddFAEST_128_RoundKey
  aes_128_add_round_key_verifier(state_bits_key, owf_in_key, rkeys_key, params);

  // for conjugates of state and s-box outputs
  bf128_t* state_conj_key = BF128_ALLOC(8 * Nstbytes);
  bf128_t* st_dash_key    = BF128_ALLOC(8 * Nstbytes);
  assert(state_conj_key);
  assert(st_dash_key);

  // ::2
  for (unsigned int r = 0; r < FAEST_128_R / 2; r++) {
    // ::3-4
    aes_128_f256_f2_conjugates_128(state_conj_key, state_bits_key, params);

    // ::5-6 : start of norms in witness
    const bf128_t* norm_keys_ptr = w_key + 3 * Nstbits * r / 2;

    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::8-9
      bf128_t y_key[4];
      aes_128_inv_norm_to_conjugates_verifier(y_key, norm_keys_ptr + 4 * i);

      // ::10-11
      aes_128_inv_norm_constraints_verifier(hasher, state_conj_key + 8 * i, y_key, delta);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_key[i * 8 + j]  = bf128_mul(state_conj_key[conj_index], y_key[y_index]);
      }
    }

    // ::15-16
    bf128_t k_0_key[FAEST_128_LAMBDA / 8];
    bf128_t k_1_key[FAEST_128_LAMBDA / 8];
    aes_128_state_to_bytes_verifier(k_0_key, rkeys_key + (2 * r + 1) * Nstbits, params);
    // ::17
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_key[byte_i] = bf128_mul(k_0_key[byte_i], k_0_key[byte_i]);
    }

    // ::18
    bf128_t st_b_key[2][FAEST_128_LAMBDA / 8];
    memset(st_b_key, 0x00, sizeof(st_b_key));
    for (unsigned int b = 0; b < 2; b++) {
      bf128_t st_b_tmp_key[16];
      memset(st_b_tmp_key, 0x00, sizeof(st_b_tmp_key));

      // ::19
      aes_128_sbox_affine_verifier(st_b_key[b], st_dash_key, delta, b, params);
      // ::20
      aes_128_shiftrows_verifier(st_b_tmp_key, st_b_key[b], params);
      // ::21
      aes_128_mix_columns_verifier(st_b_key[b], st_b_tmp_key, b, params);
      // ::22
      if (b == 0) {
        aes_128_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_0_key, delta, true,
                                             params);
      } else {
        aes_128_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_1_key, delta, false,
                                             params);
      }
    }
    // ::23-24
    bf128_t* s_tilde_key = BF128_ALLOC(Nstbits);
    assert(s_tilde_key);
    if (r == FAEST_128_R / 2 - 1) {
      // ::25
      aes_128_add_round_key_verifier(s_tilde_key, owf_out_key, rkeys_key + FAEST_128_R * Nstbits,
                                     params);
    } else {
      // ::27-28
      memcpy(s_tilde_key, w_key + (Nstbits / 2) + (Nstbits / 2) * 3 * r, Nstbits * sizeof(bf128_t));
    }
    // ::29
    bf128_t* s_dash_dash_key = BF128_ALLOC(Nstbits);
    aes_128_inverse_shiftrows_verifier(s_dash_dash_key, s_tilde_key, params);
    assert(s_dash_dash_key);
    // ::30
    bf128_t* s_state_key = BF128_ALLOC(Nstbits);
    aes_128_inverse_affine_verifier(s_state_key, s_dash_dash_key, delta, params);
    assert(s_state_key);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      const bf128_t s_key = bf128_byte_combine(s_state_key + 8 * byte_i);
      // ::33
      const bf128_t s_sq_key = bf128_byte_combine_sq(s_state_key + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    s_sq * st_{0,i} + delta^2 * s
      //
      zk_hash_128_update(hasher, bf128_add(bf128_mul(s_sq_key, st_b_key[0][byte_i]),
                                           bf128_mul(delta, bf128_mul(delta, s_key))));
      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    s * st_{1,i} + delta * st_{0,i}
      //
      zk_hash_128_update(hasher, bf128_add(bf128_mul(s_key, st_b_key[1][byte_i]),
                                           bf128_mul(delta, st_b_key[0][byte_i])));
    }
    if (r != (FAEST_128_R / 2) - 1) {
      bf128_t* tmp_state_key = s_state_key;
      aes_128_bitwise_mix_column_verifier(tmp_state_key, s_tilde_key, params);
      aes_128_add_round_key_verifier(state_bits_key, tmp_state_key,
                                     rkeys_key + (2 * r + 2) * Nstbits, params);
    }
    faest_aligned_free(s_tilde_key);
    faest_aligned_free(s_dash_dash_key);
    faest_aligned_free(s_state_key);
  }
  faest_aligned_free(st_dash_key);
  faest_aligned_free(state_conj_key);
  faest_aligned_free(state_bits_key);
}

static void aes_192_enc_constraints_verifier(zk_hash_192_ctx* hasher, const bf192_t* owf_in_key,
                                             const bf192_t* owf_out_key, const bf192_t* w_key,
                                             const bf192_t* rkeys_key, const bf192_t delta,
                                             const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  bf192_t* state_bits_key = BF192_ALLOC(Nstbits);
  assert(state_bits_key);

  /// ::1 AddFAEST_192_RoundKey
  aes_192_add_round_key_verifier(state_bits_key, owf_in_key, rkeys_key, params);

  // for conjugates of state and s-box outputs
  bf192_t* state_conj_key = BF192_ALLOC(8 * Nstbytes);
  bf192_t* st_dash_key    = BF192_ALLOC(8 * Nstbytes);
  assert(state_conj_key);
  assert(st_dash_key);

  // ::2
  for (unsigned int r = 0; r < FAEST_192_R / 2; r++) {
    // ::3-4
    aes_192_f256_f2_conjugates_192(state_conj_key, state_bits_key, params);

    // ::5-6 : start of norms in witness
    const bf192_t* norm_keys_ptr = w_key + 3 * Nstbits * r / 2;

    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::8-9
      bf192_t y_key[4];
      aes_192_inv_norm_to_conjugates_verifier(y_key, norm_keys_ptr + 4 * i);

      // ::10-11
      aes_192_inv_norm_constraints_verifier(hasher, state_conj_key + 8 * i, y_key, delta);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_key[i * 8 + j]  = bf192_mul(state_conj_key[conj_index], y_key[y_index]);
      }
    }

    // ::15-16
    bf192_t k_0_key[FAEST_192_LAMBDA / 8];
    bf192_t k_1_key[FAEST_192_LAMBDA / 8];
    aes_192_state_to_bytes_verifier(k_0_key, rkeys_key + (2 * r + 1) * Nstbits, params);
    // ::17
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_key[byte_i] = bf192_mul(k_0_key[byte_i], k_0_key[byte_i]);
    }

    // ::18
    bf192_t st_b_key[2][FAEST_192_LAMBDA / 8];
    memset(st_b_key, 0x00, sizeof(st_b_key));
    for (unsigned int b = 0; b < 2; b++) {
      bf192_t st_b_tmp_key[FAEST_192_LAMBDA / 8];
      memset(st_b_tmp_key, 0x00, sizeof(st_b_tmp_key));

      // ::19
      aes_192_sbox_affine_verifier(st_b_key[b], st_dash_key, delta, b, params);
      // ::20
      aes_192_shiftrows_verifier(st_b_tmp_key, st_b_key[b], params);
      // ::21
      aes_192_mix_columns_verifier(st_b_key[b], st_b_tmp_key, b, params);
      // ::22
      if (b == 0) {
        aes_192_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_0_key, delta, true,
                                             params);
      } else {
        aes_192_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_1_key, delta, false,
                                             params);
      }
    }
    // ::23-24
    bf192_t* s_tilde_key = BF192_ALLOC(Nstbits);
    assert(s_tilde_key);
    if (r == FAEST_192_R / 2 - 1) {
      // ::25
      aes_192_add_round_key_verifier(s_tilde_key, owf_out_key, rkeys_key + FAEST_192_R * Nstbits,
                                     params);
    } else {
      // ::27-28
      memcpy(s_tilde_key, w_key + (Nstbits / 2) + (Nstbits / 2) * 3 * r, Nstbits * sizeof(bf192_t));
    }
    // ::29
    bf192_t* s_dash_dash_key = BF192_ALLOC(Nstbits);
    assert(s_dash_dash_key);
    aes_192_inverse_shiftrows_verifier(s_dash_dash_key, s_tilde_key, params);
    // ::30
    bf192_t* s_state_key = BF192_ALLOC(Nstbits);
    assert(s_state_key);
    aes_192_inverse_affine_verifier(s_state_key, s_dash_dash_key, delta, params);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      const bf192_t s_key = bf192_byte_combine(s_state_key + 8 * byte_i);
      // ::33
      const bf192_t s_sq_key = bf192_byte_combine_sq(s_state_key + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    s_sq * st_{0,i} + delta^2 * s
      //
      zk_hash_192_update(hasher, bf192_add(bf192_mul(s_sq_key, st_b_key[0][byte_i]),
                                           bf192_mul(delta, bf192_mul(delta, s_key))));
      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    s * st_{1,i} + delta * st_{0,i}
      //
      zk_hash_192_update(hasher, bf192_add(bf192_mul(s_key, st_b_key[1][byte_i]),
                                           bf192_mul(delta, st_b_key[0][byte_i])));
    }
    if (r != (FAEST_192_R / 2) - 1) {
      bf192_t* tmp_state_key = s_state_key;
      aes_192_bitwise_mix_column_verifier(tmp_state_key, s_tilde_key, params);
      aes_192_add_round_key_verifier(state_bits_key, tmp_state_key,
                                     rkeys_key + (2 * r + 2) * Nstbits, params);
    }
    faest_aligned_free(s_tilde_key);
    faest_aligned_free(s_dash_dash_key);
    faest_aligned_free(s_state_key);
  }
  faest_aligned_free(st_dash_key);
  faest_aligned_free(state_conj_key);
  faest_aligned_free(state_bits_key);
}

static void aes_256_enc_constraints_verifier(zk_hash_256_ctx* hasher, const bf256_t* owf_in_key,
                                             const bf256_t* owf_out_key, const bf256_t* w_key,
                                             const bf256_t* rkeys_key, const bf256_t delta,
                                             const faest_paramset_t* params) {
  const unsigned int Nst      = params->Nst;
  const unsigned int Nstbits  = 32 * Nst;
  const unsigned int Nstbytes = Nstbits / 8;

  bf256_t* state_bits_key = BF256_ALLOC(Nstbits);
  assert(state_bits_key);

  /// ::1 AddFAEST_256_RoundKey
  aes_256_add_round_key_verifier(state_bits_key, owf_in_key, rkeys_key, params);

  // for conjugates of state and s-box outputs
  bf256_t* state_conj_key = BF256_ALLOC(8 * Nstbytes);
  bf256_t* st_dash_key    = BF256_ALLOC(8 * Nstbytes);
  assert(state_conj_key);
  assert(st_dash_key);

  // ::2
  for (unsigned int r = 0; r < FAEST_256_R / 2; r++) {
    // ::3-4
    aes_256_f256_f2_conjugates_256(state_conj_key, state_bits_key, params);

    // ::5-6 : start of norms in witness
    const bf256_t* norm_keys_ptr = w_key + 3 * Nstbits * r / 2;

    // ::7
    for (unsigned int i = 0; i < Nstbytes; i++) {
      // ::8-9
      bf256_t y_key[4];
      aes_256_inv_norm_to_conjugates_verifier(y_key, norm_keys_ptr + 4 * i);

      // ::10-11
      aes_256_inv_norm_constraints_verifier(hasher, state_conj_key + 8 * i, y_key, delta);

      // ::12
      for (unsigned int j = 0; j < 8; j++) {
        // ::13-14
        unsigned int conj_index = i * 8 + ((j + 4) % 8);
        unsigned int y_index    = j % 4;
        st_dash_key[i * 8 + j]  = bf256_mul(state_conj_key[conj_index], y_key[y_index]);
      }
    }

    // ::15-16
    bf256_t k_0_key[FAEST_256_LAMBDA / 8];
    bf256_t k_1_key[FAEST_256_LAMBDA / 8];
    aes_256_state_to_bytes_verifier(k_0_key, rkeys_key + (2 * r + 1) * Nstbits, params);
    // ::17
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      k_1_key[byte_i] = bf256_mul(k_0_key[byte_i], k_0_key[byte_i]);
    }

    // ::18
    bf256_t st_b_key[2][FAEST_256_LAMBDA / 8];
    memset(st_b_key, 0x00, sizeof(st_b_key));
    for (unsigned int b = 0; b < 2; b++) {
      bf256_t st_b_tmp_key[FAEST_256_LAMBDA / 8];
      memset(st_b_tmp_key, 0x00, sizeof(st_b_tmp_key));

      // ::19
      aes_256_sbox_affine_verifier(st_b_key[b], st_dash_key, delta, b, params);
      // ::20
      aes_256_shiftrows_verifier(st_b_tmp_key, st_b_key[b], params);
      // ::21
      aes_256_mix_columns_verifier(st_b_key[b], st_b_tmp_key, b, params);
      // ::22
      if (b == 0) {
        aes_256_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_0_key, delta, true,
                                             params);
      } else {
        aes_256_add_round_key_bytes_verifier(st_b_key[b], st_b_key[b], k_1_key, delta, false,
                                             params);
      }
    }
    // ::23-24
    bf256_t* s_tilde_key = BF256_ALLOC(Nstbits);
    assert(s_tilde_key);
    if (r == FAEST_256_R / 2 - 1) {
      // ::25
      aes_256_add_round_key_verifier(s_tilde_key, owf_out_key, rkeys_key + FAEST_256_R * Nstbits,
                                     params);
    } else {
      // ::27-28
      memcpy(s_tilde_key, w_key + (Nstbits / 2) + (Nstbits / 2) * 3 * r, Nstbits * sizeof(bf256_t));
    }
    // ::29
    bf256_t* s_dash_dash_key = BF256_ALLOC(Nstbits);
    assert(s_dash_dash_key);
    aes_256_inverse_shiftrows_verifier(s_dash_dash_key, s_tilde_key, params);
    // ::30
    bf256_t* s_state_key = BF256_ALLOC(Nstbits);
    assert(s_state_key);
    aes_256_inverse_affine_verifier(s_state_key, s_dash_dash_key, delta, params);

    // ::31
    for (unsigned int byte_i = 0; byte_i < Nstbytes; byte_i++) {
      // ::32
      const bf256_t s_key = bf256_byte_combine(s_state_key + 8 * byte_i);
      // ::33
      const bf256_t s_sq_key = bf256_byte_combine_sq(s_state_key + 8 * byte_i);

      // ::36
      // compute <s^sq>^1 * <st_{0,i}>^2 - <s>^1
      //    s_sq * st_{0,i} + delta^2 * s
      //
      zk_hash_256_update(hasher, bf256_add(bf256_mul(s_sq_key, st_b_key[0][byte_i]),
                                           bf256_mul(delta, bf256_mul(delta, s_key))));
      // ::37
      // compute <s>^1 * <st_{1,i}>^2 - <st_{0,i}>^2
      //    s * st_{1,i} + delta * st_{0,i}
      //
      zk_hash_256_update(hasher, bf256_add(bf256_mul(s_key, st_b_key[1][byte_i]),
                                           bf256_mul(delta, st_b_key[0][byte_i])));
    }
    if (r != (FAEST_256_R / 2) - 1) {
      bf256_t* tmp_state_key = s_state_key;
      aes_256_bitwise_mix_column_verifier(tmp_state_key, s_tilde_key, params);
      aes_256_add_round_key_verifier(state_bits_key, tmp_state_key,
                                     rkeys_key + (2 * r + 2) * Nstbits, params);
    }
    faest_aligned_free(s_tilde_key);
    faest_aligned_free(s_dash_dash_key);
    faest_aligned_free(s_state_key);
  }
  faest_aligned_free(st_dash_key);
  faest_aligned_free(state_conj_key);
  faest_aligned_free(state_bits_key);
}

// OWF CONSTRAINTS
static void aes_128_constraints_prover(zk_hash_128_3_ctx* hasher, const uint8_t* w,
                                       const bf128_t* w_tag, const uint8_t* owf_in,
                                       const uint8_t* owf_out, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * params->Nst;
  const unsigned int beta      = (FAEST_128_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_128_3_raise_and_update(hasher, bf128_mul(w_tag[0], w_tag[1]),
                                 bf128_add(bf128_mul_bit(w_tag[0], ptr_get_bit(w, 1)),
                                           bf128_mul_bit(w_tag[1], ptr_get_bit(w, 0))));

  // ::7-8
  uint8_t* in        = malloc(blocksize / 8);
  bf128_t* in_tag    = BF128_ALLOC(blocksize);
  uint8_t* out       = malloc(beta * blocksize / 8);
  bf128_t* out_tag   = BF128_ALLOC(beta * blocksize);
  uint8_t* rkeys     = malloc((FAEST_128_R + 1) * blocksize / 8);
  bf128_t* rkeys_tag = BF128_ALLOC((FAEST_128_R + 1) * blocksize);
  assert(in);
  assert(in_tag);
  assert(out);
  assert(out_tag);
  assert(rkeys);
  assert(rkeys_tag);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_128_NK, FAEST_128_NK, FAEST_128_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_128_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; ++i, ++idx) {
          rkeys[idx] = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_tag[8 * idx + j] = bf128_zero();
          }
        }
      }
    }

    // ::10
    memcpy(in, w, blocksize / 8);
    memcpy(in_tag, w_tag, blocksize * sizeof(bf128_t));
    // ::11
    xor_u8_array(w, owf_out, out, blocksize / 8);
    memcpy(out_tag, w_tag, blocksize * sizeof(bf128_t));
  } else {
    // jump to ::13 for AES
    memcpy(in, owf_in, blocksize / 8);
    constant_to_vole_128_prover(in_tag, blocksize);

    // ::14
    memcpy(out, owf_out, beta * blocksize / 8);
    constant_to_vole_128_prover(out_tag, beta * blocksize);

    // ::15 skiped as B = 1
    // ::16
    aes_128_expkey_constraints_prover(hasher, rkeys, rkeys_tag, w, w_tag, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    if (b == 1) {
      in[0] = in[0] ^ 0x01;
    }

    aes_128_enc_constraints_prover(hasher, in, in_tag, out + b * blocksize / 8,
                                   out_tag + b * blocksize, w + (Lke + b * Lenc) / 8,
                                   w_tag + Lke + b * Lenc, rkeys, rkeys_tag, params);
  }

  free(in);
  faest_aligned_free(in_tag);
  free(out);
  faest_aligned_free(out_tag);
  free(rkeys);
  faest_aligned_free(rkeys_tag);
}

static void aes_192_constraints_prover(zk_hash_192_3_ctx* hasher, const uint8_t* w,
                                       const bf192_t* w_tag, const uint8_t* owf_in,
                                       const uint8_t* owf_out, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * params->Nst;
  const unsigned int beta      = (FAEST_192_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_192_3_raise_and_update(hasher, bf192_mul(w_tag[0], w_tag[1]),
                                 bf192_add(bf192_mul_bit(w_tag[0], ptr_get_bit(w, 1)),
                                           bf192_mul_bit(w_tag[1], ptr_get_bit(w, 0))));

  // ::7-8
  uint8_t* in        = malloc(blocksize / 8);
  bf192_t* in_tag    = BF192_ALLOC(blocksize);
  uint8_t* out       = malloc(beta * blocksize / 8);
  bf192_t* out_tag   = BF192_ALLOC(beta * blocksize);
  uint8_t* rkeys     = malloc((FAEST_192_R + 1) * blocksize / 8);
  bf192_t* rkeys_tag = BF192_ALLOC((FAEST_192_R + 1) * blocksize);
  assert(in);
  assert(in_tag);
  assert(out);
  assert(out_tag);
  assert(rkeys);
  assert(rkeys_tag);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_192_NK, FAEST_192_NK, FAEST_192_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_192_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; ++i, ++idx) {
          rkeys[idx] = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_tag[8 * idx + j] = bf192_zero();
          }
        }
      }
    }

    // ::10
    memcpy(in, w, blocksize / 8);
    memcpy(in_tag, w_tag, blocksize * sizeof(bf192_t));
    // ::11
    xor_u8_array(w, owf_out, out, blocksize / 8);
    memcpy(out_tag, w_tag, blocksize * sizeof(bf192_t));
  } else {
    // jump to ::13 for AES
    memcpy(in, owf_in, blocksize / 8);
    constant_to_vole_192_prover(in_tag, blocksize);

    // ::14
    memcpy(out, owf_out, beta * blocksize / 8);
    constant_to_vole_192_prover(out_tag, beta * blocksize);

    // ::15 skiped as B = 1
    // ::16
    aes_192_expkey_constraints_prover(hasher, rkeys, rkeys_tag, w, w_tag, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    if (b == 1) {
      in[0] = in[0] ^ 0x01;
    }

    aes_192_enc_constraints_prover(hasher, in, in_tag, out + b * blocksize / 8,
                                   out_tag + b * blocksize, w + (Lke + b * Lenc) / 8,
                                   w_tag + Lke + b * Lenc, rkeys, rkeys_tag, params);
  }

  free(in);
  faest_aligned_free(in_tag);
  free(out);
  faest_aligned_free(out_tag);
  free(rkeys);
  faest_aligned_free(rkeys_tag);
}

static void aes_256_constraints_prover(zk_hash_256_3_ctx* hasher, const uint8_t* w,
                                       const bf256_t* w_tag, const uint8_t* owf_in,
                                       const uint8_t* owf_out, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * params->Nst;
  const unsigned int beta      = (FAEST_256_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_256_3_raise_and_update(hasher, bf256_mul(w_tag[0], w_tag[1]),
                                 bf256_add(bf256_mul_bit(w_tag[0], ptr_get_bit(w, 1)),
                                           bf256_mul_bit(w_tag[1], ptr_get_bit(w, 0))));

  // ::7-8
  uint8_t* in        = malloc(blocksize / 8);
  bf256_t* in_tag    = BF256_ALLOC(blocksize);
  uint8_t* out       = malloc(beta * blocksize / 8);
  bf256_t* out_tag   = BF256_ALLOC(beta * blocksize);
  uint8_t* rkeys     = malloc((FAEST_256_R + 1) * blocksize / 8);
  bf256_t* rkeys_tag = BF256_ALLOC((FAEST_256_R + 1) * blocksize);
  assert(in);
  assert(in_tag);
  assert(out);
  assert(out_tag);
  assert(rkeys);
  assert(rkeys_tag);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_256_NK, FAEST_256_NK, FAEST_256_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_256_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; ++i, ++idx) {
          rkeys[idx] = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_tag[8 * idx + j] = bf256_zero();
          }
        }
      }
    }

    // ::10
    memcpy(in, w, blocksize / 8);
    memcpy(in_tag, w_tag, blocksize * sizeof(bf256_t));
    // ::11
    xor_u8_array(w, owf_out, out, blocksize / 8);
    memcpy(out_tag, w_tag, blocksize * sizeof(bf256_t));
  } else {
    // jump to ::13 for AES
    memcpy(in, owf_in, blocksize / 8);
    constant_to_vole_256_prover(in_tag, blocksize);

    // ::14
    memcpy(out, owf_out, beta * blocksize / 8);
    constant_to_vole_256_prover(out_tag, beta * blocksize);

    // ::15 skiped as B = 1
    // ::16
    aes_256_expkey_constraints_prover(hasher, rkeys, rkeys_tag, w, w_tag, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    if (b == 1) {
      in[0] = in[0] ^ 0x01;
    }

    aes_256_enc_constraints_prover(hasher, in, in_tag, out + b * blocksize / 8,
                                   out_tag + b * blocksize, w + (Lke + b * Lenc) / 8,
                                   w_tag + Lke + b * Lenc, rkeys, rkeys_tag, params);
  }

  free(in);
  faest_aligned_free(in_tag);
  free(out);
  faest_aligned_free(out_tag);
  free(rkeys);
  faest_aligned_free(rkeys_tag);
}

// OWF CONSTRAINTS VERIFIER
static void aes_128_constraints_verifier(zk_hash_128_ctx* hasher, const bf128_t* w_key,
                                         const uint8_t* owf_in, const uint8_t* owf_out,
                                         bf128_t delta, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * Nst;
  const unsigned int beta      = (FAEST_128_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_128_update(hasher, bf128_mul(delta, bf128_mul(w_key[0], w_key[1])));

  // ::7-8
  bf128_t* rkeys_key = BF128_ALLOC((FAEST_128_R + 1) * blocksize);
  bf128_t* in_key    = BF128_ALLOC(blocksize);
  bf128_t* out_key   = BF128_ALLOC(beta * blocksize);
  assert(rkeys_key);
  assert(in_key);
  assert(out_key);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_128_NK, FAEST_128_NK, FAEST_128_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_128_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; i++) {
          uint8_t rk_byte = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_key[8 * idx + j] = bf128_mul_bit(delta, get_bit(rk_byte, j));
          }
          idx++;
        }
      }
    }
    // ::10-11
    memcpy(in_key, w_key, blocksize * sizeof(bf128_t));
    for (unsigned int i = 0; i < blocksize; i++) {
      out_key[i] = bf128_add(w_key[i], bf128_mul_bit(delta, ptr_get_bit(owf_out, i)));
    }
  } else {
    // jump to ::13 for AES
    constant_to_vole_128_verifier(in_key, owf_in, delta, blocksize);

    // ::14-15
    // if beta=2, load both public key blocks
    constant_to_vole_128_verifier(out_key, owf_out, delta, beta * blocksize);

    // ::16
    aes_128_expkey_constraints_verifier(hasher, rkeys_key, w_key, delta, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    // ::21
    if (b == 1) {
      in_key[0] = bf128_add(in_key[0], delta); // adding one
      out_key += blocksize;
    }
    aes_128_enc_constraints_verifier(hasher, in_key, out_key, w_key + Lke + b * Lenc, rkeys_key,
                                     delta, params);
  }

  faest_aligned_free(rkeys_key);
  faest_aligned_free(in_key);
  faest_aligned_free(out_key);
}

static void aes_192_constraints_verifier(zk_hash_192_ctx* hasher, const bf192_t* w_key,
                                         const uint8_t* owf_in, const uint8_t* owf_out,
                                         bf192_t delta, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * Nst;
  const unsigned int beta      = (FAEST_192_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_192_update(hasher, bf192_mul(delta, bf192_mul(w_key[0], w_key[1])));

  // ::7-8
  bf192_t* rkeys_key = BF192_ALLOC((FAEST_192_R + 1) * blocksize);
  bf192_t* in_key    = BF192_ALLOC(blocksize);
  bf192_t* out_key   = BF192_ALLOC(beta * blocksize);
  assert(rkeys_key);
  assert(in_key);
  assert(out_key);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_192_NK, FAEST_192_NK, FAEST_192_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_192_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; i++) {
          uint8_t rk_byte = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_key[8 * idx + j] = bf192_mul_bit(delta, get_bit(rk_byte, j));
          }
          idx++;
        }
      }
    }
    // ::10-11
    memcpy(in_key, w_key, blocksize * sizeof(bf192_t));
    for (unsigned int i = 0; i < blocksize; i++) {
      out_key[i] = bf192_add(w_key[i], bf192_mul_bit(delta, ptr_get_bit(owf_out, i)));
    }
  } else {
    // jump to ::13 for AES
    constant_to_vole_192_verifier(in_key, owf_in, delta, blocksize);

    // ::14-15
    // if beta=2, load both public key blocks
    constant_to_vole_192_verifier(out_key, owf_out, delta, beta * blocksize);

    // ::16
    aes_192_expkey_constraints_verifier(hasher, rkeys_key, w_key, delta, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    // ::21
    if (b == 1) {
      in_key[0] = bf192_add(in_key[0], delta); // adding one
    }
    aes_192_enc_constraints_verifier(hasher, in_key, out_key + b * blocksize,
                                     w_key + Lke + b * Lenc, rkeys_key, delta, params);
  }

  faest_aligned_free(rkeys_key);
  faest_aligned_free(in_key);
  faest_aligned_free(out_key);
}

static void aes_256_constraints_verifier(zk_hash_256_ctx* hasher, const bf256_t* w_key,
                                         const uint8_t* owf_in, const uint8_t* owf_out,
                                         bf256_t delta, const faest_paramset_t* params) {
  const unsigned int Lke       = params->Lke;
  const unsigned int Lenc      = params->Lenc;
  const unsigned int Nst       = params->Nst;
  const unsigned int blocksize = 32 * Nst;
  const unsigned int beta      = (FAEST_256_LAMBDA + blocksize - 1) / blocksize;
  // ::1-3 owf_in, owf_out, z and z_tag

  // ::4-5
  zk_hash_256_update(hasher, bf256_mul(delta, bf256_mul(w_key[0], w_key[1])));

  // ::7-8
  bf256_t* rkeys_key = BF256_ALLOC((FAEST_256_R + 1) * blocksize);
  bf256_t* in_key    = BF256_ALLOC(blocksize);
  bf256_t* out_key   = BF256_ALLOC(beta * blocksize);
  assert(rkeys_key);
  assert(in_key);
  assert(out_key);

  if (faest_is_em(params)) {
    aes_round_keys_t round_keys;
    expand_key(&round_keys, owf_in, FAEST_256_NK, FAEST_256_NK, FAEST_256_R);

    unsigned int idx = 0;
    for (unsigned int r = 0; r < FAEST_256_R + 1; r++) {
      for (unsigned int n = 0; n < Nst; n++) {
        for (unsigned int i = 0; i < 4; i++) {
          uint8_t rk_byte = round_keys.round_keys[r][n][i];
          for (unsigned int j = 0; j < 8; j++) {
            rkeys_key[8 * idx + j] = bf256_mul_bit(delta, get_bit(rk_byte, j));
          }
          idx++;
        }
      }
    }
    // ::10-11
    memcpy(in_key, w_key, blocksize * sizeof(bf256_t));
    for (unsigned int i = 0; i < blocksize; i++) {
      out_key[i] = bf256_add(w_key[i], bf256_mul_bit(delta, ptr_get_bit(owf_out, i)));
    }
  } else {
    // jump to ::13 for AES
    constant_to_vole_256_verifier(in_key, owf_in, delta, blocksize);

    // ::14-15
    // if beta=2, load both public key blocks
    constant_to_vole_256_verifier(out_key, owf_out, delta, beta * blocksize);

    // ::16
    aes_256_expkey_constraints_verifier(hasher, rkeys_key, w_key, delta, params);
  }

  // ::18-20
  for (unsigned int b = 0; b < beta; b++) {
    // ::21
    if (b == 1) {
      in_key[0] = bf256_add(in_key[0], delta); // adding one
    }
    aes_256_enc_constraints_verifier(hasher, in_key, out_key + b * blocksize,
                                     w_key + Lke + b * Lenc, rkeys_key, delta, params);
  }

  faest_aligned_free(rkeys_key);
  faest_aligned_free(in_key);
  faest_aligned_free(out_key);
}

// OWF PROVER
static void aes_128_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde,
                           const uint8_t* w, const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                           const uint8_t* owf_out, const uint8_t* chall_2,
                           const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1-5
  // V becomes the w_tag: ell + 2*lambda field elements
  bf128_t* w_tag = column_to_row_major_and_shrink_V_128(V, ell); // This is the tag for w

  // ::6-7 embed VOLE masks
  bf128_t bf_u_star_0 = bf128_sum_poly_bits(u);
  bf128_t bf_u_star_1 = bf128_sum_poly_bits(u + FAEST_128_LAMBDA / 8);

  // ::8-9
  bf128_t bf_v_star_0 = bf128_sum_poly(w_tag + ell);
  bf128_t bf_v_star_1 = bf128_sum_poly(w_tag + ell + FAEST_128_LAMBDA);

  // Step: 13-18
  zk_hash_128_3_ctx hasher;
  zk_hash_128_3_init(&hasher, chall_2);

  aes_128_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params);

  zk_hash_128_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf128_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);

  faest_aligned_free(w_tag);
}

static void aes_192_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde,
                           const uint8_t* w, const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                           const uint8_t* owf_out, const uint8_t* chall_2,
                           const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1-5
  // V becomes the w_tag: ell + 2*lambda field elements
  bf192_t* w_tag = column_to_row_major_and_shrink_V_192(V, ell); // This is the tag for w

  // ::6-7 embed VOLE masks
  bf192_t bf_u_star_0 = bf192_sum_poly_bits(u);
  bf192_t bf_u_star_1 = bf192_sum_poly_bits(u + FAEST_192_LAMBDA / 8);

  // ::8-9
  bf192_t bf_v_star_0 = bf192_sum_poly(w_tag + ell);
  bf192_t bf_v_star_1 = bf192_sum_poly(w_tag + ell + FAEST_192_LAMBDA);

  // Step: 13-18
  zk_hash_192_3_ctx hasher;
  zk_hash_192_3_init(&hasher, chall_2);

  aes_192_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params);

  zk_hash_192_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf192_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);

  faest_aligned_free(w_tag);
}

static void aes_256_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde,
                           const uint8_t* w, const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                           const uint8_t* owf_out, const uint8_t* chall_2,
                           const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1-5
  // V becomes the w_tag: ell + 2*lambda field elements
  bf256_t* w_tag = column_to_row_major_and_shrink_V_256(V, ell); // This is the tag for w

  // ::6-7 embed VOLE masks
  bf256_t bf_u_star_0 = bf256_sum_poly_bits(u);
  bf256_t bf_u_star_1 = bf256_sum_poly_bits(u + FAEST_256_LAMBDA / 8);

  // ::8-9
  bf256_t bf_v_star_0 = bf256_sum_poly(w_tag + ell);
  bf256_t bf_v_star_1 = bf256_sum_poly(w_tag + ell + FAEST_256_LAMBDA);

  // Step: 13-18
  zk_hash_256_3_ctx hasher;
  zk_hash_256_3_init(&hasher, chall_2);

  aes_256_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params);

  zk_hash_256_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf256_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);

  faest_aligned_free(w_tag);
}

// OWF VERIFIER
static void aes_128_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                             const uint8_t* owf_in, const uint8_t* owf_out, const uint8_t* chall_2,
                             const uint8_t* chall_3, const uint8_t* a1_tilde,
                             const uint8_t* a2_tilde, const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1
  bf128_t bf_delta    = bf128_load(chall_3);
  bf128_t bf_delta_sq = bf128_mul(bf_delta, bf_delta);

  // ::2-6
  bf128_t* q_key = column_to_row_major_and_shrink_V_128(Q, ell);

  // ::7-9
  bf128_t q_star_0 = bf128_sum_poly(q_key + ell);
  bf128_t q_star_1 = bf128_sum_poly(q_key + ell + FAEST_128_LAMBDA);

  // ::10
  bf128_t q_star = bf128_add(q_star_0, bf128_mul(bf_delta, q_star_1));

  // ::13-14
  zk_hash_128_ctx b_ctx;
  zk_hash_128_init(&b_ctx, chall_2);

  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf128_add(q_key[i], bf128_mul_bit(bf_delta, ptr_get_bit(d, i)));
  }

  // ::11-12
  aes_128_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);
  faest_aligned_free(q_key);

  // ::13-14
  uint8_t q_tilde[FAEST_128_LAMBDA / 8];
  zk_hash_128_finalize(q_tilde, &b_ctx, q_star);

  // ::16
  bf128_t tmp1 = bf128_mul(bf128_load(a1_tilde), bf_delta);
  bf128_t tmp2 = bf128_mul(bf128_load(a2_tilde), bf_delta_sq);
  bf128_t tmp3 = bf128_add(tmp1, tmp2);
  bf128_t ret  = bf128_add(bf128_load(q_tilde), tmp3);

  bf128_store(a0_tilde, ret);
}

static void aes_192_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                             const uint8_t* owf_in, const uint8_t* owf_out, const uint8_t* chall_2,
                             const uint8_t* chall_3, const uint8_t* a1_tilde,
                             const uint8_t* a2_tilde, const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1
  bf192_t bf_delta    = bf192_load(chall_3);
  bf192_t bf_delta_sq = bf192_mul(bf_delta, bf_delta);

  // ::2-6
  bf192_t* q_key = column_to_row_major_and_shrink_V_192(Q, ell);

  // ::7-9
  bf192_t q_star_0 = bf192_sum_poly(q_key + ell);
  bf192_t q_star_1 = bf192_sum_poly(q_key + ell + FAEST_192_LAMBDA);

  // ::10
  bf192_t q_star = bf192_add(q_star_0, bf192_mul(bf_delta, q_star_1));

  // ::13-14
  zk_hash_192_ctx b_ctx;
  zk_hash_192_init(&b_ctx, chall_2);

  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf192_add(q_key[i], bf192_mul_bit(bf_delta, ptr_get_bit(d, i)));
  }

  // ::11-12
  aes_192_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);
  faest_aligned_free(q_key);

  // ::13-14
  uint8_t q_tilde[FAEST_192_LAMBDA / 8];
  zk_hash_192_finalize(q_tilde, &b_ctx, q_star);

  // ::16
  bf192_t tmp1 = bf192_mul(bf192_load(a1_tilde), bf_delta);
  bf192_t tmp2 = bf192_mul(bf192_load(a2_tilde), bf_delta_sq);
  bf192_t tmp3 = bf192_add(tmp1, tmp2);
  bf192_t ret  = bf192_add(bf192_load(q_tilde), tmp3);

  bf192_store(a0_tilde, ret);
}

static void aes_256_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                             const uint8_t* owf_in, const uint8_t* owf_out, const uint8_t* chall_2,
                             const uint8_t* chall_3, const uint8_t* a1_tilde,
                             const uint8_t* a2_tilde, const faest_paramset_t* params) {
  const unsigned int ell = params->l;

  // ::1
  bf256_t bf_delta    = bf256_load(chall_3);
  bf256_t bf_delta_sq = bf256_mul(bf_delta, bf_delta);

  // ::2-6
  bf256_t* q_key = column_to_row_major_and_shrink_V_256(Q, ell);

  // ::7-9
  bf256_t q_star_0 = bf256_sum_poly(q_key + ell);
  bf256_t q_star_1 = bf256_sum_poly(q_key + ell + FAEST_256_LAMBDA);

  // ::10
  bf256_t q_star = bf256_add(q_star_0, bf256_mul(bf_delta, q_star_1));

  // ::13-14
  zk_hash_256_ctx b_ctx;
  zk_hash_256_init(&b_ctx, chall_2);

  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf256_add(q_key[i], bf256_mul_bit(bf_delta, ptr_get_bit(d, i)));
  }

  // ::11-12
  aes_256_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);
  faest_aligned_free(q_key);

  // ::13-14
  uint8_t q_tilde[FAEST_256_LAMBDA / 8];
  zk_hash_256_finalize(q_tilde, &b_ctx, q_star);

  // ::16
  bf256_t tmp1 = bf256_mul(bf256_load(a1_tilde), bf_delta);
  bf256_t tmp2 = bf256_mul(bf256_load(a2_tilde), bf_delta_sq);
  bf256_t tmp3 = bf256_add(tmp1, tmp2);
  bf256_t ret  = bf256_add(bf256_load(q_tilde), tmp3);

  bf256_store(a0_tilde, ret);
}

// AES(-EM) OWF dispatchers
void aes_prove(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde, const uint8_t* w,
               const uint8_t* u, uint8_t** V, const uint8_t* owf_in, const uint8_t* owf_out,
               const uint8_t* chall_2, const faest_paramset_t* params) {
  switch (params->lambda) {
  case 256:
    aes_256_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  case 192:
    aes_192_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  default:
    aes_128_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
  }
}

void aes_verify(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q, const uint8_t* chall_2,
                const uint8_t* chall_3, const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                const uint8_t* owf_in, const uint8_t* owf_out, const faest_paramset_t* params) {
  switch (params->lambda) {
  case 256:
    aes_256_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
    break;
  case 192:
    aes_192_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
    break;
  default:
    aes_128_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
  }
}

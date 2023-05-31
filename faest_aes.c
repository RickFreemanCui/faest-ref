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

#include <string.h>
#include <stdlib.h>

static uint8_t Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x26};

ATTR_CONST static inline bf8_t get_bit(bf8_t in, uint8_t index) {
  return (in >> index) & 0x01;
}

ATTR_CONST static inline bf8_t set_bit(bf8_t in, uint8_t index) {
  return (in << index);
}

static void aes_key_schedule_forward(uint32_t m, const uint8_t* x, uint8_t Mtag, uint8_t Mkey,
                                     const uint8_t* delta, uint8_t* out,
                                     const faest_paramset_t* params) {
  // Step: 1
  if ((Mtag == 1 && Mkey == 1) || (Mkey == 1 && delta == NULL)) {
    return;
  }

  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int R           = params->cipher_param.numRounds;
  const unsigned int Nwd         = params->faest_param.Nwd;
  const unsigned int lambdaBytes = lambda / 8;

  if (m == 1) {
    // Step 3
    memcpy(out, x, lambdaBytes);
    memset(out + lambdaBytes, 0, (R + 1) * 128 / 8 - lambdaBytes);

    // Step: 4
    uint32_t i_wd = lambda;

    // Step: 5..10
    for (uint32_t j = Nwd; j < 4 * (R + 1); j++) {
      if ((j % Nwd) == 0 || (Nwd > 6 && (j % Nwd) == 4)) {
        memcpy(out + 32 * j / 8, x + i_wd / 8, 4);
        i_wd += 32;
      } else {
        for (uint32_t i = 0; i < 32; i += 8) {
          out[(32 * j + i) / 8] |= set_bit(get_bit(out[(32 * (j - Nwd) + i) / 8], i % 8) ^
                                               get_bit(out[(32 * (j - 1) + i) / 8], i % 8),
                                           i % 8);
        }
      }
    }
    return;
  }

  const unsigned int y_out_len = (R + 1) * 128;

  bf128_t* bf_y = malloc(y_out_len * sizeof(bf128_t));
  for (uint32_t i = 0; i < lambdaBytes; i++) {
    for (uint32_t j = 0; j < 8; j++) {
      bf_y[(i * 8) + j] = bf128_from_bit(get_bit(x[i], j));
    }
  }
  // Step: 4
  uint32_t i_wd = lambda;

  // Step: 5..10
  for (uint32_t j = Nwd; j < 4 * (R + 1); j++) {
    if ((j % Nwd) == 0 || (Nwd > 6 && (j % Nwd) == 4)) {
      for (uint32_t i = (j * 32); i <= ((j * 32) + 31); i++) {
        bf_y[i] = bf128_from_bit(get_bit(x[i / 8], i % 8));
      }
      i_wd += 32;
    } else {
      for (uint32_t i = 0; i < 32; i++) {
        bf_y[(32 * j) + i] = bf128_add(bf_y[32 * (j - Nwd) + i], bf_y[32 * (j - 1) + i]);
      }
    }
  }

  for (uint32_t i = 0; i < y_out_len; ++i) {
    bf128_store(out + i * lambdaBytes, bf_y[i]);
  }
  free(bf_y);
}

static uint8_t* aes_key_schedule_backward(uint32_t m, const uint8_t* x, const uint8_t* xk,
                                          uint8_t Mtag, uint8_t Mkey, const uint8_t* delta,
                                          const faest_paramset_t* params) {
  // Step: 1
  if ((Mtag == 1 && Mkey == 1) || (Mkey == 1 && delta == NULL)) {
    return NULL;
  }

  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int Ske         = params->faest_param.Ske;
  const unsigned int lambdaBytes = lambda / 8;

  // STep: 2
  if (m == 1) {
    uint8_t* bf_y  = malloc(Ske);
    uint32_t iwd   = 0;
    uint32_t c     = 0;
    bool rmvRcon   = true;
    uint32_t ircon = 0;

    for (uint32_t j = 0; j < Ske; j++) {
      // Step 7 (bit sliced)
      uint8_t x_tilde = x[j] ^ xk[(iwd + 8 * c) / 8];

      // Step 8
      if (Mtag == 0 && rmvRcon == true && c == 0) {
        uint8_t rcon = Rcon[ircon];
        ircon        = ircon + 1;
        uint8_t r    = 0;
        for (uint32_t i = 0; i < 8; i++) {
          // Step 12; delta is always 0
          r |= set_bit(get_bit(rcon, i) & (1 ^ Mkey), i);
        }
        // Step 13 (bit sliced)
        x_tilde ^= r;
      }

      // Step: 15..23
      uint8_t y_tilde = 0;
      y_tilde |= set_bit(get_bit(x_tilde, 5) ^ get_bit(x_tilde, 2) ^ get_bit(x_tilde, 0) ^
                             ((1 ^ Mtag) & (1 ^ Mkey)),
                         7);
      y_tilde |= set_bit(get_bit(x_tilde, 7) ^ get_bit(x_tilde, 4) ^ get_bit(x_tilde, 1), 6);
      y_tilde |= set_bit(get_bit(x_tilde, 6) ^ get_bit(x_tilde, 3) ^ get_bit(x_tilde, 0) ^
                             ((1 ^ Mtag) & (1 ^ Mkey)),
                         5);
      y_tilde |= set_bit(get_bit(x_tilde, 7) ^ get_bit(x_tilde, 5) ^ get_bit(x_tilde, 2), 4);
      y_tilde |= set_bit(get_bit(x_tilde, 6) ^ get_bit(x_tilde, 4) ^ get_bit(x_tilde, 1), 3);
      y_tilde |= set_bit(get_bit(x_tilde, 5) ^ get_bit(x_tilde, 3) ^ get_bit(x_tilde, 0), 2);
      y_tilde |= set_bit(get_bit(x_tilde, 7) ^ get_bit(x_tilde, 4) ^ get_bit(x_tilde, 2), 1);
      y_tilde |= set_bit(get_bit(x_tilde, 6) ^ get_bit(x_tilde, 3) ^ get_bit(x_tilde, 1), 0);

      // Step: 23
      bf_y[j] = y_tilde;
      // Step: 24
      c = c + 1;

      if (c == 4) {
        c = 0;
        if (lambda == 192) {
          iwd += 192;
        } else {
          iwd += 128;
          if (lambda == 256) {
            rmvRcon = !rmvRcon;
          }
        }
      }
    }
    return bf_y;
  }

  bf128_t bf_delta;
  if (delta == NULL) {
    bf_delta = bf128_zero();
  } else {
    bf_delta = bf128_load(delta);
  }

  bf128_t* bf_y  = malloc(sizeof(bf128_t) * 8 * Ske);
  uint32_t iwd   = 0;
  uint32_t c     = 0;
  bool rmvRcon   = true;
  uint32_t ircon = 0;

  bf128_t bf_mkey             = bf128_from_bit(Mkey);
  bf128_t bf_minus_mkey       = bf128_from_bit(1 ^ Mkey);
  bf128_t bf_minus_mtag       = bf128_from_bit(1 ^ Mtag);
  bf128_t bf_mkey_times_delta = bf128_mul(bf_mkey, bf_delta);
  bf_mkey_times_delta         = bf128_add(bf_mkey_times_delta, bf_minus_mkey);

  bf128_t bf_x_tilde[8];

  for (uint32_t j = 0; j < Ske; j++) {
    // Step 7
    for (uint32_t i = 0; i < 8; i++) {
      bf_x_tilde[i] = bf128_add(bf128_from_bit(get_bit(x[j], i)),
                                bf128_from_bit(get_bit(xk[(iwd + 8 * c) / 8], i)));
    }

    if (Mtag == 0 && rmvRcon == true && c == 0) {
      uint8_t r = Rcon[ircon];
      ircon     = ircon + 1;
      bf128_t bf_r[8];

      for (uint32_t i = 0; i < 8; i++) {
        bf_r[i]       = bf128_from_bit(get_bit(r, i));
        bf_r[i]       = bf128_mul(bf_r[i], bf_mkey_times_delta);
        bf_x_tilde[i] = bf128_add(bf_x_tilde[i], bf_r[i]);
      }
    }

    bf128_t bf_y_tilde[8];
    bf_y_tilde[7] = bf128_add(bf128_add(bf128_add(bf_x_tilde[5], bf_x_tilde[2]), bf_x_tilde[0]),
                              bf128_mul(bf_minus_mtag, bf_mkey_times_delta));
    bf_y_tilde[6] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[4]), bf_x_tilde[1]);
    bf_y_tilde[5] = bf128_add(bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[3]), bf_x_tilde[0]),
                              bf128_mul(bf_minus_mtag, bf_mkey_times_delta));
    bf_y_tilde[4] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[5]), bf_x_tilde[2]);
    bf_y_tilde[3] = bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[4]), bf_x_tilde[1]);
    bf_y_tilde[2] = bf128_add(bf128_add(bf_x_tilde[5], bf_x_tilde[3]), bf_x_tilde[0]);
    bf_y_tilde[1] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[4]), bf_x_tilde[2]);
    bf_y_tilde[0] = bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[3]), bf_x_tilde[1]);

    // TODO: get rid of this copy
    for (uint32_t i = 0; i < 8; i++) {
      bf_y[(8 * j) + i] = bf_y_tilde[i];
    }
    c = c + 1;

    if (c == 4) {
      c = 0;
      if (lambda == 192) {
        iwd += 192;
      } else {
        iwd += 128;
        if (lambda == 256) {
          rmvRcon = !rmvRcon;
        }
      }
    }
  }

  uint8_t* y_out = malloc(Ske * 8 * lambdaBytes);
  for (uint32_t i = 0; i < Ske * 8; ++i) {
    bf128_store(y_out + i * lambdaBytes, bf_y[i]);
  }
  free(bf_y);
  return y_out;
}

static void aes_key_schedule_constraints(const uint8_t* w, const uint8_t* v, const uint8_t Mkey,
                                         const uint8_t* q, const uint8_t* delta, uint8_t* A0,
                                         uint8_t* A1, uint8_t* k, uint8_t* vk, uint8_t* B,
                                         uint8_t* qk, const faest_paramset_t* params) {
  const unsigned int lambda     = params->faest_param.lambda;
  const unsigned int Lke        = params->faest_param.Lke;
  const unsigned int Nwd        = params->faest_param.Nwd;
  const unsigned int Ske        = params->faest_param.Ske;
  const unsigned int lambdaByte = lambda / 8;
  uint32_t w_len                = Lke / 8;
  uint32_t q_len                = lambdaByte * (Lke / 8);

  if (Mkey == 0) {
    // STep: 2
    aes_key_schedule_forward(1, w, 0, 0, NULL, k, params);

    // Step: 3
    aes_key_schedule_forward(lambda, v, 1, 0, NULL, vk, params);

    // Step: 4
    uint8_t* w_dash = aes_key_schedule_backward(1, w + lambdaByte, k, 0, 0, NULL, params);

    // Step: 5
    uint8_t* v_w_dash = aes_key_schedule_backward(lambda, v + lambdaByte, vk, 1, 0, NULL, params);

    // Step: 6..8
    uint32_t iwd = 32 * (Nwd - 1);
    for (uint32_t j = 0; j < Ske / 4; j++) {
      bf128_t bf_k_hat[4];
      bf128_t bf_v_k_hat[4];
      bf128_t bf_w_dash_hat[4];
      bf128_t bf_v_w_dash_hat[4];
      for (uint32_t r = 0; r <= 3; r++) {
        // Step: 10..11
        bf_k_hat[(r + 3) % 4]   = bf128_byte_combine_bits(k[(iwd + 8 * r) / 8]);
        bf_v_k_hat[(r + 3) % 4] = bf128_byte_combine_bits(vk[(iwd + 8 * r) / 8]);
        bf_w_dash_hat[r]        = bf128_byte_combine_bits(w_dash[(32 * j + 8 * r) / 8]);
        bf_v_w_dash_hat[r]      = bf128_byte_combine_bits(v_w_dash[(32 * j + 8 * r) / 8]);
      }
      // Step: 13..17
      for (uint32_t r = 0; r <= 3; r++) {
        bf128_store(A0 + ((4 * j + r) + lambdaByte), bf128_mul(bf_v_k_hat[r], bf_v_w_dash_hat[r]));
        bf128_store(A1 + ((4 * j + r) + lambdaByte),
                    bf128_add(bf128_add(bf128_mul(bf128_add(bf_k_hat[r], bf_v_k_hat[r]),
                                                  bf128_add(bf_w_dash_hat[r], bf_v_w_dash_hat[r])),
                                        bf128_from_bf8(bf8_one())),
                              bf128_load(A0 + ((4 * j + r) * lambdaByte))));
      }
      if (lambda == 192) {
        iwd = iwd + 192;
      } else {
        iwd = iwd + 128;
      }
    }
    free(v_w_dash);
    free(w_dash);
    return;
  }

  // Step: 19..20
  aes_key_schedule_forward(lambda, q, 0, 1, delta, qk, params);
  uint8_t* q_w_dash = aes_key_schedule_backward(lambda, q + lambdaByte, qk, 0, 1, delta, params);

  // Step 23..24
  uint32_t iwd = 32 * (Nwd - 1);
  for (uint32_t j = 0; j < Ske / 4; j++) {
    bf128_t bf_q_hat_k[4];
    bf128_t bf_q_hat_w_dash[4];
    for (uint32_t r = 0; r <= 3; r++) {
      // Step: 25..26
      bf_q_hat_k[(r + 3) % 4] = bf128_byte_combine(qk + ((iwd + 8 * r) * lambdaByte));
      bf_q_hat_w_dash[r]      = bf128_byte_combine(q_w_dash + ((32 * j + 8 * r) * lambdaByte));
    }
    // STep: 27
    for (uint32_t r = 0; r <= 3; r++) {
      bf128_t bf_tmp;
      bf_tmp = bf128_mul(bf_q_hat_k[r], bf_q_hat_w_dash[r]);
      bf_tmp = bf128_add(bf_tmp, bf128_mul(bf128_mul(bf128_from_bf8(bf8_one()), bf128_load(delta)),
                                           bf128_load(delta)));
      bf128_store(&B[4 * j + r], bf_tmp);
    }
    if (lambda == 192) {
      iwd = iwd + 192;
    } else {
      iwd = iwd + 128;
    }
  }
  free(q_w_dash);
}

static int aes_enc_forward(uint32_t m, const uint8_t* x, const uint8_t* xk, const uint8_t* in,
                           uint8_t Mtag, uint8_t Mkey, const uint8_t* delta, uint8_t* y_out,
                           const faest_paramset_t* params) {
  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int R           = params->cipher_param.numRounds;
  const unsigned int lambdaBytes = lambda / 8;

  uint32_t bf_y_len = sizeof(bf128_t) * R * 16;
  bf128_t* bf_y     = malloc(bf_y_len);

  uint32_t ird;

  bf128_t bf_delta;
  if (delta == NULL) {
    bf_delta = bf128_zero();
  } else {
    bf_delta = bf128_load(delta);
  }

  if (m == 1) {

    // STep: 2
    for (uint32_t i = 0; i < 16; i++) {
      uint8_t xin = 0;
      // STep: 3
      for (uint32_t j = 0; j < 8; j++) {
        // STep: 4
        // TODO: check bit order
        xin |= set_bit(get_bit(in[i], j) & (1 ^ Mtag) & (1 ^ Mkey), j);
      }
      // STep: 5
      bf_y[i] = bf128_add(bf128_byte_combine_bits(xin), bf128_byte_combine_bits(xk[i]));
    }
    uint32_t ix, ik, iy;
    for (uint32_t j = 1; j < R; j++) {
      for (uint32_t c = 0; c <= 3; c++) {
        ix = 128 * (j - 1) + 32 * c;
        ik = 128 * j + 32 * c;
        iy = 16 * j + 4 * c;
        bf128_t bf_x_hat[4];
        bf128_t bf_xk_hat[4];
        for (uint32_t r = 0; r <= 3; r++) {
          // Step: 12..13
          bf_x_hat[r]  = bf128_byte_combine_bits(x[(ix + 8 * R) / 8]);
          bf_xk_hat[r] = bf128_byte_combine_bits(xk[(ix + 8 * R) / 8]);
        }
        bf128_t bf_one   = bf128_one();
        bf128_t bf_two   = bf128_from_bf8(2);
        bf128_t bf_three = bf128_from_bf8(3);
        // Step : 14
        bf_y[iy + 0] = bf128_add(bf_xk_hat[0], bf128_mul(bf_x_hat[0], bf_two));
        bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[1], bf_three));
        bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[2], bf_one));
        bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[3], bf_one));

        // STep: 15
        bf_y[iy + 1] = bf128_add(bf_xk_hat[1], bf128_mul(bf_x_hat[0], bf_one));
        bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[1], bf_two));
        bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[2], bf_three));
        bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[3], bf_one));

        // STep: 16
        bf_y[iy + 2] = bf128_add(bf_xk_hat[2], bf128_mul(bf_x_hat[0], bf_one));
        bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[1], bf_one));
        bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[2], bf_two));
        bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[3], bf_three));

        // Step: 17
        bf_y[iy + 3] = bf128_add(bf_xk_hat[3], bf128_mul(bf_x_hat[0], bf_three));
        bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[1], bf_one));
        bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[2], bf_two));
        bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[3], bf_two));
      }
    }
    // Step: 18
    uint32_t idx = 0;
    for (uint32_t i = 0; i < bf_y_len; i += lambdaBytes) {
      bf128_store(y_out + i, bf_y[idx]);
      idx += 1;
    }
    free(bf_y);
    return 1;
  }

  bf128_t bf_minus_mtag = bf128_from_bit(1 ^ Mtag);
  bf128_t bf_minus_mkey = bf128_from_bit(1 ^ Mkey);
  bf128_t bf_mkey       = bf128_from_bit(Mkey);

  // Step: 2..4
  for (uint32_t i = 0; i < 16; i++) {
    bf128_t bf_xin[8];
    for (uint32_t j = 0; j < 8; j++) {
      bf_xin[j] = bf128_mul(bf128_mul(bf128_from_bit(get_bit(in[i], j)), bf_minus_mtag),
                            bf128_add(bf128_mul(bf_mkey, bf_delta), bf_minus_mkey));
    }
    // STep: 5
    // remove copies
    uint8_t* xin_tmp = malloc(lambdaBytes * 8);
    memcpy(xin_tmp, bf_xin, lambdaBytes * 8);
    uint8_t* xk_tmp = malloc(lambdaBytes * 8);
    memcpy(xk_tmp, xk + (8 * i * lambdaBytes), lambdaBytes * 8);
    bf_y[i] = bf128_add(bf128_byte_combine(xin_tmp), bf128_byte_combine(xk_tmp));
    free(xin_tmp);
    free(xk_tmp);
  }
  uint32_t ix, ik, iy;
  for (uint32_t j = 1; j < R; j++) {
    for (uint32_t c = 0; c <= 3; c++) {
      ix = 128 * (j - 1) + 32 * c;
      ik = 128 * j + 32 * c;
      iy = 16 * j + 4 * c;
      bf128_t bf_x_hat[4];
      bf128_t bf_xk_hat[4];
      for (uint32_t r = 0; r <= 3; r++) {
        // Step: 12..13
        // FIXME: this looks bogus
        uint8_t* x_tmp = malloc(8 * lambdaBytes);
        memcpy(x_tmp, x + ((ix + 8 * R) / 8 * lambdaBytes), 8 * lambdaBytes);
        bf_x_hat[r] = bf128_byte_combine(x_tmp);
        free(x_tmp);

        uint8_t* xk_tmp = malloc(8 * lambdaBytes);
        memcpy(xk_tmp, xk + ((ix + 8 * R) / 8 * lambdaBytes), 8 * lambdaBytes);
        bf_xk_hat[r] = bf128_byte_combine(xk_tmp);
        free(xk_tmp);
      }
      bf128_t bf_one = bf128_one();
      // FIXME
      bf128_t bf_two   = bf128_from_bf64(2);
      bf128_t bf_three = bf128_from_bf64(3);
      // Step : 14
      bf_y[iy + 0] = bf128_add(bf_xk_hat[0], bf128_mul(bf_x_hat[0], bf_two));
      bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[1], bf_three));
      bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[2], bf_one));
      bf_y[iy + 0] = bf128_add(bf_y[iy + 0], bf128_mul(bf_x_hat[3], bf_one));

      // STep: 15
      bf_y[iy + 1] = bf128_add(bf_xk_hat[1], bf128_mul(bf_x_hat[0], bf_one));
      bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[1], bf_two));
      bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[2], bf_three));
      bf_y[iy + 1] = bf128_add(bf_y[iy + 1], bf128_mul(bf_x_hat[3], bf_one));

      // STep: 16
      bf_y[iy + 2] = bf128_add(bf_xk_hat[2], bf128_mul(bf_x_hat[0], bf_one));
      bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[1], bf_one));
      bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[2], bf_two));
      bf_y[iy + 2] = bf128_add(bf_y[iy + 2], bf128_mul(bf_x_hat[3], bf_three));

      // Step: 17
      bf_y[iy + 3] = bf128_add(bf_xk_hat[3], bf128_mul(bf_x_hat[0], bf_three));
      bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[1], bf_one));
      bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[2], bf_two));
      bf_y[iy + 3] = bf128_add(bf_y[iy + 3], bf128_mul(bf_x_hat[3], bf_two));
    }
  }
  // Step: 18
  uint32_t idx = 0;
  for (uint32_t i = 0; i < bf_y_len; i += lambdaBytes) {
    bf128_store(y_out + i, bf_y[idx]);
    idx += 1;
  }
  free(bf_y);
  return 1;
}

static int aes_enc_backward(uint32_t m, const uint8_t* x, const uint8_t* xk, uint8_t Mtag,
                            uint8_t Mkey, const uint8_t* delta, const uint8_t* out, uint8_t* y_out,
                            const faest_paramset_t* params) {
  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int R           = params->cipher_param.numRounds;
  const unsigned int lambdaBytes = lambda / 8;

  uint32_t y_out_len = lambdaBytes * R * 16;

  // Step: 1
  uint32_t bf_y_len = sizeof(bf128_t) * R * 16;
  bf128_t* bf_y     = malloc(bf_y_len);

  uint32_t ird;

  bf128_t bf_delta;
  if (delta == NULL) {
    bf_delta = bf128_zero();
  } else {
    bf_delta = bf128_load(delta);
  }

  if (m == 1) {
    uint8_t xtilde;
    // Step:2..4
    for (uint32_t j = 0; j < R; j++) {
      for (uint32_t c = 0; c <= 3; c++) {
        for (uint32_t r = 0; r <= 3; r++) {
          // Step: 5..6
          ird = (128 * j) + (32 * ((c - r) % 4)) + (8 * r);
          if (j < (R - 1)) {
            // Step: 7
            xtilde = x[ird / 8];
          } else {
            // Step: 9
            uint8_t xout = 0;
            for (uint32_t i = 0; i < 8; i++) {
              // Step: 10..11
              // delta is always \bot if called with m == 1
              xout |= set_bit(get_bit(out[(ird - 1152) / 8], i) & (1 ^ Mtag) & (1 ^ Mkey), i);
            }
            xtilde = xout ^ xk[(128 + ird) / 8];
          }
          // Step: 12..20
          uint8_t ytilde = 0;
          ytilde |= set_bit(get_bit(xtilde, 5) ^ get_bit(xtilde, 2) ^ get_bit(xtilde, 0) ^
                                ((1 ^ Mtag) & (1 ^ Mkey)),
                            7);
          ytilde |= set_bit(get_bit(xtilde, 7) ^ get_bit(xtilde, 4) ^ get_bit(xtilde, 1), 6);
          ytilde |= set_bit(get_bit(xtilde, 6) ^ get_bit(xtilde, 3) ^ get_bit(xtilde, 0) ^
                                ((1 ^ Mtag) & (1 ^ Mkey)),
                            5);
          ytilde |= set_bit(get_bit(xtilde, 7) ^ get_bit(xtilde, 5) ^ get_bit(xtilde, 2), 4);
          ytilde |= set_bit(get_bit(xtilde, 6) ^ get_bit(xtilde, 4) ^ get_bit(xtilde, 1), 3);
          ytilde |= set_bit(get_bit(xtilde, 5) ^ get_bit(xtilde, 3) ^ get_bit(xtilde, 0), 2);
          ytilde |= set_bit(get_bit(xtilde, 7) ^ get_bit(xtilde, 4) ^ get_bit(xtilde, 2), 1);
          ytilde |= set_bit(get_bit(xtilde, 6) ^ get_bit(xtilde, 3) ^ get_bit(xtilde, 1), 0);

          // Step: 21
          bf_y[16 * j + 4 * c + r] = bf128_byte_combine_bits(ytilde);
        }
      }
    }
    uint32_t idx = 0;
    for (uint32_t i = 0; i < y_out_len; i += lambdaBytes) {
      bf128_store(y_out + i, bf_y[idx]);
      idx++;
    }
    free(bf_y);
    return 1;
  }

  bf128_t* bf_x_tilde   = malloc(sizeof(bf128_t) * 8);
  bf128_t* bf_xout      = malloc(sizeof(bf128_t) * 8);
  bf128_t bf_minus_mtag = bf128_from_bit(1 - Mtag);
  bf128_t bf_minus_mkey = bf128_from_bit(1 - Mkey);
  bf128_t bf_mkey       = bf128_from_bit(Mkey);

  // STep: 2..4
  for (uint32_t j = 0; j < R; j++) {
    for (uint32_t c = 0; c <= 3; c++) {
      for (uint32_t r = 0; r <= 3; r++) {
        // Step: 5
        ird = (128 * j) + (32 * ((c - r) % 4)) + (8 * r);
        // Step: 6
        if (j < (R - 1)) {
          // Step: 7
          for (uint32_t i = 0; i < 8; i++) {
            bf_x_tilde[i] = bf128_from_bit(get_bit(x[ird / 8], i));
          }
        } else {
          // Step: 9
          for (uint32_t i = 0; i < 8; i++) {
            // Step: 10
            uint8_t* out_zeros_concat = malloc(lambdaBytes);
            out_zeros_concat[0]       = (get_bit(out[(ird - 1152) / 8], i) << 7);
            memset(out_zeros_concat + 1, 0, lambdaBytes - 1);
            bf_xout[i] = bf128_mul(bf128_mul(bf128_load(out_zeros_concat), bf_minus_mtag),
                                   bf128_add(bf128_mul(bf_mkey, bf_delta), bf_minus_mkey));
            // Step: 11
            bf_x_tilde[i] = bf128_add(bf_xout[i], bf128_from_bit(get_bit(xk[(128 + ird) / 8], i)));
            free(out_zeros_concat);
          }
        }
        // Step: 12
        bf128_t bf_y_tilde[8];
        // STep: 13..20
        bf_y_tilde[7] = bf128_add(
            bf128_add(bf128_add(bf_x_tilde[5], bf_x_tilde[2]), bf_x_tilde[0]),
            bf128_mul(bf_minus_mtag, bf128_add(bf128_mul(bf_mkey, bf_delta), bf_minus_mkey)));
        bf_y_tilde[6] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[4]), bf_x_tilde[1]);
        bf_y_tilde[5] = bf128_add(
            bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[3]), bf_x_tilde[0]),
            bf128_mul(bf_minus_mtag, bf128_add(bf128_mul(bf_mkey, bf_delta), bf_minus_mkey)));
        bf_y_tilde[4] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[5]), bf_x_tilde[2]);
        bf_y_tilde[3] = bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[4]), bf_x_tilde[1]);
        bf_y_tilde[2] = bf128_add(bf128_add(bf_x_tilde[5], bf_x_tilde[3]), bf_x_tilde[0]);
        bf_y_tilde[1] = bf128_add(bf128_add(bf_x_tilde[7], bf_x_tilde[4]), bf_x_tilde[2]);
        bf_y_tilde[0] = bf128_add(bf128_add(bf_x_tilde[6], bf_x_tilde[3]), bf_x_tilde[1]);

        // Step: 21
        uint8_t* y_tilde = malloc(lambdaBytes * 8);
        memcpy(y_tilde, bf_y_tilde, lambdaBytes * 8);
        bf_y[16 * j + 4 * c + r] = bf128_byte_combine(y_tilde);
        free(y_tilde);
      }
    }
  }
  free(bf_x_tilde);
  free(bf_xout);

  // STep: 22
  uint32_t idx = 0;
  for (uint32_t i = 0; i < y_out_len; i += lambdaBytes) {
    bf128_store(y_out + i, bf_y[idx]);
    idx++;
  }
  free(bf_y);
  return 1;
}

static void aes_enc_constraints(const uint8_t* in, const uint8_t* out, const uint8_t* w,
                                const uint8_t* v, const uint8_t* k, const uint8_t* vk, uint8_t Mkey,
                                const uint8_t* q, const uint8_t* qk, const uint8_t* delta,
                                uint8_t* A0, uint8_t* A1, uint8_t* B,
                                const faest_paramset_t* params) {
  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int Senc        = params->faest_param.Senc;
  const unsigned int lambdaBytes = lambda / 8;

  if (Mkey == 0) {
    uint8_t* s       = malloc(lambdaBytes * Senc);
    uint8_t* vs      = malloc(lambdaBytes * Senc);
    uint8_t* s_dash  = malloc(lambdaBytes * Senc);
    uint8_t* vs_dash = malloc(lambdaBytes * Senc);
    aes_enc_forward(1, w, k, in, 0, 0, NULL, s, params);
    aes_enc_forward(lambda, v, vk, in, 1, 0, NULL, vs, params);
    aes_enc_backward(1, w, k, 0, 0, delta, out, s_dash, params);
    aes_enc_backward(lambda, v, vk, 1, 0, delta, out, vs_dash, params);

    bf128_t* bf_s       = malloc(sizeof(bf128_t) * Senc);
    bf128_t* bf_vs      = malloc(sizeof(bf128_t) * Senc);
    bf128_t* bf_s_dash  = malloc(sizeof(bf128_t) * Senc);
    bf128_t* bf_vs_dash = malloc(sizeof(bf128_t) * Senc);
    for (uint8_t i = 0; i < Senc; i++) {
      bf_s[i]       = bf128_load(s + (i * lambdaBytes));
      bf_vs[i]      = bf128_load(vs + (i * lambdaBytes));
      bf_s_dash[i]  = bf128_load(s_dash + (i * lambdaBytes));
      bf_vs_dash[i] = bf128_load(vs_dash + (i * lambdaBytes));
    }
    free(s);
    free(vs);
    free(s_dash);
    free(vs_dash);

    bf128_t* bf_a0 = malloc(sizeof(bf128_t) * Senc);
    bf128_t* bf_a1 = malloc(sizeof(bf128_t) * Senc);
    for (uint32_t j = 0; j < Senc; j++) {
      bf_a0[j] = bf128_mul(bf_vs[j], bf_vs_dash[j]);
      bf128_store(A0 + (lambdaBytes * j), bf_a0[j]);
      bf_a1[j] = bf128_add(
          bf128_add(bf128_mul(bf128_add(bf_s[j], bf_vs[j]), bf128_add(bf_s_dash[j], bf_vs_dash[j])),
                    bf_a0[j]),
          bf128_from_bf8(bf8_one()));
      bf128_store(A1 + (lambdaBytes * j), bf_a1[j]);
    }
    free(bf_s);
    free(bf_vs);
    free(bf_s_dash);
    free(bf_vs_dash);
    free(bf_a0);
    free(bf_a1);
  } else {
    // Step: 11..12
    uint8_t* qs      = malloc(lambdaBytes * Senc);
    uint8_t* qs_dash = malloc(lambdaBytes * Senc);
    aes_enc_forward(lambda, q, qk, in, 0, 1, delta, qs, params);
    aes_enc_backward(lambda, q, qk, 0, 1, delta, out, qs_dash, params);

    // Step: 13..14
    bf128_t* bf_qs      = malloc(sizeof(bf128_t) * Senc);
    bf128_t* bf_qs_dash = malloc(sizeof(bf128_t) * Senc);
    uint32_t idx        = 0;
    for (uint32_t i = 0; i < Senc; i++) {
      bf_qs[i]      = bf128_load(qs + idx);
      bf_qs_dash[i] = bf128_load(qs_dash + idx);
      idx += lambdaBytes;
    }
    bf128_t minus_part =
        bf128_mul(bf128_mul(bf128_from_bf8(bf8_one()), bf128_load(delta)), bf128_load(delta));
    for (uint32_t j = 0; j < Senc; j++) {
      bf128_t bf_b_j = bf128_add(bf128_mul(bf_qs[j], bf_qs_dash[j]), minus_part);
      bf128_store(B + (lambdaBytes * j), bf_b_j);
    }
    free(qs);
    free(qs_dash);
    free(bf_qs);
    free(bf_qs_dash);
  }
}

void aes_prove(const uint8_t* w, const uint8_t* u, uint8_t** V, const uint8_t* in,
               const uint8_t* out, const uint8_t* chall, uint8_t* a_tilde, uint8_t* b_tilde,
               const faest_paramset_t* params) {
  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int beta        = params->faest_param.beta;
  const unsigned int l           = params->faest_param.l;
  const unsigned int Lke         = params->faest_param.Lke;
  const unsigned int Lenc        = params->faest_param.Lenc;
  const unsigned int R           = params->cipher_param.numRounds;
  const unsigned int Ske         = params->faest_param.Ske;
  const unsigned int Senc        = params->faest_param.Senc;
  const unsigned int lambdaBytes = lambda / 8;

  // Step: 1..2
  bf8_t* bf_w   = malloc(l);
  bf128_t* bf_v = malloc((l + lambda) * sizeof(bf128_t));
  for (uint32_t i = 0; i < l; i++) {
    bf_w[i] = bf8_from_bit(get_bit(w[i / 8], i % 8));
  }
  for (uint32_t i = 0; i < l + lambda; i++) {
    bf_v[i] = bf128_load(V[i]);
  }

  // Step: 3..4
  // do nothing

  // Step: 6
  uint8_t* w_tilde = malloc(Lke);
  uint8_t* v_tilde = malloc(Lke * lambdaBytes);
  memcpy(w_tilde, bf_w, Lke);
  memcpy(v_tilde, bf_v, Lke * lambdaBytes);

  // Step: 7
  const unsigned int length_a = Ske + (beta * Senc) + 1;
  uint8_t* A0                 = malloc(lambdaBytes * length_a);
  uint8_t* A1                 = malloc(lambdaBytes * length_a);
  uint8_t* k                  = malloc((R + 1) * 128);
  uint8_t* vk                 = malloc(lambdaBytes * ((R + 1) * 128));
  uint8_t* qk                 = malloc(lambdaBytes * ((R + 1) * 128));
  if (Lke > 0) {
    aes_key_schedule_constraints(w_tilde, v_tilde, 0, NULL, NULL, A0, A1, k, vk, NULL, qk, params);
  }

  // Step: Skipping 8 in implementation
  // Step: 9
  w_tilde = realloc(w_tilde, Lenc);
  v_tilde = realloc(v_tilde, Lenc * lambdaBytes);
  memcpy(w_tilde, bf_w + Lke, Lenc);
  memcpy(v_tilde, bf_v + Lke, Lenc * lambdaBytes);

  // Step: 10,11
  aes_enc_constraints(in, out, w_tilde, v_tilde, k, vk, 0, NULL, NULL, NULL,
                      A0 + (lambdaBytes * Ske), A1 + (lambdaBytes * Ske), NULL, params);

  // Step: 12
  if (beta == 2) {
    // Step: 13
    memcpy(w_tilde, bf_w + Lke + Lenc, l - Lke + Lenc);
    memcpy(v_tilde, bf_v + (Lke + Lenc), l - Lke + Lenc);
    // Step: 14, 15
    aes_enc_constraints(in + 16, out + 16, w_tilde, v_tilde, k, vk, 0, NULL, NULL, NULL,
                        A0 + lambdaBytes * (Ske + Senc), A1 + lambdaBytes * (Ske + Senc), NULL,
                        params);
  }
  free(w_tilde);
  free(v_tilde);
  free(bf_w);
  free(qk);
  free(vk);
  free(k);

  // Step: 16..18
  bf128_t bf_us = bf128_zero();
  bf128_t bf_vs = bf128_zero();
  for (uint32_t i = 0; i < lambda; i++) {
    bf_us = bf128_add(bf_us, bf128_from_bf8(get_bit(u[(i + l) / 8], (i + l) % 8)));
    bf_vs = bf128_add(bf_vs, bf_v[l + i]);
  }
  free(bf_v);

  memcpy(A1 + lambdaBytes * (Ske + beta * Senc), &bf_us, lambdaBytes);
  memcpy(A0 + lambdaBytes * (Ske + beta * Senc), &bf_vs, lambdaBytes);

  bf128_t* bf_a1_us_concat = malloc(sizeof(bf128_t) * length_a);
  memcpy(bf_a1_us_concat, A1, sizeof(bf128_t) * length_a);
  bf128_t* bf_a0_vs_concat = malloc(sizeof(bf128_t) * length_a);
  memcpy(bf_a0_vs_concat, A0, sizeof(bf128_t) * length_a);

  free(A1);
  free(A0);

  zk_hash_128(a_tilde, chall, bf_a1_us_concat, length_a - 1);
  zk_hash_128(b_tilde, chall, bf_a0_vs_concat, length_a - 1);

  free(bf_a0_vs_concat);
  free(bf_a1_us_concat);
}

uint8_t* aes_verify(uint8_t* d, uint8_t** Q, const uint8_t* chall_2, const uint8_t* chall_3,
                    const uint8_t* a_tilde, const uint8_t* in, const uint8_t* out,
                    const faest_paramset_t* params) {
  const unsigned int lambda      = params->faest_param.lambda;
  const unsigned int tau         = params->faest_param.tau;
  const unsigned int t0          = params->faest_param.t0;
  const unsigned int k0          = params->faest_param.k0;
  const unsigned int t1          = params->faest_param.t1;
  const unsigned int k1          = params->faest_param.k1;
  const unsigned int beta        = params->faest_param.beta;
  const unsigned int l           = params->faest_param.l;
  const unsigned int Lke         = params->faest_param.Lke;
  const unsigned int Lenc        = params->faest_param.Lenc;
  const unsigned int R           = params->cipher_param.numRounds;
  const unsigned int Ske         = params->faest_param.Ske;
  const unsigned int Senc        = params->faest_param.Senc;
  const unsigned int lambdaBytes = lambda / 8;

  // Step: 1
  const uint8_t* delta = chall_3;

  // Step: 2
  // do nothing

  // Step: 3
  // do nothing

  // Step: 4..10
  for (uint32_t i = 0; i < tau; i++) {
    unsigned int depth = i < t0 ? k0 : k1;
    uint8_t* fancy_d   = malloc(depth);
    ChalDec(chall_3, i, k0, t0, k1, t1, fancy_d);
    for (uint32_t j = 0; j < depth; j++) {
      if (fancy_d[j] == 1) {
        xorUint8Arr(d, Q[i + j], Q[i + j], (l + 7) / 8);
      }
    }
    free(fancy_d);
  }

  // Step: 11..12
  bf128_t* bf_q   = malloc(sizeof(bf128_t) * (l + lambda));
  uint8_t** new_Q = column_to_row_major_and_shrink_V(Q, lambda, l);
  for (uint32_t i = 0; i < l + lambda; i++) {
    bf_q[i] = bf128_load(new_Q[i]);
  }
  free(new_Q[0]);
  free(new_Q);

  // Step: 13
  uint8_t* q_lke = malloc(lambdaBytes * (Lke));
  memcpy(q_lke, bf_q, sizeof(bf128_t) * Lke);
  const unsigned int length_b = Ske + (beta * Senc) + 1;
  uint8_t* k                  = malloc((R + 1) * 128);
  uint8_t* vk                 = malloc(lambdaBytes * ((R + 1) * 128));
  uint8_t* qk                 = malloc(lambdaBytes * ((R + 1) * 128));
  uint8_t* B_0                = malloc(lambdaBytes * length_b);
  if (Lke > 0) {
    aes_key_schedule_constraints(NULL, NULL, 1, q_lke, delta, NULL, NULL, k, vk, B_0, qk, params);
  }
  free(q_lke);

  // Step: 14
  uint8_t* B_1        = B_0 + Ske * lambdaBytes;
  uint8_t* q_lke_lenc = malloc(lambdaBytes * (Lenc - Lke));
  memcpy(q_lke_lenc, bf_q + Lke, sizeof(bf128_t) * (Lenc - Lke));
  aes_enc_constraints(in, out, NULL, NULL, NULL, NULL, 1, q_lke_lenc, qk, delta, NULL, NULL, B_1,
                      params);

  if (beta == 2) {
    // Step: 18
    uint8_t* B_2 = B_0 + (Ske + Senc) * lambdaBytes;
    memcpy(q_lke_lenc, bf_q + (Lke + Lenc), sizeof(bf128_t) * (l - Lenc - Lke));
    aes_enc_constraints(in + 16, out + 16, NULL, NULL, NULL, NULL, 1, q_lke_lenc, qk, delta, NULL,
                        NULL, B_2, params);
  }
  free(q_lke_lenc);

  free(qk);
  free(vk);
  free(k);

  // Step: 20
  bf128_t bf_qs = bf128_zero();
  for (uint32_t i = 0; i < l + lambda; i++) {
    bf_qs = bf128_add(bf_qs, bf_q[i]);
  }
  free(bf_q);

  // Step 21
  // TODO: avoid these copies
  memcpy(B_0 + lambdaBytes * (Ske + beta * Senc), &bf_qs, lambdaBytes);
  bf128_t* b_qs_concat = malloc(length_b * sizeof(bf128_t));
  memcpy(b_qs_concat, B_0, length_b * sizeof(bf128_t));
  uint8_t* q_tilde = malloc(lambdaBytes);
  zk_hash_128(q_tilde, chall_2, b_qs_concat, length_b - 1);
  free(B_0);
  free(b_qs_concat);

  bf128_t bf_qtilde = bf128_load(q_tilde);
  bf128_store(q_tilde, bf128_add(bf_qtilde, bf128_mul(bf128_load(a_tilde), bf128_load(delta))));

  return q_tilde;
}

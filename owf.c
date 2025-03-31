/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "owf.h"
#include "aes.h"
#include "utils.h"

// For RSD H mat
#include "random_oracle.h"
//

#include <string.h>

#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#include <assert.h>
#endif

#if defined(HAVE_AESNI)
#include "cpu.h"
#include "aesni.h"

ATTR_TARGET_AESNI static void owf_128_aesni(const uint8_t* key, const uint8_t* input,
                                            uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, key);

  __m128i m = _mm_xor_si128(_mm_loadu_si128((const __m128i_u*)input), rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  _mm_storeu_si128((__m128i_u*)output, m);
}

ATTR_TARGET_AESNI static void owf_192_aesni(const uint8_t* key, const uint8_t* input,
                                            uint8_t* output) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni(rk, key);

  __m128i temp[2];
  temp[1] = _mm_loadu_si128((const __m128i_u*)input);
  temp[0] = _mm_xor_si128(temp[1], rk[0]);
  temp[1] = _mm_xor_si128(temp[0], _mm_setr_epi32(1, 0, 0, 0));
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  temp[0] = _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_192]);
  temp[1] = _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_192]);
  _mm_storeu_si128((__m128i_u*)output, temp[0]);
  _mm_storeu_si128((__m128i_u*)(output + IV_SIZE), temp[1]);
}

ATTR_TARGET_AESNI static void owf_256_aesni(const uint8_t* key, const uint8_t* input,
                                            uint8_t* output) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni(rk, key);

  __m128i temp[2];
  temp[1] = _mm_loadu_si128((const __m128i_u*)input);
  temp[0] = _mm_xor_si128(temp[1], rk[0]);
  temp[1] = _mm_xor_si128(temp[0], _mm_setr_epi32(1, 0, 0, 0));
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  temp[0] = _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_256]);
  temp[1] = _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_256]);
  _mm_storeu_si128((__m128i_u*)output, temp[0]);
  _mm_storeu_si128((__m128i_u*)(output + IV_SIZE), temp[1]);
}

ATTR_TARGET_AESNI static void owf_em_128_aesni(const uint8_t* key, const uint8_t* input,
                                               uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, input);

  __m128i mkey = _mm_loadu_si128((const __m128i_u*)key);
  __m128i m    = _mm_xor_si128(mkey, rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  m = _mm_xor_si128(m, mkey);
  _mm_storeu_si128((__m128i_u*)output, m);
}

#if defined(HAVE_AVX2)
ATTR_TARGET_AESNI_AVX2 static void owf_128_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                      uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, key);

  __m128i m = _mm_xor_si128(_mm_loadu_si128((const __m128i_u*)input), rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  _mm_storeu_si128((__m128i_u*)output, m);
}

ATTR_TARGET_AESNI_AVX2 static void owf_192_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                      uint8_t* output) {
  __m128i rk[AES_ROUNDS_192 + 1];
  aes192_expand_key_aesni_avx2(rk, key);

  __m128i temp[2];
  temp[1] = _mm_loadu_si128((const __m128i_u*)input);
  temp[0] = _mm_xor_si128(temp[1], rk[0]);
  temp[1] = _mm_xor_si128(temp[0], _mm_setr_epi32(1, 0, 0, 0));
  for (unsigned int round = 1; round != AES_ROUNDS_192; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  temp[0] = _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_192]);
  temp[1] = _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_192]);
  _mm_storeu_si128((__m128i_u*)output, temp[0]);
  _mm_storeu_si128((__m128i_u*)(output + IV_SIZE), temp[1]);
}

ATTR_TARGET_AESNI_AVX2 static void owf_256_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                      uint8_t* output) {
  __m128i rk[AES_ROUNDS_256 + 1];
  aes256_expand_key_aesni_avx2(rk, key);

  __m128i temp[2];
  temp[1] = _mm_loadu_si128((const __m128i_u*)input);
  temp[0] = _mm_xor_si128(temp[1], rk[0]);
  temp[1] = _mm_xor_si128(temp[0], _mm_setr_epi32(1, 0, 0, 0));
  for (unsigned int round = 1; round != AES_ROUNDS_256; ++round) {
    temp[0] = _mm_aesenc_si128(temp[0], rk[round]);
    temp[1] = _mm_aesenc_si128(temp[1], rk[round]);
  }
  temp[0] = _mm_aesenclast_si128(temp[0], rk[AES_ROUNDS_256]);
  temp[1] = _mm_aesenclast_si128(temp[1], rk[AES_ROUNDS_256]);
  _mm_storeu_si128((__m128i_u*)output, temp[0]);
  _mm_storeu_si128((__m128i_u*)(output + IV_SIZE), temp[1]);
}

ATTR_TARGET_AESNI_AVX2 static void owf_em_128_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                         uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, input);

  __m128i mkey = _mm_loadu_si128((const __m128i_u*)key);
  __m128i m    = _mm_xor_si128(mkey, rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  m = _mm_xor_si128(m, mkey);
  _mm_storeu_si128((__m128i_u*)output, m);
}
#endif
#endif

void owf_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_128_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_128_aesni(key, input, output);
    return;
  }
#endif

#if defined(HAVE_OPENSSL)
  const EVP_CIPHER* cipher = EVP_aes_128_ecb();
  assert(cipher);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
  int len = 0;
  EVP_EncryptUpdate(ctx, output, &len, input, IV_SIZE);
  assert((unsigned int)len == IV_SIZE);
  EVP_CIPHER_CTX_free(ctx);
#else
  aes_round_keys_t round_keys;
  aes128_init_round_keys(&round_keys, key);
  aes128_encrypt_block(&round_keys, input, output);
#endif
}

void owf_192(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_192_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_192_aesni(key, input, output);
    return;
  }
#endif

#if defined(HAVE_OPENSSL)
  const EVP_CIPHER* cipher = EVP_aes_192_ecb();
  assert(cipher);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
  int len = 0;
  EVP_EncryptUpdate(ctx, output, &len, input, IV_SIZE);
  assert((unsigned int)len == IV_SIZE);
  uint8_t buf[16];
  memcpy(buf, input, sizeof(buf));
  buf[0] ^= 0x1;
  EVP_EncryptUpdate(ctx, output + IV_SIZE, &len, buf, IV_SIZE);
  assert((unsigned int)len == IV_SIZE);
  EVP_CIPHER_CTX_free(ctx);
#else
  aes_round_keys_t round_keys;
  aes192_init_round_keys(&round_keys, key);

  // first block
  aes192_encrypt_block(&round_keys, input, output);
  // second block
  uint8_t buf[16];
  memcpy(buf, input, sizeof(buf));
  buf[0] ^= 0x1;
  aes192_encrypt_block(&round_keys, buf, output + 16);
#endif
}

void owf_256(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_256_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_256_aesni(key, input, output);
    return;
  }
#endif

#if defined(HAVE_OPENSSL)
  const EVP_CIPHER* cipher = EVP_aes_256_ecb();
  assert(cipher);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
  int len = 0;
  // first block
  EVP_EncryptUpdate(ctx, output, &len, input, IV_SIZE);
  assert((unsigned int)len == IV_SIZE);
  // second block
  uint8_t buf[16];
  memcpy(buf, input, sizeof(buf));
  buf[0] ^= 0x1;
  EVP_EncryptUpdate(ctx, output + IV_SIZE, &len, buf, IV_SIZE);
  assert((unsigned int)len == IV_SIZE);
  EVP_CIPHER_CTX_free(ctx);
#else
  aes_round_keys_t round_keys;
  aes256_init_round_keys(&round_keys, key);

  // first block
  aes256_encrypt_block(&round_keys, input, output);
  // second block
  uint8_t buf[16];
  memcpy(buf, input, sizeof(buf));
  buf[0] ^= 0x1;
  aes256_encrypt_block(&round_keys, buf, output + 16);
#endif
}

void owf_em_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_em_128_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_em_128_aesni(key, input, output);
    return;
  }
#endif

  // same as owf_128 with swapped keys and the additional xor
  owf_128(input, key, output);
  xor_u8_array(output, key, output, 16);
}

void owf_em_192(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  aes_round_keys_t round_keys;
  rijndael192_init_round_keys(&round_keys, input);
  rijndael192_encrypt_block(&round_keys, key, output);
  xor_u8_array(output, key, output, 24);
}

void owf_em_256(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  aes_round_keys_t round_keys;
  rijndael256_init_round_keys(&round_keys, input);
  rijndael256_encrypt_block(&round_keys, key, output);
  xor_u8_array(output, key, output, 32);
}


// input is the public seed for sampling the H matrix
// key is the private seed for sampling the e vector
// output is the public vector y = H * e
bool owf_rsd(const uint8_t* key, const uint8_t* input, uint8_t* output, int lambda) {

  const resolved_paramset_t* paramset =  resolved_get_paramset(lambda == 320 ? RESOLVED_320F : (RESOLVED_512F));
  const int code_length = paramset->code_length;
  const int code_dimension = paramset->code_dimension;
  const int code_noise_weight = paramset->code_noise_weight;
  const int code_block_size = paramset->code_block_size;

  const int output_len = (code_length - code_dimension + 7) / 8; // Round to byte
  int ret = 0;  

  memset(output, 0, output_len);

  //generate mat H
  uint8_t *buffer=generate_H_mat(code_length - code_dimension, code_length, input, lambda);

  uint8_t *e = (uint8_t *)malloc(code_length);
  generate_e(e,code_length,code_noise_weight,code_block_size,key,lambda);


  // y=H*e
  uint8_t *y = (uint8_t *)malloc(code_length - code_dimension);
  memset(y,0,code_length - code_dimension);
  for(int i=0;i<code_length - code_dimension;i++)
  for(int j=0;j<code_length;j++){
    y[i] ^= getH(i,j,code_length - code_dimension,code_length,buffer) & e[j];
  }
  //pack y into output
  for(int i=0;i<code_length - code_dimension;i++){
    output[i/8] ^= (y[i] << (i%8));
  }

  free(e);
  free(y);
  free(buffer); 

  return ret == 0;
}



void owf_rsd_320(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  owf_rsd(key, input, output, 320);
}


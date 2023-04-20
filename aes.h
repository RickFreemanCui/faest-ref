/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_AES_H
#define FAEST_AES_H

#include "fields.h"
#include "macros.h"

FAEST_BEGIN_C_DECL

void aes_increment_iv(bf8_t* iv);
void aes_ctr_encrypt(bf8_t* key, bf8_t* iv, bf8_t* plaintext, bf8_t* output, uint16_t seclv_);

FAEST_END_C_DECL

#endif
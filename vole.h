/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_VOLE_H
#define FAEST_VOLE_H

#include "bavc.h"
#include <stdbool.h>

FAEST_BEGIN_C_DECL

// k_b is at most 12, so chalout needs to point to an array of at most 12 bytes
int ChalDec(const uint8_t* chal, unsigned int i, unsigned int k0, unsigned int t0, unsigned int k1,
            unsigned int t1, uint8_t* chalout);

void vole_commit(const uint8_t* rootKey, const uint8_t* iv, unsigned int ellhat,
                 const faest_paramset_t* params, vec_com_t* vecCom, uint8_t* c, uint8_t* u,
                 uint8_t** v);

bool vole_reconstruct(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                      const uint8_t* decom_i, const uint8_t* c, unsigned int ellhat,
                      const faest_paramset_t* params);

#if defined(FAEST_TESTS)
int ConvertToVole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
                  unsigned int outLenBytes, uint8_t* u, uint8_t* v, const faest_paramset_t* params);
#endif

FAEST_END_C_DECL

#endif

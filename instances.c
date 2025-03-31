/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "instances.h"
#include "parameters.h"

const char* faest_get_param_name(faest_paramid_t paramid) {
  switch (paramid) {
  case PARAMETER_SET_INVALID:
    return "PARAMETER_SET_INVALID";
  case FAEST_128S:
    return "FAEST_128S";
  case FAEST_128F:
    return "FAEST_128F";
  case FAEST_192S:
    return "FAEST_192S";
  case FAEST_192F:
    return "FAEST_192F";
  case FAEST_256S:
    return "FAEST_256S";
  case FAEST_256F:
    return "FAEST_256F";
  case FAEST_EM_128S:
    return "FAEST_EM_128S";
  case FAEST_EM_128F:
    return "FAEST_EM_128F";
  case FAEST_EM_192S:
    return "FAEST_EM_192S";
  case FAEST_EM_192F:
    return "FAEST_EM_192F";
  case FAEST_EM_256S:
    return "FAEST_EM_256S";
  case FAEST_EM_256F:
    return "FAEST_EM_256F";
  default:
    return "PARAMETER_SET_MAX_INDEX";
  }
}

#define CALC_TAU1(name) ((name##_LAMBDA - name##_W_GRIND) % name##_TAU)
#define CALC_TAU0(name) (name##_TAU - CALC_TAU1(name))
#define CALC_L(name)                                                                               \
  (CALC_TAU1(name) * (1 << CALC_K(name)) + CALC_TAU0(name) * (1 << (CALC_K(name) - 1)))
#define CALC_K(name) (((name##_LAMBDA - name##_W_GRIND) / (name##_TAU)) + 1)

#define PARAMS(name)                                                                               \
  {                                                                                                \
      name##_LAMBDA,                                                                               \
      name##_TAU,                                                                                  \
      name##_W_GRIND,                                                                              \
      name##_T_OPEN,                                                                               \
      name##_ELL,                                                                                  \
      CALC_K(name),                                                                                \
      CALC_TAU0(name),                                                                             \
      CALC_TAU1(name),                                                                             \
      CALC_L(name),                                                                                \
      name##_Nst,                                                                                  \
      name##_Ske,                                                                                  \
      name##_R,                                                                                    \
      name##_Senc,                                                                                 \
      name##_Lke,                                                                                  \
      name##_Lenc,                                                                                 \
      name##_SIG_SIZE,                                                                             \
      name##_OWF_INPUT_SIZE,                                                                       \
      name##_OWF_OUTPUT_SIZE,                                                                      \
  }

#define FAEST_128S_PARAMS PARAMS(FAEST_128S)
#define FAEST_128F_PARAMS PARAMS(FAEST_128F)
#define FAEST_192S_PARAMS PARAMS(FAEST_192S)
#define FAEST_192F_PARAMS PARAMS(FAEST_192F)
#define FAEST_256S_PARAMS PARAMS(FAEST_256S)
#define FAEST_256F_PARAMS PARAMS(FAEST_256F)
#define FAEST_EM_128S_PARAMS PARAMS(FAEST_EM_128S)
#define FAEST_EM_128F_PARAMS PARAMS(FAEST_EM_128F)
#define FAEST_EM_192S_PARAMS PARAMS(FAEST_EM_192S)
#define FAEST_EM_192F_PARAMS PARAMS(FAEST_EM_192F)
#define FAEST_EM_256S_PARAMS PARAMS(FAEST_EM_256S)
#define FAEST_EM_256F_PARAMS PARAMS(FAEST_EM_256F)

#define CASE_PARAM(P)                                                                              \
  case P: {                                                                                        \
    static const faest_paramset_t params = P##_PARAMS;                                             \
    return &params;                                                                                \
  }

const faest_paramset_t* faest_get_paramset(faest_paramid_t paramid) {
  switch (paramid) {
    CASE_PARAM(FAEST_128S)
    CASE_PARAM(FAEST_128F)
    CASE_PARAM(FAEST_EM_128S)
    CASE_PARAM(FAEST_EM_128F)
    CASE_PARAM(FAEST_192S)
    CASE_PARAM(FAEST_192F)
    CASE_PARAM(FAEST_EM_192S)
    CASE_PARAM(FAEST_EM_192F)
    CASE_PARAM(FAEST_256S)
    CASE_PARAM(FAEST_256F)
    CASE_PARAM(FAEST_EM_256S)
    CASE_PARAM(FAEST_EM_256F)
  default:
    return NULL;
  }
}

// ReSolveD Parameter Implementation

const char* resolved_get_param_name(resolved_paramid_t paramid) {
  switch (paramid) {
  case PARAMETER_SET_INVALID:
    return "RESOLVED_PARAMETER_SET_INVALID";
  case RESOLVED_320F:
    return "RESOLVED_320F";
  case RESOLVED_512F:
    return "RESOLVED_512F";
  default:
    return "RESOLVED_PARAMETER_SET_MAX_INDEX";
  }
}



#define RESOLVED_PARAMS(name)                                                                               \
  {                                                                                                \
      name##_LAMBDA,                                                                               \
      name##_TAU,                                                                                  \
      name##_W_GRIND,                                                                              \
      name##_T_OPEN,                                                                               \
      name##_ELL,                                                                                  \
      CALC_K(name),                                                                                \
      CALC_TAU0(name),                                                                             \
      CALC_TAU1(name),                                                                             \
      CALC_L(name),                                                                                \
      name##_M,                                                                                  \
      name##_K,                                                                                  \
      name##_W,                                                                                    \
      name##_BLOCK_SIZE,                                                                                    \
      name##_SIG_SIZE,                                                                             \
      name##_OWF_INPUT_SIZE,                                                                       \
      name##_OWF_OUTPUT_SIZE,                                                                      \
  }

#define RESOLVED_320F_PARAMS RESOLVED_PARAMS(RESOLVED_320F)
#define RESOLVED_512F_PARAMS RESOLVED_PARAMS(RESOLVED_512F)

#define RESOLVED_CASE_PARAM(P)                                                                              \
  case P: {                                                                                        \
    static const resolved_paramset_t params = P##_PARAMS;                                             \
    return &params;                                                                                \
  }

const resolved_paramset_t* resolved_get_paramset(resolved_paramid_t paramid) {
  switch (paramid) {
    RESOLVED_CASE_PARAM(RESOLVED_320F)
  default:
    return NULL;
  }
}
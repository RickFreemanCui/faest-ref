/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_COMPAT_H
#define FAEST_COMPAT_H

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "macros.h"

#include <stddef.h>

#if !defined(HAVE_CONFIG_H) && !defined(OQS)
/* In case cmake checks were not run, define HAVE_* for known good configurations. We skip those if
 * building for OQS, as the compat functions from there can be used instead. */
#if defined(__OpenBSD__)
#include <sys/param.h>
#endif /* __OpenBSD__ */

#if !defined(HAVE_ALIGNED_ALLOC) && !defined(__APPLE__) && !defined(__MINGW32__) &&                \
    !defined(__MINGW64__) && !defined(_MSC_VER) && !defined(__ANDROID__) &&                        \
    (defined(_ISOC11_SOURCE) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L))
/* aligned_alloc was introduced in ISO C 2011. Even if building with -std=c11, some toolchains do
 * not provide aligned_alloc, including toolchains for Android, OS X, MinGW, and others. */
#define HAVE_ALIGNED_ALLOC
#endif /* HAVE_ALIGNED_ALLOC */

#if !defined(HAVE_EXPLICIT_BZERO) &&                                                               \
    (GLIBC_CHECK(2, 25) || (defined(__OpenBSD__) && OpenBSD >= 201405) || FREEBSD_CHECK(11, 0) ||  \
     NETBSD_CHECK(8, 0))
/* explicit_bzero was introduced in glibc 2.35, OpenBSD 5.5, FreeBSD 11.0 and NetBSD 8.0 */
#define HAVE_EXPLICIT_BZERO
#endif /* HAVE_EXPLICIT_BZERO */

#if !defined(HAVE_TIMINGSAFE_BCMP) && ((defined(__OpenBSD__) && OpenBSD >= 201105) ||              \
                                       FREEBSD_CHECK(12, 0) || MACOSX_CHECK(10, 12, 1))
/* timingsafe_bcmp was introduced in OpenBSD 4.9, FreeBSD 12.0, and MacOS X 10.12 */
#define HAVE_TIMINGSAFE_BCMP
#endif /* HAVE_TIMINGSAFE_BCMP */
#endif /* !HAVE_CONFIG_H && !OQS */

#if defined(HAVE_ALIGNED_ALLOC)
#include <stdlib.h>

#define faest_aligned_alloc(alignment, size) aligned_alloc((alignment), (size))
#define faest_aligned_free(ptr) free((ptr))
#else
FAEST_BEGIN_C_DECL

/**
 * Some aligned_alloc compatbility implementations require custom free
 * functions, so we provide one too.
 */
void faest_aligned_free(void* ptr);
/**
 * Compatibility implementation of aligned_alloc from ISO C 2011.
 */
void* faest_aligned_alloc(size_t alignment, size_t size) ATTR_MALLOC(faest_aligned_free)
    ATTR_ALLOC_ALIGN(1) ATTR_ALLOC_SIZE(2);

FAEST_END_C_DECL
#endif /* HAVE_ALIGNED_ALLOC */

#include "endian_compat.h"

#if defined(HAVE_TIMINGSAFE_BCMP)
#include <string.h>

#define faest_timingsafe_bcmp(a, b, len) timingsafe_bcmp((a), (b), (len))
#else
FAEST_BEGIN_C_DECL

/**
 * Compatibility implementation of timingsafe_bcmp from OpenBSD 4.9 and FreeBSD 12.0.
 */
int faest_timingsafe_bcmp(const void* a, const void* b, size_t len);

FAEST_END_C_DECL
#endif /* HAVE_TIMINGSAFE_BCMP */

#if defined(HAVE_EXPLICIT_BZERO)
#include <string.h>

#define faest_explicit_bzero(ptr, len) explicit_bzero((ptr), (len))
#else
FAEST_BEGIN_C_DECL

/**
 * Compatibility implementation of explicit_bzero
 */
void faest_explicit_bzero(void* a, size_t len);

FAEST_END_C_DECL
#endif /* HAVE_EXPLICIT_BZERO */

#if defined(OQS)
#define faest_aligned_alloc(alignment, size) OQS_MEM_aligned_alloc((alignment), (size))
#define faest_aligned_free(ptr) OQS_MEM_aligned_free((ptr))
#define faest_timingsafe_bcmp(a, b, len) OQS_MEM_secure_bcmp((a), (b), (len))
#define faest_explicit_bzero(ptr, len) OQS_MEM_cleanse(ptr, len)
#endif

/* helper macros/functions for checked integer subtraction */
#if GNUC_CHECK(5, 0) || __has_builtin(__builtin_add_overflow)
#define add_overflow_u64(x, y, sum) __builtin_add_overflow(x, y, sum)
#define sub_overflow_size_t(x, y, diff) __builtin_sub_overflow(x, y, diff)
#else
#include <stdbool.h>
#include <stddef.h>

ATTR_ARTIFICIAL
static inline bool add_overflow_u64(const uint64_t x, const uint64_t y, uint64_t* sum) {
  *sum = x + y;
  return *sum < x;
}

ATTR_ARTIFICIAL
static inline bool sub_overflow_size_t(const size_t x, const size_t y, size_t* diff) {
  *diff = x - y;
  return x < y;
}
#endif

#include <stdint.h>
#include <limits.h>

/* helper functions for left and right rotations of bytes */
#if GNUC_CHECK(4, 9) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>

#define rotl8 __rolb
#define rotr8 __rorb
#elif __has_builtin(__builtin_rotateleft) && __has_builtin(__builtin_rotateright)
#define rotl8 __builtin_rotateleft8
#define rotr8 __builtin_rotateright8
#else
ATTR_CONST static inline uint8_t rotl8(uint8_t n, unsigned int c) {
  const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
  c &= mask;
  return (n << c) | (n >> ((-c) & mask));
}

ATTR_CONST static inline uint8_t rotr8(uint8_t n, unsigned int c) {
  const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
  c &= mask;
  return (n >> c) | (n << ((-c) & mask));
}
#endif

/* helper functions to compute number of leading zeroes */
#if GNUC_CHECK(4, 7) || __has_builtin(__builtin_clz)
ATTR_CONST ATTR_ARTIFICIAL static inline uint32_t clz(uint32_t x) {
  return x ? __builtin_clz(x) : 32;
}
#elif defined(_MSC_VER)
#include <intrin.h>
ATTR_CONST ATTR_ARTIFICIAL static inline uint32_t clz(uint32_t x) {
  unsigned long index = 0;
  if (_BitScanReverse(&index, x)) {
    return 31 - index;
  }
  return 32;
}
#else
/* Number of leading zeroes of x.
 * From the book
 * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
 * http://www.hackersdelight.org/hdcodetxt/nlz.c.txt
 */
ATTR_CONST ATTR_ARTIFICIAL static inline uint32_t clz(uint32_t x) {
  if (!x) {
    return 32;
  }

  uint32_t n = 1;
  if (!(x >> 16)) {
    n = n + 16;
    x = x << 16;
  }
  if (!(x >> 24)) {
    n = n + 8;
    x = x << 8;
  }
  if (!(x >> 28)) {
    n = n + 4;
    x = x << 4;
  }
  if (!(x >> 30)) {
    n = n + 2;
    x = x << 2;
  }
  n = n - (x >> 31);

  return n;
}
#endif

ATTR_CONST ATTR_ARTIFICIAL static inline uint32_t ceil_log2(uint32_t x) {
  if (!x) {
    return 0;
  }
  return 32 - clz(x - 1);
}

/* helper functions for byte parity: 0 if even number of bits are set, 1 if odd number of bts are
 * set */
#if __has_builtin(__builtin_parity)
#define parity8 __builtin_parity
#elif __has_builtin(__builtin_popcount)
#define parity8(x) (__builtin_popcount(x) & 0x1)
#else
ATTR_CONST ATTR_ARTIFICIAL static inline uint8_t parity8(uint8_t n) {
  n ^= n >> 4;
  n ^= n >> 2;
  n ^= n >> 1;
  return !((~n) & 1);
}
#endif

#if !defined(__cplusplus)
#include <assert.h>

/* static_assert fallback */
#if !defined(_MSC_VER) && !defined(static_assert)
#define static_assert _Static_assert
#endif
#endif

#endif

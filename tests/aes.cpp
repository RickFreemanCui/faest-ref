/*
 *  SPDX-License-Identifier: MIT
 */

// Reference - https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
// Tested against Appendix C.1

#include "../aes.h"
#include "tvs_aes.hpp"

#include <boost/test/unit_test.hpp>
#include <array>

namespace {
  typedef std::array<uint8_t, 16> block_t;
  typedef std::array<uint8_t, 24> block192_t;
  typedef std::array<uint8_t, 32> block256_t;
} // namespace

namespace aes_ctr_128_tv {
  constexpr std::array<uint8_t, 16> key{
      0x42, 0x13, 0x4f, 0x71, 0x34, 0x89, 0x1b, 0x16,
      0x82, 0xa8, 0xab, 0x56, 0x76, 0x27, 0x30, 0x0c,
  };
  constexpr std::array<uint8_t, 16> in{
      0x7b, 0x60, 0x66, 0xd6, 0x5a, 0x73, 0xd6, 0x00,
      0xa0, 0xae, 0xf0, 0x1c, 0x8b, 0x19, 0x17, 0x40,
  };
  constexpr std::array<uint8_t, 16> out{
      0x89, 0x13, 0xaf, 0x07, 0x31, 0xb5, 0x81, 0xdf,
      0x8a, 0x0a, 0xb5, 0x6e, 0x08, 0x3c, 0x6b, 0x7c,
  };
  constexpr std::array<uint8_t, 200> expected_extended_witness{
      0x42, 0x13, 0x4f, 0x71, 0x34, 0x89, 0x1b, 0x16, 0x82, 0xa8, 0xab, 0x56, 0x76, 0x27, 0x30,
      0x0c, 0x8f, 0x17, 0xb1, 0x49, 0x0f, 0xd0, 0xda, 0xcd, 0xf2, 0xd9, 0xd1, 0xe8, 0xbe, 0xb9,
      0x03, 0xe9, 0x0e, 0x21, 0xd4, 0x69, 0x89, 0xaf, 0x43, 0x7f, 0x5d, 0xa1, 0x87, 0x11, 0x19,
      0x81, 0x05, 0xd0, 0x87, 0x51, 0x4e, 0x23, 0x7a, 0xc4, 0x76, 0xcc, 0x12, 0x2d, 0x39, 0x29,
      0x9f, 0x6f, 0xcc, 0x5c, 0x93, 0xb2, 0xa5, 0x47, 0x54, 0x8f, 0xbd, 0xd6, 0x4b, 0x4b, 0x6c,
      0x10, 0x08, 0xf9, 0x87, 0x12, 0xf1, 0xd6, 0x17, 0xbb, 0x6f, 0x27, 0x27, 0xb2, 0x07, 0x15,
      0xe4, 0x53, 0xfd, 0x65, 0x3d, 0xf0, 0x56, 0xdc, 0x23, 0x70, 0xe1, 0xd3, 0x3a, 0x75, 0x92,
      0xf0, 0x64, 0x1b, 0xa6, 0x76, 0x3b, 0x4e, 0xb3, 0xf8, 0xd9, 0xa6, 0xa1, 0x60, 0x52, 0xf2,
      0xe6, 0x85, 0xef, 0x07, 0x09, 0x84, 0x7e, 0x8e, 0x93, 0x93, 0x5f, 0x6d, 0xfb, 0x85, 0xf6,
      0x74, 0x06, 0xd4, 0xd7, 0x30, 0xec, 0xce, 0x0d, 0xeb, 0x43, 0x47, 0x21, 0x9c, 0xf2, 0x0f,
      0x19, 0x04, 0x6b, 0x9a, 0xe8, 0x14, 0x7d, 0x4a, 0xfa, 0x47, 0x52, 0x36, 0x92, 0x49, 0x4e,
      0x52, 0xf1, 0x5d, 0x25, 0xf4, 0x7b, 0x57, 0xea, 0xd5, 0xb1, 0x42, 0x7a, 0x9a, 0x0c, 0xd8,
      0xaf, 0xb5, 0x0a, 0xcb, 0xbc, 0xd1, 0x08, 0xfa, 0xfb, 0x38, 0x34, 0x0b, 0x05, 0x50, 0xb9,
      0x0c, 0xb2, 0x5d, 0x9a, 0x9f,
  };
} // namespace aes_ctr_128_tv

namespace rijndael_em_128_tv {
  constexpr std::array<uint8_t, 16> key = aes_ctr_128_tv::key;
  constexpr std::array<uint8_t, 16> in  = aes_ctr_128_tv::in;
  constexpr std::array<uint8_t, 16> out{
      0xb8, 0xcf, 0x49, 0x82, 0x1b, 0x05, 0xe3, 0xfd,
      0x4c, 0xb6, 0x61, 0x5c, 0x5f, 0x79, 0x77, 0x2f,
  };
  constexpr std::array<uint8_t, 160> expected_extended_witness{
      0x42, 0x13, 0x4f, 0x71, 0x34, 0x89, 0x1b, 0x16, 0x82, 0xa8, 0xab, 0x56, 0x76, 0x27, 0x30,
      0x0c, 0x12, 0x2d, 0x39, 0x29, 0x9f, 0x6f, 0xcc, 0x5c, 0x93, 0xb2, 0xa5, 0x47, 0x54, 0x8f,
      0xbd, 0xd6, 0x55, 0xc8, 0x8c, 0x8b, 0x8c, 0xc9, 0x97, 0x14, 0x5a, 0x76, 0xcb, 0xd6, 0x90,
      0xf4, 0x31, 0xba, 0xaa, 0x46, 0x42, 0x9e, 0x6c, 0x09, 0xea, 0x2e, 0xc0, 0x6c, 0x1d, 0x85,
      0x1b, 0xc9, 0xc3, 0x5d, 0x89, 0x66, 0x60, 0x4b, 0x48, 0xda, 0x00, 0xae, 0x52, 0xfb, 0x67,
      0x55, 0x69, 0x0d, 0x10, 0x8d, 0x3a, 0x84, 0x49, 0xd4, 0x37, 0x97, 0xab, 0x90, 0x44, 0x2d,
      0x41, 0x3f, 0x00, 0xab, 0x03, 0x15, 0x4a, 0x33, 0xde, 0x00, 0x71, 0x05, 0xaa, 0x3e, 0x4a,
      0x7a, 0xdf, 0x9e, 0xcc, 0x23, 0x29, 0xe7, 0xb0, 0xe5, 0x1c, 0x09, 0x83, 0xf2, 0x88, 0x86,
      0xae, 0xc2, 0x67, 0x31, 0xa2, 0xbd, 0x5c, 0x4a, 0x5b, 0xb4, 0xfb, 0x2d, 0xf1, 0x52, 0x0d,
      0xce, 0xde, 0x23, 0xb5, 0xd1, 0xf5, 0xb6, 0x81, 0x64, 0xd9, 0xbc, 0x9b, 0xc1, 0xea, 0x46,
      0x51, 0x91, 0x7c, 0x18, 0x81, 0xf7, 0x60, 0x6a, 0x9f, 0x77,
  };
} // namespace rijndael_em_128_tv

namespace aes_ctr_192_tv {
  constexpr std::array<uint8_t, 24> key{
      0x7f, 0x64, 0xa4, 0x6b, 0xbd, 0x02, 0x67, 0x2c, 0xed, 0x19, 0xfb, 0x73,
      0x5b, 0xf0, 0x46, 0xaf, 0x23, 0x6e, 0x38, 0x79, 0x85, 0x13, 0x79, 0xd3,
  };
  constexpr std::array<uint8_t, 32> in{
      0x2f, 0xae, 0x1b, 0x7c, 0x4a, 0x8f, 0xb6, 0x1c, 0x15, 0x7c, 0x4d,
      0xe2, 0x9d, 0x35, 0x62, 0x33, 0x63, 0x94, 0x75, 0x39, 0x50, 0x2d,
      0x7e, 0xa5, 0xf7, 0x33, 0xd0, 0xca, 0x3c, 0xc2, 0xb5, 0xd0,
  };
  constexpr std::array<uint8_t, 32> out{
      0x1a, 0xb4, 0x2c, 0x3c, 0xde, 0xb6, 0xb5, 0x08, 0xff, 0xc8, 0x3d,
      0x5b, 0x48, 0x9f, 0x62, 0xca, 0xdd, 0x3f, 0x53, 0x92, 0xbb, 0x4b,
      0x0a, 0xe3, 0xed, 0xf0, 0xe9, 0xe7, 0x0c, 0x4d, 0xb4, 0x2c,
  };
  constexpr std::array<uint8_t, 408> expected_extended_witness{
      0x7f, 0x64, 0xa4, 0x6b, 0xbd, 0x02, 0x67, 0x2c, 0xed, 0x19, 0xfb, 0x73, 0x5b, 0xf0, 0x46,
      0xaf, 0x23, 0x6e, 0x38, 0x79, 0x85, 0x13, 0x79, 0xd3, 0x03, 0xd2, 0xc2, 0xfc, 0x1a, 0x19,
      0xe6, 0x18, 0xfb, 0x09, 0x6b, 0xc2, 0x89, 0xf0, 0x8b, 0x5b, 0xbf, 0xa7, 0x98, 0xb6, 0xf9,
      0x0d, 0x1b, 0x70, 0x5e, 0x47, 0x3d, 0xf7, 0x0e, 0xd5, 0x87, 0x6d, 0x53, 0x5d, 0x4e, 0xde,
      0x68, 0x4d, 0x36, 0xf0, 0x41, 0xa6, 0x08, 0x04, 0xb4, 0x74, 0x3e, 0x81, 0x89, 0xb3, 0x12,
      0x1b, 0x1b, 0x61, 0x0c, 0x07, 0x10, 0x84, 0x66, 0xe9, 0x28, 0x3d, 0xe2, 0xee, 0x5e, 0x0d,
      0x6a, 0xb4, 0x90, 0xf0, 0xf4, 0x8d, 0x7d, 0xa6, 0x3c, 0x2c, 0xd5, 0xca, 0x8f, 0x9f, 0xa8,
      0x34, 0x74, 0xfb, 0x55, 0x2c, 0x06, 0x28, 0xce, 0x38, 0x24, 0x33, 0xaf, 0x5b, 0x4a, 0x31,
      0x29, 0x6b, 0xcd, 0xdc, 0x7e, 0x9b, 0xaf, 0x4a, 0x26, 0x05, 0xa0, 0xc7, 0x64, 0xdd, 0xa3,
      0xa1, 0xb1, 0x67, 0x75, 0xf1, 0x41, 0x17, 0x9d, 0xc0, 0x5c, 0xcc, 0xa7, 0x36, 0x84, 0x79,
      0x2f, 0x2f, 0xc1, 0x26, 0x01, 0xd3, 0x04, 0xe9, 0x92, 0xbc, 0xad, 0xfd, 0x08, 0xec, 0xc8,
      0xf8, 0x73, 0x66, 0x3d, 0x16, 0x68, 0x11, 0xfc, 0xc0, 0xa0, 0xe1, 0x6f, 0xa0, 0x07, 0x90,
      0x69, 0x2e, 0x0e, 0x50, 0x31, 0x7d, 0xb5, 0xda, 0xc6, 0x4c, 0xdd, 0x4b, 0xf7, 0x49, 0x4d,
      0xa0, 0x12, 0x9e, 0x20, 0x28, 0x8f, 0x0d, 0x00, 0xb6, 0x6e, 0xdf, 0x23, 0x1b, 0x1b, 0x28,
      0xed, 0x78, 0x71, 0x61, 0xf6, 0xa4, 0xa7, 0x6b, 0xa0, 0x9a, 0x92, 0x6a, 0xd7, 0x4f, 0x97,
      0x1f, 0xff, 0x39, 0xc1, 0x09, 0x44, 0xdf, 0x9c, 0x15, 0xf1, 0xd2, 0x55, 0xe5, 0x0d, 0x00,
      0xa2, 0x23, 0x3e, 0xa7, 0x85, 0x8c, 0xd4, 0x56, 0x9c, 0xcd, 0xbd, 0xe7, 0x47, 0x66, 0xd9,
      0x5e, 0xe0, 0x85, 0x3f, 0x1c, 0x3a, 0x77, 0x66, 0x3b, 0x33, 0xde, 0xc0, 0x73, 0x62, 0x0f,
      0x2a, 0x56, 0xa0, 0x7c, 0x4a, 0xb4, 0x72, 0xdf, 0x40, 0x4b, 0x4e, 0x5e, 0x4f, 0x41, 0xd7,
      0x23, 0xe6, 0xd5, 0xf6, 0x4d, 0x6b, 0x94, 0x02, 0x06, 0xcd, 0x03, 0x49, 0xcf, 0x32, 0x78,
      0xee, 0x29, 0xc2, 0xed, 0x36, 0x0c, 0x45, 0x3a, 0xdb, 0xfe, 0xe2, 0xf6, 0x80, 0xe6, 0xe9,
      0x27, 0x1c, 0x29, 0x4f, 0xa9, 0x5f, 0xd6, 0xcf, 0x6b, 0xcb, 0x93, 0x1b, 0x8f, 0x3c, 0x6f,
      0xcc, 0x54, 0x8f, 0x12, 0x2c, 0x0c, 0x6b, 0x4c, 0xe3, 0xbe, 0x0b, 0xe0, 0x9b, 0x72, 0x0f,
      0x8c, 0xea, 0x4d, 0x09, 0x48, 0x7f, 0x3c, 0xe1, 0xec, 0xdb, 0x31, 0x95, 0x85, 0x2b, 0x2e,
      0xfd, 0xd6, 0xb3, 0xf0, 0xa9, 0x2a, 0xb1, 0x80, 0xc4, 0xf2, 0x05, 0xd5, 0x85, 0x7b, 0x8c,
      0xe4, 0x80, 0x15, 0x03, 0x82, 0x90, 0x9c, 0x29, 0x89, 0xdd, 0x3d, 0x5a, 0x68, 0xe3, 0xb6,
      0x83, 0xd1, 0xc4, 0xa1, 0x3e, 0xb5, 0x8b, 0x33, 0x27, 0x8c, 0x7e, 0x6f, 0x04, 0x18, 0xcd,
      0x2f, 0x13, 0xeb};
} // namespace aes_ctr_192_tv

namespace rijndael_em_192_tv {
  constexpr std::array<uint8_t, 24> key = {0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f, 0xbe, 0x52,
                                           0xc0, 0xcd, 0x0b, 0xed, 0xbe, 0x6a, 0x4c, 0x04,
                                           0xb3, 0x75, 0x89, 0x7d, 0x36, 0x9b, 0x7e, 0x62};
  constexpr std::array<uint8_t, 24> in  = {
      0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03, 0x86,
      0xaf, 0xa3, 0xd3, 0xf2, 0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19,
  };
  constexpr std::array<uint8_t, 24> out = {0xbf, 0x71, 0x16, 0xfd, 0x88, 0xb0, 0x75, 0x2f,
                                           0x06, 0x01, 0xc3, 0x14, 0xdc, 0xbb, 0xa6, 0x25,
                                           0x6b, 0x8e, 0xc4, 0x5b, 0xd2, 0x4e, 0x10, 0x84};

  constexpr std::array<uint8_t, 288> expected_extended_witness{
      0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f, 0xbe, 0x52, 0xc0, 0xcd, 0x0b, 0xed, 0xbe, 0x6a, 0x4c,
      0x04, 0xb3, 0x75, 0x89, 0x7d, 0x36, 0x9b, 0x7e, 0x62, 0xd9, 0xc5, 0x30, 0x42, 0x93, 0xe4,
      0xdb, 0x3c, 0x44, 0xdd, 0x13, 0x21, 0x82, 0xc5, 0xc9, 0x53, 0x8f, 0x7a, 0xa0, 0xd7, 0xa7,
      0xea, 0xd8, 0x7f, 0x6c, 0xf8, 0x6a, 0x05, 0x27, 0xb6, 0x50, 0xbf, 0x53, 0xf1, 0x60, 0x05,
      0x9b, 0xab, 0x5b, 0xf1, 0x6b, 0xaf, 0xe4, 0xde, 0x81, 0xd3, 0xd4, 0x6d, 0x1a, 0x7b, 0xd6,
      0x52, 0x5b, 0x14, 0xbb, 0xa9, 0x02, 0x9d, 0x2c, 0x62, 0x99, 0xfd, 0xd6, 0x4a, 0x85, 0x79,
      0x7f, 0xdf, 0x1e, 0x1f, 0x52, 0x46, 0x04, 0x21, 0x1e, 0xa9, 0x3a, 0xf6, 0xe6, 0xf9, 0x3c,
      0x76, 0x91, 0xed, 0xac, 0xdc, 0x5c, 0x14, 0x6a, 0x6d, 0x71, 0x37, 0x29, 0x8d, 0x3c, 0xeb,
      0x16, 0xa1, 0xdc, 0xb9, 0x8f, 0x13, 0xba, 0xab, 0x9c, 0x8d, 0x4a, 0x9d, 0xe6, 0xd9, 0xb5,
      0xc2, 0xb4, 0xfc, 0xc9, 0x86, 0x79, 0x2f, 0x84, 0x5a, 0x9a, 0x22, 0xa2, 0x94, 0xae, 0x7e,
      0xf2, 0x77, 0x4d, 0xb1, 0x5c, 0x7c, 0x29, 0xd2, 0x92, 0x61, 0x4a, 0xf6, 0xa8, 0x0d, 0x5f,
      0xb2, 0x2d, 0xe1, 0x23, 0x2c, 0x5d, 0xe2, 0x4f, 0x4f, 0x27, 0x08, 0x7a, 0x21, 0xe3, 0xf0,
      0xdb, 0xde, 0x54, 0xa6, 0x9c, 0x6e, 0x78, 0x03, 0xd6, 0x0b, 0x61, 0x3f, 0x5d, 0x6d, 0xe8,
      0xe6, 0x37, 0x1f, 0x1a, 0x48, 0xee, 0x80, 0xd5, 0xae, 0x45, 0xad, 0x0b, 0x28, 0xc4, 0x10,
      0x28, 0xb5, 0xfb, 0xf0, 0x58, 0xf1, 0x18, 0x08, 0x77, 0xd8, 0x41, 0xb5, 0x95, 0xa3, 0x9e,
      0xba, 0x35, 0x11, 0x0d, 0x2b, 0x87, 0xad, 0x87, 0xaf, 0x6d, 0xa2, 0xfe, 0x81, 0xd5, 0xa3,
      0x86, 0x16, 0x30, 0xa6, 0x8b, 0xb8, 0x0c, 0xcf, 0x60, 0xe7, 0xe8, 0x69, 0x7a, 0xfd, 0xe4,
      0xb3, 0xfa, 0x48, 0x7a, 0x9e, 0x9f, 0xd1, 0xda, 0x75, 0xf9, 0xe1, 0x29, 0x95, 0xa3, 0x7c,
      0xd2, 0xf0, 0xcb, 0x96, 0xc1, 0x6c, 0x4d, 0x24, 0x25, 0xb5, 0xd8, 0xab, 0x19, 0x69, 0x21,
      0x84, 0x79, 0x6b,
  };
} // namespace rijndael_em_192_tv

namespace aes_ctr_256_tv {
  constexpr std::array<uint8_t, 32> key{
      0xa9, 0x86, 0x63, 0xac, 0x8a, 0x05, 0x78, 0xbe, 0xd7, 0x2c, 0x80,
      0x91, 0x07, 0x67, 0xce, 0x11, 0xf1, 0x79, 0x59, 0xde, 0x6a, 0x99,
      0xbb, 0xdc, 0x75, 0xb2, 0x04, 0x63, 0x6f, 0x1d, 0xd2, 0x5f,
  };
  constexpr std::array<uint8_t, 32> in{
      0x78, 0xff, 0xd6, 0xd1, 0x95, 0x73, 0xdb, 0x9f, 0xa4, 0x08, 0xe8,
      0xcb, 0x29, 0xf8, 0x2e, 0x27, 0x96, 0xe0, 0x8f, 0x0d, 0xf9, 0xf1,
      0x8a, 0x1d, 0x67, 0xd5, 0xec, 0x22, 0x14, 0x92, 0x32, 0x17,
  };
  constexpr std::array<uint8_t, 32> out{
      0xef, 0x34, 0x98, 0xa1, 0x9e, 0xab, 0x0a, 0x9e, 0xad, 0x99, 0xd7,
      0xf2, 0xe1, 0x68, 0xf5, 0xad, 0x18, 0xdf, 0x02, 0x86, 0x6d, 0xf4,
      0x2b, 0x80, 0x24, 0xe3, 0x9e, 0x24, 0xeb, 0x51, 0x83, 0x67,
  };
  constexpr std::array<uint8_t, 500> expected_extended_witness{
      0xa9, 0x86, 0x63, 0xac, 0x8a, 0x05, 0x78, 0xbe, 0xd7, 0x2c, 0x80, 0x91, 0x07, 0x67, 0xce,
      0x11, 0xf1, 0x79, 0x59, 0xde, 0x6a, 0x99, 0xbb, 0xdc, 0x75, 0xb2, 0x04, 0x63, 0x6f, 0x1d,
      0xd2, 0x5f, 0x0c, 0x33, 0xac, 0x04, 0x40, 0x86, 0xe1, 0x5e, 0xe9, 0x57, 0x02, 0x00, 0x05,
      0xe9, 0x4c, 0x3c, 0x04, 0x4b, 0xfa, 0x09, 0x22, 0xb2, 0x02, 0x9b, 0xb3, 0x0d, 0xee, 0x2e,
      0xc5, 0x4f, 0x55, 0x9e, 0x42, 0x9a, 0x50, 0xea, 0x99, 0xc8, 0x63, 0x25, 0xf8, 0x6e, 0x3b,
      0xba, 0x2c, 0x41, 0xec, 0x2a, 0x12, 0xdd, 0x13, 0x5c, 0x3e, 0x38, 0x45, 0x05, 0xc0, 0x36,
      0xe1, 0xff, 0x8f, 0xdb, 0xd5, 0xfd, 0x31, 0xb6, 0x0a, 0xbe, 0x97, 0x89, 0x54, 0x0e, 0xd5,
      0x01, 0x46, 0xe9, 0x31, 0x0f, 0x57, 0xd5, 0xbc, 0x54, 0x19, 0x6f, 0x11, 0x25, 0xe0, 0x38,
      0x14, 0xd4, 0xa1, 0x85, 0xe0, 0xd8, 0x30, 0x53, 0x08, 0xcf, 0x91, 0x81, 0x03, 0xa6, 0x0d,
      0xf8, 0x83, 0xd9, 0x87, 0x61, 0x22, 0xfa, 0x5a, 0x57, 0xda, 0x1d, 0x5b, 0x22, 0xe9, 0x6c,
      0xf0, 0x86, 0x69, 0x76, 0x76, 0x6e, 0xaa, 0xa5, 0xe4, 0x6c, 0xee, 0xce, 0x80, 0x99, 0xab,
      0x17, 0xb7, 0x79, 0xd2, 0x0f, 0x84, 0x88, 0x1a, 0xcd, 0x0a, 0x35, 0x0e, 0xfc, 0x5b, 0x26,
      0xae, 0x99, 0x23, 0x51, 0xdd, 0xf8, 0x46, 0x7a, 0xc9, 0xa3, 0x6c, 0x58, 0x1a, 0x9d, 0xef,
      0x32, 0x5c, 0x25, 0x6f, 0x0a, 0xec, 0x85, 0x64, 0x02, 0xb2, 0x0e, 0xcd, 0x7d, 0x45, 0x7c,
      0xc3, 0x6e, 0x7c, 0x92, 0xf6, 0xb8, 0x1e, 0x1e, 0x4b, 0x22, 0x53, 0x91, 0x5b, 0x5b, 0x7d,
      0xe0, 0x4d, 0xb3, 0x1d, 0xf6, 0x5f, 0xd7, 0x08, 0xe8, 0x29, 0x59, 0xea, 0x93, 0xdb, 0xc4,
      0xa9, 0xd5, 0xc8, 0x52, 0xa1, 0x4a, 0xff, 0x5c, 0x35, 0xe4, 0x3f, 0x3e, 0xf9, 0x11, 0x85,
      0x9c, 0xca, 0x5a, 0x1f, 0x05, 0x7a, 0xbe, 0xb6, 0x76, 0xd7, 0xf2, 0xaf, 0x70, 0xcc, 0x3c,
      0xa7, 0x33, 0xf0, 0xea, 0x8a, 0x41, 0x59, 0xef, 0x5c, 0xc9, 0x6b, 0x3c, 0x06, 0x70, 0xf7,
      0x01, 0xc9, 0xc9, 0xc6, 0x1c, 0xcb, 0xa9, 0x75, 0xbf, 0x50, 0x6f, 0x8f, 0x99, 0xb0, 0x32,
      0xe7, 0xe6, 0xce, 0x0a, 0x7d, 0x33, 0x89, 0x6d, 0xbb, 0xb4, 0xde, 0x6c, 0x4c, 0x78, 0x93,
      0x51, 0xfc, 0xe9, 0x13, 0xaf, 0x36, 0x42, 0xcd, 0x3c, 0xfa, 0x9d, 0x5d, 0x88, 0x20, 0xd5,
      0xf1, 0xd0, 0x31, 0x08, 0xe7, 0xcc, 0xd7, 0x28, 0x31, 0x3d, 0xb4, 0xb1, 0x54, 0x08, 0x15,
      0x40, 0xb1, 0xcd, 0xab, 0xcb, 0x08, 0xff, 0xa1, 0x23, 0x27, 0x1d, 0xab, 0xa1, 0x9b, 0x3c,
      0x99, 0xf4, 0x0d, 0x23, 0x25, 0x2a, 0xa9, 0xe6, 0x9f, 0x9f, 0x4e, 0xd1, 0xf0, 0xc2, 0x75,
      0xc3, 0x15, 0x71, 0x04, 0x46, 0x2b, 0x00, 0x15, 0xc8, 0x09, 0x81, 0xf2, 0x43, 0xfa, 0x88,
      0xce, 0x85, 0x60, 0x5d, 0xf2, 0x34, 0x1d, 0x01, 0x10, 0x9d, 0x6f, 0xbc, 0x7e, 0x78, 0x6b,
      0x5c, 0x86, 0xad, 0xce, 0x95, 0x75, 0x35, 0xdd, 0x77, 0xfb, 0x2c, 0x80, 0x73, 0x7e, 0x3c,
      0xac, 0x40, 0xcf, 0x61, 0xea, 0xd2, 0x81, 0x30, 0xaa, 0x99, 0x93, 0x58, 0x10, 0x98, 0x71,
      0xf0, 0x9b, 0x42, 0x0f, 0xbc, 0xb9, 0xef, 0x69, 0xeb, 0x0c, 0x6c, 0xdb, 0x95, 0xb8, 0x52,
      0x04, 0x0b, 0xa2, 0x81, 0x88, 0x3c, 0x39, 0xb0, 0xb9, 0x40, 0xe6, 0xa1, 0x52, 0xce, 0x96,
      0x34, 0x04, 0xbe, 0x87, 0x82, 0x2a, 0x0d, 0x82, 0x53, 0xdd, 0xd3, 0x5b, 0x21, 0x76, 0x4a,
      0x7a, 0x4b, 0x77, 0xa2, 0x5b, 0x6a, 0xc0, 0x47, 0x44, 0x3e, 0xd1, 0xb8, 0xde, 0x3f, 0xff,
      0xfb, 0x31, 0x97, 0xa9, 0xf1,
  };
} // namespace aes_ctr_256_tv

namespace rijndael_em_256_tv {
  constexpr std::array<uint8_t, 32> key{
      0xc0, 0xcd, 0x0b, 0xed, 0xbe, 0x6a, 0x4c, 0x04, 0xb3, 0x75, 0x89,
      0x7d, 0x36, 0x9b, 0x7e, 0x62, 0xaa, 0x6a, 0x6f, 0x17, 0x13, 0xd2,
      0x7a, 0x71, 0xfe, 0x98, 0x9e, 0x93, 0xdc, 0x79, 0xd2, 0x7d,
  };
  constexpr std::array<uint8_t, 32> in{
      0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03,
      0x86, 0xaf, 0xa3, 0xd3, 0xf2, 0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26,
      0x6c, 0x19, 0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f, 0xbe, 0x52,
  };
  constexpr std::array<uint8_t, 32> out = {
      0xf4, 0x1b, 0x6b, 0xb2, 0x22, 0x5c, 0xaf, 0xfc, 0x82, 0x31, 0xcc,
      0xe0, 0x21, 0x9e, 0x2c, 0xcc, 0xb0, 0xf8, 0x0e, 0x68, 0x0d, 0xf2,
      0xdf, 0xef, 0xca, 0x1b, 0x96, 0x57, 0x18, 0x42, 0x00, 0x25,
  };
  constexpr std::array<uint8_t, 448> expected_extended_witness{
      0xc0, 0xcd, 0x0b, 0xed, 0xbe, 0x6a, 0x4c, 0x04, 0xb3, 0x75, 0x89, 0x7d, 0x36, 0x9b, 0x7e,
      0x62, 0xaa, 0x6a, 0x6f, 0x17, 0x13, 0xd2, 0x7a, 0x71, 0xfe, 0x98, 0x9e, 0x93, 0xdc, 0x79,
      0xd2, 0x7d, 0x7c, 0x40, 0x95, 0xc5, 0xcb, 0x47, 0x43, 0x45, 0xe6, 0x07, 0x47, 0xf8, 0xee,
      0xad, 0xd4, 0x15, 0x02, 0xbf, 0x50, 0x8a, 0x91, 0xcd, 0x1f, 0x39, 0x57, 0x33, 0x9e, 0x0f,
      0xd4, 0x9f, 0x7e, 0x60, 0x45, 0x70, 0x29, 0x73, 0x06, 0x79, 0xd2, 0xbc, 0xba, 0x30, 0x3a,
      0x52, 0x69, 0x50, 0x58, 0x47, 0xa8, 0xcf, 0x06, 0x1b, 0x17, 0xe8, 0xee, 0x7d, 0xb8, 0x1a,
      0x90, 0xc6, 0x93, 0x60, 0x71, 0x03, 0x82, 0x67, 0xed, 0x88, 0xcf, 0xdb, 0x86, 0xb2, 0x09,
      0x87, 0xe4, 0x9a, 0x36, 0xa5, 0x03, 0xca, 0x0a, 0x74, 0xea, 0xaa, 0xe6, 0xce, 0xef, 0x2b,
      0xc4, 0x0b, 0x9e, 0xdf, 0x83, 0x88, 0x46, 0x6f, 0x74, 0xd8, 0x66, 0x36, 0x45, 0x5f, 0xd5,
      0xb1, 0x5a, 0x82, 0xd0, 0x19, 0x8c, 0x31, 0xd2, 0x8b, 0x6e, 0xef, 0x92, 0x87, 0x65, 0x6c,
      0x94, 0x5b, 0x37, 0x10, 0x2f, 0xb0, 0x43, 0x62, 0x41, 0x11, 0x2b, 0xd8, 0x58, 0x7d, 0xd0,
      0x7c, 0xb8, 0x07, 0x9a, 0x17, 0x81, 0xd8, 0xd2, 0xc8, 0xd4, 0x8d, 0xb1, 0x51, 0xb6, 0x1d,
      0x98, 0xe9, 0x8f, 0xdc, 0xdf, 0x12, 0xac, 0x7e, 0x5d, 0x71, 0x81, 0xe6, 0xcd, 0x19, 0x68,
      0x66, 0xa8, 0xe7, 0x6d, 0xf9, 0xf5, 0xbc, 0x2f, 0xf0, 0xe9, 0xe1, 0x98, 0xdb, 0xea, 0xd4,
      0x7b, 0x2e, 0x81, 0x3b, 0x86, 0x74, 0x24, 0x19, 0xc0, 0x94, 0x20, 0x43, 0xdf, 0x3d, 0xcd,
      0xe6, 0xa7, 0xbb, 0xf7, 0x2a, 0x75, 0x2d, 0x77, 0x82, 0xa1, 0x0b, 0x76, 0x28, 0x15, 0x78,
      0xa4, 0xad, 0xc2, 0x88, 0x73, 0x8c, 0xb6, 0x5d, 0x99, 0x17, 0xec, 0xab, 0x6d, 0x2a, 0xc9,
      0x3c, 0x0f, 0xb4, 0xcf, 0x57, 0x84, 0x8b, 0xb8, 0x7f, 0x4e, 0xff, 0xb7, 0xd0, 0xf1, 0x6c,
      0x74, 0xd7, 0xe0, 0x9f, 0x25, 0x2f, 0xbb, 0x46, 0x9e, 0x36, 0xd9, 0xc4, 0xc7, 0x55, 0x9a,
      0x2c, 0x8b, 0x73, 0xf1, 0xc8, 0x04, 0x74, 0x49, 0xbc, 0xc5, 0x01, 0xbc, 0x08, 0x64, 0x48,
      0x06, 0x4b, 0xa2, 0x61, 0x5d, 0x8f, 0x2b, 0x35, 0x2a, 0xd8, 0xe3, 0x43, 0x1b, 0xb8, 0x72,
      0x58, 0x55, 0x93, 0xf1, 0x77, 0x31, 0x88, 0xc9, 0x92, 0x14, 0xef, 0x4f, 0xe6, 0x86, 0x41,
      0x79, 0x50, 0xb5, 0x8e, 0x17, 0x43, 0x40, 0x78, 0x62, 0x72, 0x83, 0x11, 0xb1, 0x91, 0xfd,
      0x94, 0x85, 0x53, 0x93, 0xf3, 0xb7, 0xe6, 0x69, 0x06, 0xb0, 0x03, 0x94, 0xd5, 0x00, 0x57,
      0x80, 0xb1, 0xb2, 0xe3, 0x62, 0xee, 0x61, 0x4b, 0x0c, 0x07, 0x10, 0x16, 0xd1, 0x22, 0x90,
      0x2a, 0xfd, 0xcc, 0xcf, 0x49, 0x8f, 0x1a, 0xd6, 0x3a, 0x4d, 0x8c, 0x81, 0xda, 0x2c, 0x75,
      0x58, 0x6f, 0xc5, 0xe2, 0x5f, 0x11, 0x6e, 0xf8, 0x30, 0x95, 0x5e, 0x82, 0xed, 0x39, 0xe7,
      0xd9, 0xea, 0x00, 0x29, 0x59, 0xd4, 0x33, 0x37, 0x50, 0x58, 0xd9, 0xf3, 0xf5, 0xe4, 0xe5,
      0x13, 0x18, 0xd3, 0x4a, 0x59, 0x9b, 0xeb, 0x0a, 0xc0, 0xed, 0xeb, 0x20, 0x98, 0xf9, 0x23,
      0x6c, 0x5d, 0xfc, 0x86, 0x1c, 0x41, 0xdd, 0xc4, 0x62, 0x4b, 0x6c, 0x20, 0xa3,
  };
} // namespace rijndael_em_256_tv

BOOST_AUTO_TEST_SUITE(aes)

BOOST_AUTO_TEST_CASE(test_aes128) {
  constexpr uint8_t key_128[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  constexpr uint8_t plaintext_128[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  constexpr block_t expected_128 = {
      0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
      0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };

  aes_round_keys_t ctx;
  aes128_init_round_keys(&ctx, key_128);

  block_t output_128;
  aes128_encrypt_block(&ctx, plaintext_128, output_128.data());

  BOOST_TEST(output_128 == expected_128);
}

BOOST_AUTO_TEST_CASE(test_aes192) {
  constexpr uint8_t key_192[24] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  };
  constexpr uint8_t plaintext_192[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  constexpr block_t expected_192 = {
      0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
      0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
  };

  aes_round_keys_t ctx;
  aes192_init_round_keys(&ctx, key_192);

  block_t output_192;
  aes192_encrypt_block(&ctx, plaintext_192, output_192.data());

  BOOST_TEST(output_192 == expected_192);
}

BOOST_AUTO_TEST_CASE(test_aes256) {
  constexpr uint8_t key_256[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  constexpr uint8_t plaintext_256[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  constexpr block_t expected_256 = {
      0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
      0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
  };

  aes_round_keys_t ctx;
  aes256_init_round_keys(&ctx, key_256);

  block_t output_256;
  aes256_encrypt_block(&ctx, plaintext_256, output_256.data());

  BOOST_TEST(output_256 == expected_256);
}

BOOST_AUTO_TEST_CASE(test_rijndael192) {
  constexpr block192_t key_192       = {0x80, 0x00};
  constexpr block192_t expected_192  = {0x56, 0x4d, 0x36, 0xfd, 0xeb, 0x8b, 0xf7, 0xe2,
                                        0x75, 0xf0, 0x10, 0xb2, 0xf5, 0xee, 0x69, 0xcf,
                                        0xea, 0xe6, 0x7e, 0xa0, 0xe3, 0x7e, 0x32, 0x09};
  constexpr block192_t plaintext_192 = {0};

  aes_round_keys_t ctx;
  rijndael192_init_round_keys(&ctx, key_192.data());

  block192_t output_192;
  rijndael192_encrypt_block(&ctx, plaintext_192.data(), output_192.data());

  BOOST_TEST(output_192 == expected_192);
}

BOOST_AUTO_TEST_CASE(test_rijndael256) {
  constexpr block256_t key_256      = {0x80, 0x00};
  constexpr block256_t expected_256 = {
      0xE6, 0x2A, 0xBC, 0xE0, 0x69, 0x83, 0x7B, 0x65, 0x30, 0x9B, 0xE4,
      0xED, 0xA2, 0xC0, 0xE1, 0x49, 0xFE, 0x56, 0xC0, 0x7B, 0x70, 0x82,
      0xD3, 0x28, 0x7F, 0x59, 0x2C, 0x4A, 0x49, 0x27, 0xA2, 0x77,
  };
  constexpr block256_t plaintext_256 = {0};

  aes_round_keys_t ctx;
  rijndael256_init_round_keys(&ctx, key_256.data());

  block256_t output_256;
  rijndael256_encrypt_block(&ctx, plaintext_256.data(), output_256.data());

  BOOST_TEST(output_256 == expected_256);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_aes128) {
  std::array<uint8_t, 200> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_128S); // Just using the FAEST-128s
  uint8_t* extwit =
      aes_extend_witness(aes_ctr_128_tv::key.data(), aes_ctr_128_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 200);
  free(extwit);

  BOOST_TEST(extended_witness == aes_ctr_128_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_rijndael_em128) {
  std::array<uint8_t, 160> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_EM_128S); // Just using the FAEST-128s
  uint8_t* extwit =
      aes_extend_witness(rijndael_em_128_tv::key.data(), rijndael_em_128_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 160);
  free(extwit);

  BOOST_TEST(extended_witness == rijndael_em_128_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_aes192) {
  std::array<uint8_t, 408> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_192S); // Just using the FAEST-128s
  uint8_t* extwit =
      aes_extend_witness(aes_ctr_192_tv::key.data(), aes_ctr_192_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 408);
  free(extwit);

  BOOST_TEST(extended_witness == aes_ctr_192_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_rijndael_em192) {
  std::array<uint8_t, 288> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_EM_192S); // Just using the FAEST-192s
  uint8_t* extwit =
      aes_extend_witness(rijndael_em_192_tv::key.data(), rijndael_em_192_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 288);
  free(extwit);

  BOOST_TEST(extended_witness == rijndael_em_192_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_aes256) {
  std::array<uint8_t, 500> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_256S); // Just using the FAEST-128s
  uint8_t* extwit =
      aes_extend_witness(aes_ctr_256_tv::key.data(), aes_ctr_256_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 500);
  free(extwit);

  BOOST_TEST(extended_witness == aes_ctr_256_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_rijndael_em256) {
  std::array<uint8_t, 448> extended_witness = {};
  faest_paramset_t params = faest_get_paramset(FAEST_EM_256S); // Just using the FAEST-256s
  uint8_t* extwit =
      aes_extend_witness(rijndael_em_256_tv::key.data(), rijndael_em_256_tv::in.data(), &params);
  memcpy(extended_witness.data(), extwit, 448);
  free(extwit);

  BOOST_TEST(extended_witness == rijndael_em_256_tv::expected_extended_witness);
}

BOOST_AUTO_TEST_SUITE_END()

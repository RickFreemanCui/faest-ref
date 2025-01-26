#ifndef TEST_VOLE_TVS_HPP
#define TEST_VOLE_TVS_HPP

#include <array>
#include <cstdint>

namespace bavc_tvs {
  namespace FAEST_128S {
    constexpr std::array<uint8_t, 32> h{
        0x38, 0xe7, 0x57, 0x0e, 0x97, 0x00, 0x39, 0x3e, 0x20, 0xec, 0x31,
        0xa7, 0x40, 0x3b, 0x15, 0x6d, 0x2d, 0x2b, 0x63, 0xa6, 0xf7, 0xa6,
        0x52, 0x19, 0xfb, 0x88, 0xeb, 0x00, 0x2a, 0x66, 0xfb, 0x2e,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x6f, 0x5a, 0xed, 0xf6, 0x08, 0x87, 0x3d, 0xd7, 0xfa, 0x41, 0xdf, 0x7f, 0x70,
        0x00, 0x6d, 0x7c, 0x65, 0xf3, 0xdd, 0x2f, 0x5d, 0x29, 0x33, 0x92, 0x69, 0xd0,
        0xff, 0x23, 0x7b, 0x23, 0xf7, 0xac, 0xef, 0x4f, 0xe6, 0x3e, 0x07, 0x88, 0xb3,
        0x3b, 0x05, 0xc7, 0xe8, 0x51, 0x66, 0x29, 0xc7, 0xe0, 0x34, 0xa6, 0x1e, 0x06,
        0xd0, 0xe1, 0x25, 0x12, 0x8a, 0x9c, 0xf8, 0x01, 0x8b, 0x15, 0xac, 0xd0,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x38, 0xac, 0x6c, 0xd1, 0x04, 0xad, 0x70, 0xab, 0x90, 0x6c, 0xf3, 0x8a, 0x1b,
        0xdf, 0x66, 0x0f, 0xfd, 0x39, 0x7c, 0x1d, 0xf1, 0x67, 0x3b, 0x42, 0x1f, 0x87,
        0x5c, 0x70, 0x75, 0x98, 0x67, 0x85, 0xa0, 0x09, 0x01, 0xfd, 0xbb, 0x56, 0x34,
        0xa4, 0x99, 0x23, 0x6d, 0x43, 0x8e, 0x4c, 0x5b, 0x31, 0x03, 0x5f, 0x59, 0x58,
        0x29, 0xb4, 0xeb, 0x0a, 0x26, 0x18, 0xbb, 0x5a, 0xf5, 0x5e, 0xc3, 0x68,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x7d, 0x2d, 0x49, 0x87, 0x77, 0xe2, 0xee, 0x7f, 0xda, 0x1a, 0x6f, 0xc7, 0xcd,
        0x66, 0x7a, 0x90, 0x0e, 0xca, 0x29, 0xe1, 0xd6, 0x6c, 0x9e, 0x22, 0xa1, 0xab,
        0x64, 0x58, 0xec, 0xc7, 0x15, 0xdf, 0xb8, 0xee, 0xd1, 0xfe, 0x27, 0x44, 0x49,
        0x75, 0x93, 0xc1, 0xe1, 0x6f, 0xb1, 0xb5, 0x89, 0x19, 0x38, 0xb2, 0x2b, 0xb5,
        0xc0, 0xcf, 0xe6, 0xa3, 0xb5, 0x19, 0x9f, 0xf3, 0x36, 0xe9, 0xb4, 0x3b,
    };
    constexpr std::array<uint8_t, 16> chall{
        0x49, 0x02, 0x82, 0x18, 0xd7, 0xff, 0xf3, 0x4d,
        0xd4, 0xb7, 0x50, 0x1f, 0xc6, 0x2a, 0xd3, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x21, 0x0e, 0xff, 0x84, 0x6d, 0xcf, 0x20, 0x52, 0xfc, 0x63, 0xe6, 0xe6, 0x22,
        0x13, 0x74, 0x9b, 0x45, 0x32, 0xf3, 0x28, 0x72, 0xd9, 0x31, 0xe7, 0xf5, 0x0b,
        0x08, 0x5a, 0x29, 0x30, 0x17, 0xb1, 0x5d, 0xcf, 0x36, 0x63, 0x55, 0x27, 0x66,
        0xf2, 0x20, 0x8a, 0x94, 0x31, 0x51, 0x68, 0x75, 0x81, 0xd4, 0xdb, 0x31, 0xf4,
        0xcf, 0x0f, 0x20, 0x73, 0x47, 0x56, 0xc8, 0x5d, 0x4d, 0xd3, 0xaf, 0xe7,
    };
  } // namespace FAEST_128S
  namespace FAEST_128F {
    constexpr std::array<uint8_t, 32> h{
        0xdd, 0x28, 0xa0, 0xf3, 0xf6, 0x1d, 0xbc, 0x92, 0xf9, 0x94, 0x47,
        0x8e, 0x2c, 0x0c, 0x19, 0x08, 0x99, 0xca, 0x7c, 0xbc, 0x0c, 0xbe,
        0xca, 0xf8, 0x8d, 0xa7, 0x1e, 0x32, 0xa7, 0xb5, 0xd5, 0x72,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x97, 0xf1, 0xbd, 0x39, 0xc1, 0x28, 0x49, 0x5e, 0x93, 0x1b, 0xc3, 0xf9, 0xc2,
        0xb5, 0xa0, 0x45, 0x32, 0x66, 0x94, 0x71, 0xc7, 0x99, 0xe7, 0x02, 0x7b, 0xb1,
        0x17, 0x37, 0x1d, 0xe4, 0x1e, 0x4b, 0x95, 0x69, 0x14, 0x55, 0xb9, 0x92, 0xc1,
        0x36, 0xf5, 0x50, 0x82, 0xf6, 0xa2, 0x3e, 0x8f, 0xaf, 0x4c, 0xe2, 0x9d, 0xf4,
        0xe3, 0x09, 0x82, 0x88, 0xb4, 0xda, 0x98, 0x8c, 0xe4, 0x58, 0x67, 0x63,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0xda, 0xfa, 0x5c, 0x73, 0x89, 0x82, 0x4e, 0x38, 0x8c, 0x70, 0xbb, 0xce, 0xb5,
        0xdc, 0x90, 0xfa, 0x7c, 0xa3, 0xf0, 0x06, 0x03, 0xe1, 0xca, 0x50, 0xae, 0xd1,
        0xed, 0x52, 0x57, 0x06, 0x8e, 0x0c, 0xf8, 0x5e, 0x9e, 0x89, 0xe9, 0xa2, 0x95,
        0x1d, 0xd1, 0x3e, 0xef, 0x8e, 0xc0, 0x8c, 0x67, 0xe1, 0x54, 0xa4, 0x38, 0xbf,
        0xa9, 0xc6, 0x2e, 0x97, 0x64, 0xd1, 0xab, 0x92, 0xac, 0xf5, 0xa8, 0x1e,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x6c, 0xa0, 0xd1, 0x33, 0xbe, 0x98, 0xd7, 0x0b, 0x5e, 0x75, 0xdc, 0xaa, 0x2f,
        0x6b, 0xb7, 0x74, 0xa7, 0x3a, 0xad, 0xae, 0xad, 0x87, 0xd1, 0xed, 0x17, 0xee,
        0x08, 0x7e, 0xa8, 0x65, 0x33, 0x38, 0xd0, 0xc5, 0x1d, 0xe8, 0xcd, 0x93, 0x28,
        0x01, 0xb3, 0x3f, 0x18, 0x26, 0xb9, 0x08, 0x40, 0x12, 0x3c, 0x32, 0xcc, 0x1e,
        0xa1, 0x51, 0xe8, 0x1c, 0x37, 0x41, 0x06, 0x09, 0x5d, 0x67, 0xc2, 0xb2,
    };
    constexpr std::array<uint8_t, 16> chall{
        0x6e, 0xbf, 0xa8, 0x6f, 0xb8, 0xde, 0xb9, 0x7c,
        0x1d, 0xb5, 0xf8, 0x2c, 0x9d, 0xba, 0x34, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x89, 0x25, 0x55, 0x25, 0xf9, 0x8f, 0xd3, 0xbc, 0xf1, 0x02, 0x6e, 0x05, 0xec,
        0xbf, 0xdc, 0x1c, 0x3f, 0x32, 0x2e, 0x48, 0x8f, 0x40, 0x4f, 0x73, 0xaa, 0xda,
        0x76, 0x10, 0xda, 0x62, 0x9d, 0xc7, 0xa3, 0x28, 0xc2, 0x9f, 0x50, 0xaa, 0x5d,
        0x2c, 0xeb, 0x5d, 0x5a, 0x1a, 0xcf, 0xf9, 0x6a, 0x02, 0x94, 0xb2, 0xa5, 0xb1,
        0x47, 0xff, 0xa6, 0x50, 0xaa, 0xaf, 0xc8, 0xcc, 0x10, 0x04, 0xe3, 0xbe,
    };
  } // namespace FAEST_128F
  namespace FAEST_192S {
    constexpr std::array<uint8_t, 48> h{
        0x9d, 0xcb, 0x1d, 0x53, 0x55, 0xb4, 0x5f, 0xd1, 0x24, 0x08, 0x09, 0x75,
        0xa9, 0xba, 0xc6, 0xde, 0x49, 0xc5, 0x55, 0x5a, 0x9c, 0x3a, 0x46, 0xa1,
        0x30, 0x20, 0x4f, 0xbe, 0xfe, 0xd8, 0xd0, 0xe4, 0x5b, 0x7c, 0x69, 0x55,
        0xf9, 0x14, 0x3a, 0x7b, 0x91, 0x6f, 0xb5, 0x12, 0x3f, 0xa3, 0x49, 0x8e,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0xd0, 0x39, 0x8f, 0x2d, 0xaf, 0xf5, 0xa0, 0x27, 0xb8, 0x2c, 0x6b, 0x60, 0xe4,
        0x98, 0x15, 0x16, 0xf0, 0x37, 0x80, 0x78, 0xb0, 0x2f, 0xdd, 0x1f, 0x41, 0x0f,
        0xa8, 0x7b, 0x73, 0x6c, 0x4a, 0x89, 0x3d, 0x07, 0x1c, 0x45, 0x4b, 0x10, 0xdb,
        0xd8, 0xc1, 0xde, 0x91, 0x5a, 0x29, 0x60, 0x83, 0xe6, 0xc3, 0xd9, 0x01, 0x09,
        0xa8, 0x98, 0xca, 0xed, 0x14, 0xbb, 0x01, 0x27, 0xfc, 0xaf, 0xf8, 0x20,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0xfb, 0x89, 0xc8, 0x3a, 0x63, 0x6c, 0xb6, 0x9c, 0x66, 0x9d, 0xfd, 0x26, 0xfd,
        0x7f, 0x2e, 0x8f, 0xce, 0x83, 0x1d, 0xe3, 0x3d, 0x11, 0x1e, 0xfc, 0x49, 0xdc,
        0x26, 0x7f, 0x4e, 0x9e, 0x5b, 0x0a, 0x12, 0x30, 0x15, 0x7c, 0x2f, 0xc3, 0x17,
        0xef, 0x13, 0x64, 0x33, 0xca, 0x45, 0x96, 0x45, 0x89, 0x32, 0x3a, 0x74, 0xdc,
        0xef, 0xb5, 0xca, 0xcb, 0x82, 0xad, 0xcc, 0x1f, 0x99, 0x6b, 0xe9, 0x1a,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x6b, 0x33, 0xae, 0x46, 0xb2, 0x45, 0xcd, 0x96, 0x6f, 0x87, 0x79, 0xad, 0xa0,
        0x27, 0x30, 0xd5, 0xb8, 0xe0, 0xe6, 0xb6, 0xbc, 0xac, 0xc1, 0x69, 0xb5, 0xfb,
        0x3e, 0xea, 0x7c, 0x22, 0xb5, 0x96, 0xb1, 0x9a, 0xb1, 0x35, 0x4f, 0xb4, 0x23,
        0xce, 0x28, 0xa2, 0x35, 0x43, 0xc0, 0x47, 0xed, 0x61, 0x79, 0xd9, 0x54, 0x8f,
        0x25, 0xf7, 0x5c, 0x8e, 0x67, 0x22, 0xb0, 0xe0, 0xbb, 0x77, 0x78, 0x65,
    };
    constexpr std::array<uint8_t, 24> chall{
        0x1b, 0x67, 0x1b, 0x05, 0x6c, 0xd4, 0x94, 0x67, 0xfe, 0x72, 0x98, 0x08,
        0x1d, 0x16, 0xd4, 0xfc, 0x17, 0xe5, 0x43, 0xdf, 0xe7, 0x0d, 0x0c, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0xc3, 0xde, 0x85, 0xdc, 0xcb, 0xad, 0xa4, 0x69, 0xa1, 0xbd, 0x9a, 0x4b, 0xbd,
        0x47, 0x5a, 0xce, 0x6d, 0x5e, 0x97, 0x2c, 0xee, 0x76, 0xe3, 0xcf, 0xc2, 0x75,
        0x80, 0xc2, 0xf8, 0x09, 0x78, 0xd2, 0x97, 0x03, 0x7c, 0x0c, 0xf4, 0x63, 0xfa,
        0x0d, 0x78, 0x5f, 0xd1, 0xe4, 0x3c, 0x85, 0xd7, 0x25, 0xd5, 0x8d, 0xc2, 0x99,
        0x04, 0x26, 0x9f, 0x0f, 0x83, 0xe8, 0xa2, 0xbb, 0xf4, 0xf4, 0xb6, 0xa2,
    };
  } // namespace FAEST_192S
  namespace FAEST_192F {
    constexpr std::array<uint8_t, 48> h{
        0x4a, 0xc3, 0xee, 0x3c, 0xbd, 0x99, 0x31, 0x5b, 0xb7, 0xe5, 0x4d, 0xca,
        0xa9, 0xe9, 0x00, 0x66, 0xe7, 0xba, 0x9a, 0x22, 0xd6, 0x55, 0x92, 0x37,
        0x02, 0x55, 0x0d, 0x28, 0x26, 0x45, 0xb3, 0xee, 0xa1, 0x48, 0xf0, 0xb8,
        0x1b, 0x28, 0x4f, 0xfe, 0xb3, 0x46, 0x06, 0xa1, 0xa9, 0x84, 0x02, 0x98,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x69, 0xc0, 0x6f, 0x3c, 0x50, 0x9a, 0x89, 0xff, 0x74, 0x3d, 0xd4, 0x9c, 0x0e,
        0x12, 0x61, 0x82, 0x56, 0x53, 0x63, 0x78, 0x19, 0x69, 0x7c, 0x00, 0x89, 0x0f,
        0xa3, 0x58, 0x21, 0x30, 0x39, 0x1f, 0x6d, 0x5b, 0xee, 0xe8, 0x5b, 0x24, 0xbd,
        0x22, 0x9b, 0x90, 0xbc, 0x25, 0x9d, 0x07, 0x9d, 0x0a, 0x74, 0xc2, 0x9e, 0x3e,
        0xc1, 0xa1, 0x98, 0xc8, 0x4e, 0xa1, 0xcb, 0xde, 0xf6, 0xbf, 0xb9, 0x08,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0xae, 0x29, 0xb2, 0x4d, 0x39, 0x4b, 0x26, 0xd8, 0x5f, 0xf2, 0x0b, 0x09, 0xf4,
        0x62, 0x07, 0x58, 0xc5, 0xe2, 0xb7, 0xa4, 0x3e, 0x5d, 0xcb, 0xe2, 0xac, 0xad,
        0x56, 0x71, 0x86, 0xb3, 0x14, 0xa0, 0x11, 0x04, 0xc9, 0x5d, 0xf1, 0x84, 0x1a,
        0xa1, 0xaa, 0xa5, 0x56, 0x89, 0x7e, 0xc3, 0x15, 0x34, 0x9e, 0x60, 0x6f, 0xcb,
        0x85, 0x8c, 0xc6, 0x06, 0x4c, 0xe6, 0x83, 0x76, 0x73, 0x37, 0xc8, 0xa9,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0xde, 0x73, 0xea, 0xa6, 0xb3, 0x6f, 0xf8, 0xaa, 0xe7, 0x2e, 0xfe, 0x44, 0xc0,
        0x82, 0x0e, 0x38, 0xe5, 0x2d, 0xf7, 0x81, 0x40, 0x54, 0x4a, 0x6a, 0x8e, 0x7e,
        0xa3, 0x20, 0xf5, 0xea, 0xfa, 0x0b, 0x81, 0xb4, 0xc2, 0xb9, 0x82, 0xc9, 0x4e,
        0x0f, 0xd8, 0xfb, 0x62, 0x5f, 0x25, 0x54, 0x71, 0x06, 0x9b, 0xbf, 0x24, 0xfb,
        0x7c, 0xb1, 0xfb, 0x2b, 0x69, 0xba, 0xd6, 0x32, 0xd3, 0x45, 0x13, 0xfd,
    };
    constexpr std::array<uint8_t, 24> chall{
        0x53, 0x6d, 0xce, 0xfe, 0xcb, 0xa6, 0xed, 0x3a, 0xfa, 0x5b, 0x9d, 0xba,
        0x1f, 0x61, 0x34, 0x29, 0xd2, 0x67, 0x75, 0x99, 0x9a, 0x7d, 0xf4, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x73, 0xf0, 0xe0, 0xfb, 0x5f, 0x1c, 0x7e, 0xdc, 0xaa, 0x2f, 0xa2, 0xd1, 0xe7,
        0x80, 0xd8, 0x3e, 0x0f, 0xbe, 0xa1, 0x62, 0x2d, 0x95, 0x66, 0x81, 0xf6, 0x03,
        0x3c, 0x14, 0x6e, 0x83, 0xfa, 0x5c, 0x00, 0xc4, 0x67, 0xcb, 0x4a, 0xf2, 0x78,
        0xed, 0xb3, 0xb0, 0xf9, 0x89, 0xba, 0x3c, 0xe8, 0x62, 0x20, 0x5b, 0xfa, 0xaa,
        0xdd, 0xee, 0xc5, 0x1f, 0xcd, 0x89, 0x7b, 0xc0, 0xfc, 0x0e, 0xfa, 0xfa,
    };
  } // namespace FAEST_192F
  namespace FAEST_256S {
    constexpr std::array<uint8_t, 64> h{
        0x40, 0xb6, 0xd0, 0x73, 0x5a, 0xa1, 0x23, 0x3c, 0x7d, 0xa1, 0x19, 0x5a, 0x49,
        0xa2, 0x44, 0x44, 0x95, 0x7a, 0x45, 0xb0, 0x81, 0x90, 0x63, 0xdb, 0x1a, 0x3a,
        0x3b, 0x9a, 0x35, 0x44, 0x84, 0x54, 0x91, 0x35, 0x00, 0x54, 0xbb, 0x56, 0x54,
        0x7e, 0x6c, 0x8f, 0x78, 0xbd, 0xcf, 0x93, 0x20, 0x87, 0x49, 0x5e, 0x17, 0xa5,
        0x56, 0xc6, 0xfe, 0x84, 0xa4, 0xba, 0x1c, 0xb1, 0x20, 0x94, 0xee, 0x65,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x44, 0x63, 0x05, 0xb2, 0x85, 0xcf, 0xaa, 0xed, 0x45, 0x49, 0x1f, 0x82, 0xc4,
        0x94, 0x44, 0xc2, 0xb5, 0x6d, 0x6c, 0xc8, 0x02, 0xfb, 0x24, 0x11, 0xa0, 0x41,
        0x44, 0x4a, 0x51, 0xf3, 0x6d, 0x1e, 0xae, 0x6b, 0x8f, 0x87, 0x1e, 0xe5, 0xb3,
        0xd7, 0xf0, 0x9a, 0x48, 0x80, 0xf1, 0xff, 0x07, 0xcc, 0x58, 0x24, 0x4b, 0xbe,
        0xc4, 0xff, 0x72, 0x29, 0x02, 0xd7, 0xe1, 0xd9, 0xd3, 0xda, 0x32, 0x45,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x72, 0x8f, 0x7e, 0x48, 0xac, 0xbd, 0xea, 0xba, 0xdb, 0x10, 0x38, 0x38, 0x71,
        0xd8, 0xed, 0xb1, 0x57, 0xf3, 0xb0, 0x40, 0x1b, 0x58, 0xb2, 0x01, 0xe9, 0xae,
        0xb8, 0x34, 0x8a, 0x65, 0x2e, 0xb8, 0xb4, 0x63, 0x9d, 0x73, 0x27, 0x12, 0xa6,
        0x02, 0x74, 0xe2, 0x0a, 0x4f, 0x6a, 0xb0, 0x89, 0xf1, 0xce, 0xbf, 0x6d, 0x33,
        0x31, 0x30, 0x21, 0x1f, 0x9f, 0x3b, 0xe7, 0x01, 0x13, 0x7f, 0x90, 0x62,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x83, 0x5a, 0xc0, 0xdf, 0xab, 0x07, 0xdb, 0xfe, 0xa5, 0x65, 0x65, 0x46, 0x2a,
        0x8b, 0x61, 0xae, 0xc2, 0x4e, 0x41, 0xbf, 0x3e, 0x56, 0xed, 0x5a, 0x44, 0x30,
        0x5a, 0xf2, 0xf6, 0x5d, 0xa7, 0x8c, 0x04, 0xae, 0x96, 0x74, 0x88, 0xae, 0x00,
        0x75, 0x5c, 0xc8, 0xc2, 0x39, 0x29, 0xf4, 0x73, 0xa4, 0xf9, 0xae, 0x10, 0xf1,
        0x48, 0xaa, 0x9d, 0x18, 0x46, 0xce, 0xd2, 0x2f, 0x2a, 0xfa, 0x77, 0xca,
    };
    constexpr std::array<uint8_t, 32> chall{
        0xea, 0x54, 0xe6, 0x0b, 0xb8, 0xe5, 0x37, 0x54, 0x2b, 0xb1, 0x34,
        0x07, 0x67, 0xe8, 0x17, 0x6a, 0x9d, 0x42, 0x01, 0x1d, 0x12, 0xe1,
        0x31, 0xd0, 0xbe, 0x51, 0x67, 0x3e, 0x95, 0xbe, 0x54, 0x01,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0xe2, 0x4b, 0x61, 0x01, 0x87, 0xe7, 0xe6, 0x29, 0x81, 0x00, 0x3f, 0x8b, 0x72,
        0x26, 0x4c, 0xce, 0x4e, 0x5e, 0xeb, 0x40, 0xc3, 0x7c, 0x6a, 0xc4, 0x26, 0xc3,
        0xf4, 0x64, 0x14, 0xf2, 0xf5, 0x61, 0xca, 0x18, 0xe5, 0x22, 0xb6, 0xc2, 0xd2,
        0x1d, 0x0e, 0x20, 0xc7, 0x56, 0x17, 0xbe, 0xa6, 0xac, 0x55, 0xc3, 0xd5, 0xb6,
        0xb2, 0x63, 0xd9, 0x61, 0x91, 0xa5, 0x4c, 0x15, 0x8c, 0x89, 0xd5, 0x89,
    };
  } // namespace FAEST_256S
  namespace FAEST_256F {
    constexpr std::array<uint8_t, 64> h{
        0xb9, 0xa3, 0x38, 0x1f, 0x8e, 0x4b, 0x01, 0xe5, 0x8c, 0x2b, 0xfa, 0x47, 0x98,
        0x87, 0x1e, 0xd1, 0xb0, 0xb4, 0xb7, 0xd6, 0x83, 0xf5, 0x70, 0xeb, 0xcb, 0xed,
        0xde, 0xf7, 0xa4, 0x4b, 0x4f, 0x67, 0xcf, 0x3a, 0x36, 0x71, 0x40, 0x66, 0x55,
        0xb0, 0x9e, 0x0b, 0x8c, 0x88, 0x8b, 0x2d, 0x77, 0x92, 0xa3, 0x45, 0x73, 0xa9,
        0x90, 0x89, 0x01, 0x15, 0xb8, 0x0f, 0x0f, 0x87, 0x8a, 0x13, 0x60, 0xa3,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x55, 0x8b, 0x03, 0x4d, 0x9e, 0xe6, 0x40, 0x92, 0xc1, 0x82, 0x23, 0xee, 0x98,
        0x80, 0xb1, 0xd6, 0x73, 0x26, 0x22, 0x14, 0x50, 0xed, 0x70, 0xd4, 0x23, 0xae,
        0x23, 0x9d, 0x51, 0x09, 0x1e, 0xbe, 0x81, 0xf9, 0xa0, 0xbb, 0xbb, 0xed, 0xd8,
        0xf7, 0x3e, 0x3b, 0xbb, 0xff, 0x6a, 0x1f, 0x79, 0xf9, 0x43, 0x1f, 0xe4, 0x0d,
        0x22, 0x5e, 0x86, 0x12, 0xcb, 0xc3, 0x54, 0xce, 0x7b, 0x05, 0xa2, 0x4a,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x2a, 0xff, 0x56, 0xb9, 0x62, 0x84, 0x44, 0xb4, 0x9f, 0x68, 0x7d, 0xca, 0xc9,
        0xa9, 0xdc, 0x3a, 0x37, 0xb9, 0x47, 0x94, 0x3c, 0xe5, 0x7d, 0x82, 0x9e, 0x6e,
        0xcd, 0x30, 0x94, 0x74, 0x0c, 0x03, 0x02, 0x86, 0x83, 0xbb, 0xe0, 0x6b, 0xbb,
        0x8a, 0x95, 0x0d, 0xea, 0x45, 0x90, 0xbf, 0x60, 0xab, 0xc0, 0xec, 0x88, 0xfd,
        0xe8, 0x3f, 0xa4, 0x82, 0xfb, 0x32, 0x35, 0x4a, 0xc7, 0x76, 0xbc, 0x3c,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x13, 0x7f, 0xcb, 0x8c, 0xc8, 0xc3, 0xc3, 0x6f, 0x5b, 0xba, 0x58, 0x26, 0xb9,
        0xda, 0xd1, 0x13, 0xec, 0xeb, 0xe7, 0xf1, 0x0c, 0x26, 0x96, 0x4d, 0x72, 0x1c,
        0x5f, 0xb6, 0xe5, 0x64, 0xcc, 0xef, 0xf3, 0xe4, 0x97, 0xab, 0xd5, 0x06, 0x77,
        0xa6, 0x8b, 0x12, 0x28, 0x61, 0x68, 0x2a, 0x0d, 0x30, 0x4b, 0x44, 0x1d, 0xe2,
        0xef, 0x4a, 0x29, 0x64, 0x20, 0x4a, 0x7b, 0x0b, 0x7b, 0xfe, 0x46, 0xed,
    };
    constexpr std::array<uint8_t, 32> chall{
        0x3c, 0x59, 0xe4, 0xfd, 0xde, 0x06, 0xdc, 0x05, 0x5e, 0xf0, 0x3e,
        0xba, 0x72, 0xb3, 0x5e, 0x87, 0xcc, 0x15, 0x4d, 0x24, 0x93, 0xef,
        0x9a, 0x2e, 0xfa, 0x2c, 0x94, 0x4a, 0xca, 0xb5, 0x40, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x63, 0xf2, 0x67, 0x1b, 0x58, 0xdb, 0xd9, 0x9d, 0x98, 0xee, 0x13, 0xd6, 0xef,
        0xaa, 0xc4, 0x75, 0x00, 0x5c, 0x3d, 0xde, 0x00, 0xec, 0x63, 0xa9, 0xcc, 0x49,
        0x68, 0x59, 0xc7, 0x99, 0xac, 0xd0, 0x56, 0x8d, 0xb6, 0xeb, 0x2c, 0x7a, 0x21,
        0x7b, 0xc1, 0xfc, 0xda, 0xab, 0xa7, 0x78, 0x12, 0xb3, 0xaa, 0x3d, 0xdc, 0x75,
        0x9b, 0x42, 0x61, 0x51, 0xb4, 0x54, 0xe6, 0xd2, 0x12, 0x31, 0x53, 0x01,
    };
  } // namespace FAEST_256F
  namespace FAEST_EM_128S {
    constexpr std::array<uint8_t, 32> h{
        0x8f, 0x78, 0x86, 0x63, 0x9c, 0x81, 0x49, 0x91, 0xd9, 0xba, 0x75,
        0xf4, 0xcf, 0x85, 0x73, 0x31, 0xa7, 0x07, 0x0f, 0x2a, 0xef, 0xcf,
        0x87, 0x0f, 0x14, 0x93, 0xcb, 0xb5, 0xd9, 0x8a, 0xe4, 0x91,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x0c, 0x06, 0xd6, 0x95, 0xd2, 0x46, 0x59, 0xd9, 0xd0, 0x76, 0x53, 0x83, 0xcb,
        0x2f, 0x4b, 0xd5, 0x85, 0xf6, 0x88, 0x6e, 0x3f, 0x06, 0xb9, 0x95, 0x2b, 0x6e,
        0x87, 0x39, 0x53, 0x6f, 0x75, 0xce, 0xa2, 0xa4, 0x52, 0x7a, 0xa0, 0xa8, 0x89,
        0xdf, 0xad, 0xfd, 0x19, 0x55, 0x9b, 0x59, 0xa5, 0x91, 0x44, 0xc4, 0x9a, 0x53,
        0xd6, 0x33, 0xa8, 0xb8, 0x81, 0xaf, 0x03, 0xae, 0x4b, 0xa6, 0x7f, 0xb1,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0xb7, 0xea, 0x48, 0x89, 0x58, 0xfb, 0x3b, 0x1f, 0x57, 0x67, 0x88, 0xaf, 0x43,
        0xb1, 0x7b, 0xd5, 0x14, 0x41, 0x8b, 0x85, 0xcc, 0x67, 0x2a, 0xdd, 0xf4, 0xa3,
        0xf8, 0x88, 0xb9, 0x70, 0xf1, 0x4e, 0x4b, 0x26, 0xd7, 0xc1, 0xe8, 0x35, 0x55,
        0xf8, 0xc4, 0xfb, 0x86, 0x95, 0x65, 0xa9, 0x8c, 0x2e, 0x90, 0x36, 0xae, 0x19,
        0xa7, 0xc0, 0x4f, 0x8f, 0x05, 0x2d, 0xa7, 0x92, 0x39, 0x9a, 0x89, 0x3b,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0xd2, 0xe4, 0x01, 0xf3, 0xfd, 0xa1, 0x34, 0x82, 0xa8, 0x4e, 0xc7, 0x8e, 0x10,
        0xc3, 0x21, 0xb2, 0x36, 0xdc, 0xd3, 0x32, 0x7f, 0xf0, 0x7b, 0xb4, 0x3b, 0x7e,
        0xfe, 0x27, 0x61, 0x43, 0xd8, 0x51, 0x8b, 0x19, 0x8f, 0x40, 0xa5, 0xae, 0xda,
        0x0d, 0x45, 0x3b, 0x31, 0xf4, 0x10, 0x8e, 0x9f, 0x9f, 0x67, 0xae, 0x72, 0x0e,
        0x6c, 0xb4, 0x04, 0xe2, 0x19, 0xa6, 0xd5, 0x77, 0x9f, 0x1f, 0x05, 0x5a,
    };
    constexpr std::array<uint8_t, 16> chall{
        0x44, 0xc0, 0x41, 0xe2, 0x4c, 0x5f, 0x22, 0x8f,
        0xb3, 0x51, 0xc8, 0x87, 0x0e, 0x44, 0xeb, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0xae, 0x66, 0x0c, 0xf1, 0x9c, 0xbb, 0x39, 0x14, 0xba, 0xab, 0x2d, 0x7b, 0x3d,
        0xc4, 0xc3, 0x85, 0x31, 0x8d, 0xe9, 0xbb, 0xb0, 0xc4, 0x82, 0xd9, 0xc3, 0xbd,
        0x97, 0x63, 0x0c, 0x55, 0xba, 0x6c, 0x23, 0xb9, 0x44, 0xe2, 0x6f, 0x1a, 0x94,
        0x98, 0x0a, 0xdd, 0x9c, 0x1d, 0x85, 0x65, 0xf3, 0xf5, 0xe1, 0x0b, 0x8d, 0xfb,
        0xd9, 0x86, 0x69, 0x04, 0xef, 0x38, 0x15, 0x81, 0x80, 0x35, 0xae, 0x0c,
    };
  } // namespace FAEST_EM_128S
  namespace FAEST_EM_128F {
    constexpr std::array<uint8_t, 32> h{
        0xc4, 0x23, 0x41, 0xbe, 0xa4, 0xd4, 0x1a, 0x41, 0xf7, 0x50, 0xa1,
        0x47, 0xa2, 0x04, 0xf9, 0xc7, 0x83, 0x5a, 0x10, 0x24, 0xf7, 0x25,
        0xd1, 0x48, 0xfa, 0x26, 0xf8, 0x20, 0x03, 0x26, 0x6d, 0xcc,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0xdc, 0x1f, 0x2d, 0x78, 0xd4, 0xa9, 0x94, 0x0d, 0xb8, 0x70, 0x9a, 0x33, 0xfc,
        0xd5, 0xa8, 0x86, 0x5f, 0x10, 0xe3, 0xc8, 0xe3, 0x9d, 0xe6, 0x08, 0x5b, 0xe0,
        0x3a, 0x89, 0x76, 0x5a, 0x9a, 0x90, 0x29, 0x04, 0x00, 0x1e, 0x9d, 0xd6, 0xdb,
        0xa3, 0x1f, 0x0e, 0xc8, 0x42, 0x1c, 0xea, 0xd4, 0x71, 0xcf, 0xeb, 0x7a, 0x68,
        0xb2, 0x74, 0x9b, 0x74, 0x98, 0x8e, 0x93, 0xf2, 0x16, 0x54, 0x34, 0x6f,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0xbf, 0x99, 0x8c, 0x1c, 0xa3, 0x70, 0xe1, 0x75, 0x5c, 0x64, 0x28, 0x3b, 0x44,
        0xba, 0xe4, 0x12, 0xa0, 0x5d, 0xce, 0x76, 0x1b, 0x3a, 0x19, 0x8a, 0xd6, 0x67,
        0xe6, 0x41, 0x62, 0xf3, 0x27, 0x62, 0xc1, 0xeb, 0xd8, 0x4f, 0x95, 0x82, 0x84,
        0xda, 0x74, 0x26, 0x4e, 0x2c, 0x3c, 0x94, 0x69, 0xed, 0xc3, 0x00, 0xad, 0x5c,
        0xf2, 0xd7, 0x44, 0xe2, 0x17, 0x5e, 0xf5, 0x01, 0x74, 0x36, 0xc6, 0xa6,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x26, 0x93, 0x4a, 0x0f, 0x7e, 0x96, 0x01, 0x3d, 0xa1, 0x3c, 0x83, 0x1c, 0x08,
        0xf8, 0xf5, 0xa4, 0x8d, 0xfb, 0xb2, 0x5b, 0x0e, 0xeb, 0x35, 0x27, 0xb2, 0xd7,
        0x7e, 0x7f, 0x3b, 0xe0, 0xdc, 0x54, 0x03, 0x7e, 0xfb, 0xaf, 0xe3, 0x15, 0xbc,
        0x6f, 0xe1, 0xf4, 0x69, 0x4e, 0x2b, 0xa9, 0xa1, 0xff, 0xd5, 0xa7, 0xaa, 0xa2,
        0xd7, 0x16, 0xcd, 0xa2, 0x1e, 0xdd, 0x24, 0x7d, 0xf3, 0x05, 0xc4, 0x40,
    };
    constexpr std::array<uint8_t, 16> chall{
        0xd9, 0x8e, 0xf7, 0x09, 0x83, 0x32, 0x0f, 0x27,
        0xe3, 0xd8, 0x60, 0x46, 0x31, 0x75, 0xbf, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x0a, 0xa3, 0xcc, 0x5b, 0x28, 0x40, 0x3e, 0xe8, 0x5e, 0x16, 0x62, 0x2b, 0x6c,
        0xd6, 0xe2, 0xeb, 0x7e, 0x2c, 0xac, 0x85, 0xb4, 0xfb, 0xda, 0x3d, 0x5b, 0xf9,
        0x06, 0xcb, 0xea, 0x5b, 0x34, 0x00, 0x44, 0x5f, 0x13, 0xb4, 0x26, 0x0d, 0x29,
        0xbc, 0xcf, 0x9d, 0xe1, 0xe7, 0x52, 0x0a, 0xfd, 0x47, 0x8f, 0x87, 0x0f, 0xd8,
        0x76, 0xc6, 0x91, 0xec, 0x10, 0x7f, 0x3f, 0xa3, 0x41, 0xcc, 0x32, 0xef,
    };
  } // namespace FAEST_EM_128F
  namespace FAEST_EM_192S {
    constexpr std::array<uint8_t, 48> h{
        0x95, 0xc7, 0xf3, 0x2b, 0x63, 0xa7, 0x04, 0xec, 0x3a, 0xde, 0x32, 0xd5,
        0x6f, 0x73, 0x68, 0x2b, 0x1f, 0xd0, 0x6c, 0x60, 0x80, 0x60, 0x9b, 0x54,
        0x68, 0xe2, 0x69, 0x1c, 0x9d, 0xd6, 0x5c, 0x8d, 0x38, 0x02, 0x9f, 0x90,
        0x4a, 0x39, 0x92, 0x13, 0x5d, 0x59, 0xdd, 0x7e, 0xf3, 0xd3, 0x06, 0x01,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0xd8, 0x1c, 0x47, 0x63, 0x2b, 0x57, 0xcc, 0x1f, 0xfb, 0x51, 0xc4, 0x19, 0x81,
        0xa3, 0x2f, 0x91, 0xff, 0x59, 0xa2, 0x6c, 0x23, 0xd3, 0x61, 0xbd, 0xb6, 0x69,
        0x9a, 0x3f, 0xf6, 0x9f, 0x32, 0xc3, 0x9b, 0x72, 0x54, 0xf9, 0x0a, 0x10, 0x9f,
        0x38, 0xc0, 0x61, 0x63, 0x5d, 0xbe, 0xa9, 0x40, 0x70, 0x7f, 0xd3, 0x36, 0x28,
        0x21, 0x89, 0x95, 0x03, 0x84, 0x02, 0xdb, 0x7d, 0xad, 0x21, 0x19, 0x5a,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x92, 0xf9, 0x69, 0xa3, 0x30, 0x7e, 0x6d, 0x53, 0xc8, 0x08, 0x01, 0xaa, 0x19,
        0xf8, 0xb0, 0x2b, 0xbd, 0x25, 0x23, 0x23, 0x37, 0x8b, 0xe4, 0x0d, 0x9d, 0xec,
        0x5b, 0x37, 0x14, 0x36, 0xf8, 0xc4, 0xb9, 0xec, 0xe9, 0x7a, 0xb3, 0x36, 0x6f,
        0x91, 0xc9, 0xbb, 0x08, 0x33, 0xf4, 0xc1, 0xa9, 0xd4, 0x45, 0xb2, 0x9b, 0x5e,
        0xe2, 0x79, 0xb7, 0xf6, 0xe1, 0x41, 0xd1, 0x55, 0x1e, 0x3a, 0xa9, 0x8b,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x64, 0xbe, 0xd7, 0x3a, 0xc3, 0xd5, 0xfc, 0x6a, 0x60, 0x8d, 0xbb, 0xed, 0x28,
        0x2b, 0x7f, 0x7f, 0xf8, 0xe0, 0xc0, 0x15, 0xa0, 0xe0, 0x06, 0x5c, 0x67, 0xc1,
        0xd0, 0x9f, 0xdf, 0x42, 0xd9, 0x10, 0x87, 0xda, 0xe1, 0x80, 0x20, 0x9c, 0xa2,
        0x13, 0x84, 0x8b, 0x83, 0x4d, 0xa1, 0xdd, 0x79, 0xa8, 0x9a, 0x6d, 0xd1, 0x22,
        0xf5, 0x83, 0x6d, 0x4f, 0x29, 0xbb, 0x55, 0x42, 0xaf, 0x87, 0xea, 0x27,
    };
    constexpr std::array<uint8_t, 24> chall{
        0x97, 0xf1, 0x79, 0x00, 0x99, 0x31, 0x30, 0x44, 0x8e, 0xc9, 0x81, 0x49,
        0xaa, 0xda, 0x42, 0xaa, 0xcc, 0x27, 0x71, 0x89, 0xeb, 0x6c, 0x2e, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x91, 0x1e, 0x3f, 0x27, 0xbd, 0x62, 0x1a, 0x6b, 0x3b, 0x09, 0x56, 0xc9, 0x47,
        0xcb, 0x52, 0x59, 0xd8, 0x3c, 0x26, 0xa3, 0xff, 0xcd, 0x53, 0x09, 0xf8, 0xdc,
        0x56, 0xb0, 0xb4, 0x19, 0x16, 0x58, 0xe2, 0xd2, 0xb3, 0x80, 0x07, 0x34, 0x84,
        0xe3, 0xe0, 0x28, 0x03, 0xe8, 0x7e, 0x8d, 0xdd, 0x3c, 0x18, 0xf7, 0x78, 0x08,
        0x89, 0x03, 0x15, 0x74, 0x13, 0xa0, 0x6d, 0x2b, 0x8f, 0x22, 0xaa, 0x10,
    };
  } // namespace FAEST_EM_192S
  namespace FAEST_EM_192F {
    constexpr std::array<uint8_t, 48> h{
        0x70, 0x63, 0x25, 0xf5, 0x8a, 0xff, 0x5a, 0xef, 0x20, 0xfa, 0x58, 0xa2,
        0xc8, 0x9f, 0x82, 0x19, 0xdb, 0x2f, 0x2f, 0x23, 0x3a, 0xfd, 0x6b, 0x75,
        0xbd, 0x50, 0x3f, 0x2e, 0x3f, 0xb6, 0x9c, 0x90, 0x7b, 0xad, 0xca, 0x83,
        0xe4, 0x80, 0x13, 0xbe, 0xa2, 0xe0, 0x28, 0x28, 0xc2, 0xec, 0xc0, 0xbb,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0xb9, 0x33, 0xcb, 0x1f, 0x5c, 0x67, 0x3b, 0x8a, 0xd8, 0x06, 0x3a, 0x3d, 0xb1,
        0xec, 0x1e, 0xe5, 0x2c, 0x3d, 0x5e, 0x0a, 0x4a, 0x27, 0x92, 0xfe, 0xb0, 0x7f,
        0x26, 0x43, 0xea, 0xf3, 0x50, 0x22, 0x43, 0x1d, 0xef, 0x81, 0xc5, 0xb9, 0x90,
        0xed, 0x1b, 0x43, 0x03, 0x1a, 0xc3, 0xc6, 0x2b, 0x95, 0xdb, 0x0b, 0xb5, 0x9a,
        0x8a, 0xc4, 0xda, 0x47, 0x63, 0x99, 0x28, 0x9a, 0x3a, 0x52, 0x75, 0x49,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x75, 0x7f, 0xf0, 0x68, 0x13, 0xb3, 0x1c, 0x71, 0x75, 0xa7, 0x58, 0x5d, 0xae,
        0x36, 0x6e, 0xda, 0x16, 0x25, 0x5e, 0x67, 0xca, 0x1d, 0x79, 0x51, 0x02, 0x3b,
        0x48, 0x8c, 0xa2, 0x7f, 0x71, 0xcc, 0xc8, 0x4b, 0xf6, 0x47, 0xe4, 0xb1, 0x37,
        0x81, 0xd0, 0x5c, 0x00, 0x01, 0x79, 0x63, 0xb2, 0xfc, 0xb7, 0xcb, 0xce, 0x07,
        0x31, 0x29, 0xa0, 0x9c, 0x53, 0x08, 0x4b, 0x57, 0x97, 0xd4, 0x7c, 0x0c,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x3f, 0xc0, 0xa3, 0xfd, 0xb6, 0x87, 0x4a, 0x33, 0xc1, 0x74, 0x67, 0x6f, 0xab,
        0xee, 0xdc, 0xba, 0x83, 0x7e, 0x99, 0xe1, 0x8d, 0x02, 0x08, 0x3d, 0x30, 0x41,
        0x66, 0xe9, 0xbc, 0x2f, 0x48, 0x2c, 0x3a, 0x27, 0x3a, 0x46, 0x55, 0x10, 0x63,
        0xae, 0x85, 0x28, 0xa1, 0xbf, 0x53, 0x2f, 0xae, 0x6a, 0x57, 0x1b, 0x8d, 0x60,
        0x62, 0x60, 0xb7, 0x45, 0x78, 0x3c, 0x98, 0x1d, 0x93, 0x1e, 0xbc, 0xd7,
    };
    constexpr std::array<uint8_t, 24> chall{
        0x4b, 0x6c, 0xe2, 0x1c, 0x61, 0x89, 0xb9, 0x81, 0xa1, 0xe0, 0x48, 0x86,
        0xa7, 0x9f, 0xa6, 0x0e, 0x92, 0x96, 0x34, 0x34, 0x93, 0xae, 0x18, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x8e, 0x1e, 0xe6, 0xd6, 0x6f, 0x2d, 0xa6, 0x3b, 0x52, 0x8c, 0xf4, 0xc0, 0xf2,
        0x6c, 0x77, 0xdb, 0xd4, 0x41, 0xfb, 0x54, 0x1c, 0xd9, 0x46, 0xbc, 0xf2, 0xbd,
        0xae, 0x15, 0xc3, 0x53, 0x17, 0xaf, 0x4a, 0xe1, 0x69, 0xb2, 0x97, 0x87, 0xe5,
        0xb2, 0x9e, 0xcc, 0x11, 0xc7, 0xb8, 0xe4, 0x31, 0xd7, 0x41, 0xd2, 0x2b, 0xef,
        0x65, 0x65, 0x55, 0xc6, 0x12, 0x07, 0x36, 0x1f, 0xbc, 0x51, 0x27, 0xd2,
    };
  } // namespace FAEST_EM_192F
  namespace FAEST_EM_256S {
    constexpr std::array<uint8_t, 64> h{
        0xa5, 0x87, 0x1f, 0xaa, 0x9e, 0xee, 0x27, 0x24, 0x54, 0x34, 0x97, 0xca, 0x51,
        0xc2, 0xd5, 0xc4, 0xe7, 0xa6, 0xb3, 0x61, 0x7c, 0xdd, 0x53, 0xf0, 0xac, 0xb9,
        0x49, 0x86, 0x09, 0x48, 0xaf, 0x95, 0x29, 0xb3, 0x1d, 0x73, 0xd8, 0xba, 0x34,
        0x84, 0xe1, 0xe4, 0x0c, 0x86, 0xba, 0xd9, 0xb5, 0x10, 0xe8, 0x97, 0x89, 0xce,
        0x58, 0xc8, 0xc9, 0xe2, 0x10, 0x83, 0x29, 0x68, 0xed, 0x46, 0x1b, 0x53,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0xbb, 0xaf, 0x5e, 0x48, 0x11, 0x2e, 0xc9, 0xf0, 0xfa, 0xed, 0xa9, 0x50, 0x0d,
        0x37, 0xdf, 0xd5, 0xd3, 0xc6, 0xc6, 0x1e, 0xce, 0x52, 0xb5, 0xd2, 0x63, 0x5f,
        0x64, 0x62, 0xc3, 0x33, 0x27, 0xda, 0x36, 0x2b, 0x94, 0x89, 0x2d, 0x0d, 0xb1,
        0xbc, 0xf5, 0x84, 0xf0, 0x33, 0xaf, 0x75, 0xca, 0x1d, 0xa3, 0x90, 0x5f, 0x58,
        0x4d, 0xce, 0x82, 0x91, 0xe0, 0x08, 0x87, 0xeb, 0xa8, 0xb7, 0xdb, 0x21,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x39, 0xae, 0x05, 0x32, 0xd0, 0xcc, 0x65, 0xb2, 0xb4, 0x98, 0x7e, 0xff, 0xec,
        0x22, 0x8c, 0x69, 0x1b, 0x61, 0x66, 0xfd, 0x9e, 0xf5, 0x1b, 0xbe, 0x29, 0x89,
        0x36, 0xd3, 0xab, 0x8b, 0x40, 0xb4, 0x8e, 0x56, 0x84, 0x72, 0xb3, 0xda, 0xf6,
        0xad, 0xff, 0x3b, 0x3e, 0xd0, 0xb7, 0xce, 0xc0, 0xe4, 0xba, 0x6c, 0x67, 0xe5,
        0x7c, 0xd1, 0x38, 0x5b, 0xf6, 0xa5, 0xa7, 0xc0, 0x1e, 0xb5, 0x1f, 0xac,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0xeb, 0x24, 0xdb, 0x19, 0xfd, 0x64, 0xe2, 0x2a, 0x26, 0x18, 0x1a, 0x99, 0x8b,
        0xf5, 0xe4, 0x8f, 0x15, 0x6e, 0x19, 0xed, 0x1e, 0x0d, 0x9f, 0x63, 0x10, 0x01,
        0xc4, 0x17, 0xd3, 0x48, 0xff, 0x44, 0xae, 0xcc, 0xbb, 0x27, 0x52, 0x4b, 0xa3,
        0x29, 0x9e, 0x28, 0xa6, 0x7b, 0x20, 0x1c, 0x37, 0x5a, 0xdf, 0xfa, 0x9a, 0xe5,
        0x74, 0xda, 0x27, 0x1f, 0x45, 0x19, 0x70, 0x79, 0xb5, 0x05, 0xe8, 0xf9,
    };
    constexpr std::array<uint8_t, 32> chall{
        0x0e, 0x57, 0x3a, 0x9d, 0xd6, 0x84, 0x1e, 0x1f, 0x2c, 0x0f, 0xa0,
        0xa2, 0x99, 0x65, 0x4b, 0x66, 0x2d, 0x85, 0x71, 0x8d, 0x2e, 0xb1,
        0xa4, 0xfa, 0xf6, 0x23, 0xfa, 0xe3, 0x0a, 0x2c, 0xb9, 0x02,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0x18, 0xfd, 0xb7, 0x6d, 0xef, 0x1c, 0x3b, 0xf4, 0xed, 0x34, 0x0b, 0xa4, 0x86,
        0xf8, 0x11, 0xbe, 0x0a, 0xd4, 0x44, 0x19, 0x7c, 0x50, 0x4d, 0x11, 0x4b, 0x06,
        0xbd, 0x98, 0x61, 0x53, 0x3b, 0x98, 0xaa, 0xaa, 0xab, 0xa9, 0x94, 0xd3, 0xba,
        0xa5, 0x17, 0xc6, 0x41, 0xdd, 0xb4, 0x30, 0xd2, 0x2d, 0xa3, 0x7b, 0x3d, 0xa9,
        0x16, 0x5c, 0x94, 0xb0, 0xaf, 0x1d, 0xf1, 0x66, 0x2a, 0x07, 0xa4, 0x62,
    };
  } // namespace FAEST_EM_256S
  namespace FAEST_EM_256F {
    constexpr std::array<uint8_t, 64> h{
        0x63, 0xa6, 0xce, 0x08, 0xf5, 0x5c, 0x7d, 0x2d, 0x0a, 0xbf, 0xbe, 0xdf, 0x52,
        0x68, 0xeb, 0x0b, 0xf3, 0x90, 0xfa, 0xfe, 0x54, 0x77, 0xba, 0xcd, 0xca, 0x71,
        0x1d, 0x3d, 0x62, 0x5b, 0x54, 0x13, 0x42, 0xa9, 0xf8, 0x0b, 0x68, 0xb5, 0xbd,
        0x5d, 0x9a, 0xd4, 0x2b, 0xf4, 0x18, 0x83, 0xd8, 0x99, 0x74, 0x37, 0x36, 0x19,
        0x24, 0x72, 0x97, 0x6f, 0xf6, 0xc2, 0x46, 0xf8, 0x86, 0x1a, 0xea, 0xe8,
    };
    constexpr std::array<uint8_t, 64> hashed_c{
        0x06, 0x03, 0x0c, 0x5e, 0xc0, 0x75, 0xb8, 0x4c, 0x01, 0x88, 0x84, 0x0f, 0x96,
        0x5d, 0x81, 0x18, 0xa3, 0x52, 0xd8, 0x28, 0xed, 0xc2, 0xb2, 0x8b, 0x6d, 0x21,
        0x61, 0x43, 0x2a, 0xd4, 0xf1, 0xaf, 0x3e, 0x27, 0x24, 0x53, 0xad, 0xe7, 0x4e,
        0xd7, 0xf9, 0x8c, 0xf8, 0x4c, 0x91, 0xe6, 0x34, 0x5d, 0x16, 0xbe, 0x5e, 0x53,
        0x38, 0x8f, 0xc8, 0x2b, 0xa8, 0xe5, 0xc2, 0xf8, 0x07, 0x34, 0xeb, 0x9e,
    };
    constexpr std::array<uint8_t, 64> hashed_u{
        0x97, 0x0c, 0xa5, 0xb6, 0x20, 0xc6, 0xe7, 0x70, 0xc0, 0x65, 0xde, 0x55, 0x26,
        0xac, 0x21, 0xe8, 0xfb, 0xa5, 0xcd, 0x28, 0x0e, 0xde, 0xf1, 0xe7, 0x24, 0xad,
        0xb7, 0x36, 0x5d, 0xb3, 0xa0, 0xa7, 0xdc, 0xd5, 0x1b, 0x6a, 0x75, 0x73, 0x9f,
        0x13, 0xd6, 0x3a, 0x75, 0xb5, 0x29, 0x3c, 0xbe, 0x0a, 0x32, 0xc5, 0x2d, 0x4a,
        0x95, 0x5f, 0x2d, 0xb7, 0x97, 0x08, 0xb2, 0x85, 0x51, 0x20, 0x40, 0x49,
    };
    constexpr std::array<uint8_t, 64> hashed_v{
        0x23, 0x52, 0x8f, 0x06, 0xb5, 0x2d, 0x65, 0xce, 0x16, 0x27, 0x52, 0xec, 0x75,
        0xe6, 0x65, 0x12, 0x31, 0x63, 0x71, 0x8f, 0x0c, 0xa5, 0x89, 0x9f, 0x49, 0xe2,
        0x72, 0x89, 0x8a, 0x03, 0x24, 0x05, 0xa1, 0x8b, 0xc3, 0xb8, 0xbe, 0x3d, 0x2a,
        0xb7, 0xb3, 0x4b, 0x0f, 0xa5, 0xaa, 0x8c, 0x03, 0x91, 0x72, 0x27, 0x38, 0x10,
        0x0a, 0x36, 0x88, 0x76, 0x29, 0xc3, 0xcb, 0xf7, 0x80, 0xb7, 0x10, 0x85,
    };
    constexpr std::array<uint8_t, 32> chall{
        0x66, 0x30, 0x9a, 0x4c, 0x5a, 0xb9, 0x66, 0xf6, 0x3c, 0x34, 0x2a,
        0xa7, 0x8e, 0x90, 0x50, 0x9b, 0x79, 0xd9, 0xd0, 0x4a, 0xae, 0x80,
        0x2c, 0xba, 0x40, 0x15, 0xbf, 0x5f, 0x31, 0x5a, 0x17, 0x00,
    };
    constexpr std::array<uint8_t, 64> hashed_q{
        0xd3, 0x4e, 0x8d, 0x1e, 0x7a, 0x72, 0x26, 0xa7, 0x9b, 0x80, 0xd3, 0x81, 0xdc,
        0x40, 0xb2, 0x16, 0x5f, 0x77, 0xba, 0x56, 0xbc, 0x9e, 0xb9, 0xb4, 0x01, 0xac,
        0x4e, 0x25, 0x9a, 0x6b, 0x7f, 0x8c, 0xc0, 0x0a, 0xe2, 0xe6, 0x12, 0x8e, 0x55,
        0x39, 0x7d, 0x52, 0x2e, 0x63, 0x19, 0xe2, 0x06, 0x3e, 0x48, 0x96, 0xc1, 0x2e,
        0x38, 0x81, 0x3c, 0x63, 0x85, 0x04, 0x48, 0xe5, 0x82, 0xf1, 0x67, 0x18,
    };
  } // namespace FAEST_EM_256F
} // namespace bavc_tvs

#endif

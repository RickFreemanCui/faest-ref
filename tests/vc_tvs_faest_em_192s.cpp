#include "vc_tvs.hpp"

namespace vc_tvs {
  namespace FAEST_EM_192S {
    const std::array<uint8_t, 48> h{
        0x0d, 0xad, 0xd6, 0xad, 0xd5, 0x85, 0xec, 0x49, 0x25, 0xb5, 0xec, 0x40,
        0xfa, 0x54, 0xba, 0x76, 0x29, 0xd6, 0x9d, 0x12, 0x0d, 0x4a, 0x83, 0xa2,
        0x49, 0x19, 0x1f, 0x84, 0xa6, 0x9a, 0x40, 0xb8, 0x31, 0x62, 0xe2, 0x00,
        0xe3, 0xbd, 0xba, 0x75, 0x8e, 0x77, 0xe7, 0x13, 0xd4, 0xc3, 0x76, 0xe3,
    };
    const std::array<uint8_t, 64> hashed_k{
        0x6c, 0xee, 0xb5, 0x57, 0xf9, 0xd1, 0xb7, 0xce, 0x4b, 0xb6, 0x5d, 0xa9, 0xbb,
        0x0d, 0xf4, 0x19, 0xa0, 0x85, 0x53, 0xc9, 0xbe, 0x9a, 0xb0, 0x1a, 0x7e, 0x77,
        0xea, 0xd6, 0x40, 0x33, 0xab, 0x34, 0x83, 0x57, 0x6c, 0xae, 0x77, 0x60, 0x46,
        0x5c, 0x82, 0x3a, 0xd6, 0x2c, 0xd7, 0xea, 0x32, 0x86, 0xa8, 0x19, 0x91, 0x31,
        0x93, 0xc1, 0xb3, 0x55, 0xef, 0x65, 0x26, 0x81, 0x6f, 0x2e, 0x35, 0x94,
    };
    const std::array<uint8_t, 64> hashed_sd{
        0x9a, 0x1d, 0xca, 0x58, 0xd0, 0xe9, 0xbb, 0x4a, 0x03, 0xb5, 0x58, 0xc0, 0xa5,
        0xed, 0x1c, 0xbb, 0x9e, 0x1a, 0xb6, 0xb9, 0x98, 0xe4, 0x97, 0x7b, 0x72, 0x13,
        0x8b, 0x6c, 0xf3, 0x3d, 0x82, 0x88, 0xf1, 0x2d, 0x28, 0x09, 0xf3, 0x53, 0x4c,
        0x25, 0x83, 0xfe, 0x6b, 0x18, 0x22, 0xad, 0xa1, 0x7f, 0xc4, 0x0f, 0x93, 0xdb,
        0x3d, 0x18, 0x57, 0x82, 0x3b, 0xc9, 0xf0, 0x4f, 0x94, 0xc5, 0x4b, 0xd8,
    };
    const std::array<uint16_t, 16> i_delta{
        0x0c96, 0x0401, 0x0b5e, 0x0f25, 0x004e, 0x067a, 0x0405, 0x005d,
        0x042a, 0x02c1, 0x0231, 0x047c, 0x011e, 0x0459, 0x042c, 0x06db,
    };
    const std::array<uint8_t, 64> hashed_decom_i{
        0xa8, 0x9f, 0xfa, 0x89, 0xe7, 0x2a, 0xe8, 0x1a, 0x79, 0x8c, 0x0b, 0x02, 0xbc,
        0x01, 0x24, 0x6b, 0xa5, 0x3a, 0x5d, 0xa0, 0x47, 0xa6, 0xd7, 0x65, 0xad, 0x52,
        0xfe, 0xc5, 0x2c, 0x9e, 0xeb, 0xdd, 0xde, 0x1d, 0xed, 0x9b, 0xd6, 0x4e, 0xbe,
        0x54, 0x26, 0x27, 0x0c, 0x85, 0xb0, 0x2a, 0xc1, 0x37, 0x55, 0x07, 0x20, 0xd2,
        0xb6, 0x25, 0xd1, 0x08, 0xbd, 0x98, 0x77, 0x59, 0x91, 0x7e, 0xe4, 0xdc,
    };
    const std::array<uint8_t, 64> hashed_rec_sd{
        0x72, 0xbb, 0x3c, 0x1f, 0x1f, 0xeb, 0x8d, 0x0a, 0x98, 0x16, 0x66, 0xfe, 0x94,
        0xf9, 0x6b, 0x15, 0xb2, 0x98, 0x7c, 0xfb, 0x95, 0x1a, 0x14, 0x6f, 0xd1, 0xe6,
        0x03, 0x44, 0xec, 0x6d, 0x00, 0x7c, 0x5e, 0x03, 0x44, 0x44, 0x68, 0x5b, 0xfd,
        0xfb, 0xe7, 0x95, 0x68, 0x08, 0x4c, 0xad, 0xf8, 0xad, 0x9e, 0x88, 0xce, 0x9a,
        0x51, 0xfe, 0x4b, 0x0e, 0x87, 0x29, 0xc2, 0x86, 0x8a, 0x5a, 0xd2, 0x34,
    };
  } // namespace FAEST_EM_192S
} // namespace vc_tvs

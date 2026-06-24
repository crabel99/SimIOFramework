#pragma once

#include <AES.h>
#include <PUKCC.h>
#include <TRNG.h>

#include <stdint.h>

#ifdef CRYPTO_HARDWARE_AVAILABLE
namespace Crypto {

enum CryptoHardwareMask : uint8_t {
  CRYPTO_HARDWARE_NONE = 0x00,
  CRYPTO_HARDWARE_AES = 0x01,
  CRYPTO_HARDWARE_PUKCC = 0x02,
  CRYPTO_HARDWARE_TRNG = 0x04,
};

inline bool hasAES() { return AES_AVAILABLE; };
inline bool hasPUKCC() { return PUKCC_AVAILABLE; };
inline bool hasTRNG() { return TRNG_AVAILABLE; };
uint8_t hardwareMask();

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

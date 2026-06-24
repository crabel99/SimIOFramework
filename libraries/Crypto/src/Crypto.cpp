#include "Crypto.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto {

uint8_t hardwareMask() {
  uint8_t mask = CRYPTO_HARDWARE_NONE;

  if (hasAES()) {
    mask |= CRYPTO_HARDWARE_AES;
  }

  if (hasPUKCC()) {
    mask |= CRYPTO_HARDWARE_PUKCC;
  }

  if (hasTRNG()) {
    mask |= CRYPTO_HARDWARE_TRNG;
  }

  return mask;
}

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

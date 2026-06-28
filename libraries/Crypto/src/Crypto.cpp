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

bool registerAesCallback(AesCallback callback, void *context) {
  return hasAES() && aes::registerEventCallback(callback, context);
}

void clearAesCallback() { aes::clearEventCallback(); }

bool encryptEcb128Async(const uint32_t key[4], const uint32_t plaintext[4],
                        uint32_t ciphertext[4]) {
  return hasAES() && aes::startEcb128Async(aes::Direction::Encrypt, key,
                                           plaintext, ciphertext);
}

bool decryptEcb128Async(const uint32_t key[4], const uint32_t ciphertext[4],
                        uint32_t plaintext[4]) {
  return hasAES() && aes::startEcb128Async(aes::Direction::Decrypt, key,
                                           ciphertext, plaintext);
}

bool registerTrngCallback(TrngCallback callback, void *context) {
  return hasTRNG() && trng::registerEventCallback(callback, context);
}

void clearTrngCallback() { trng::clearEventCallback(); }

bool randomWordAsync() { return hasTRNG() && trng::requestWordAsync(); }

bool registerPukccCallback(PukccCallback callback, void *context) {
  return hasPUKCC() && pukcc::registerEventCallback(callback, context);
}

void clearPukccCallback() { pukcc::clearEventCallback(); }

bool selfTestAsync(pukcc::SelfTestResult &result) {
  return hasPUKCC() && pukcc::selfTestAsync(result);
}

bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result) {
  return hasPUKCC() && pukcc::clearFlagsAsync(initialFlags, result);
}

bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result) {
  return hasPUKCC() &&
         pukcc::fillCryptoRamAsync(offset, length, fillValue, result);
}

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

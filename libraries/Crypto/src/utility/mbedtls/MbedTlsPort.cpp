#include "MbedTlsPort.h"

namespace Crypto::MbedTlsPort {

bool registerAesCallback(Crypto::AesCallback callback, void *context) {
  return Crypto::registerAesCallback(callback, context);
}

void clearAesCallback() { Crypto::clearAesCallback(); }

bool aesEcb128EncryptAsync(const uint32_t key[4], const uint32_t plaintext[4],
                           uint32_t ciphertext[4]) {
  return Crypto::encryptEcb128Async(key, plaintext, ciphertext);
}

bool aesEcb128DecryptAsync(const uint32_t key[4], const uint32_t ciphertext[4],
                           uint32_t plaintext[4]) {
  return Crypto::decryptEcb128Async(key, ciphertext, plaintext);
}

bool registerTrngCallback(Crypto::TrngCallback callback, void *context) {
  return Crypto::registerTrngCallback(callback, context);
}

void clearTrngCallback() { Crypto::clearTrngCallback(); }

bool requestEntropyWordAsync() { return Crypto::randomWordAsync(); }

bool registerPukccCallback(Crypto::PukccCallback callback, void *context) {
  return Crypto::registerPukccCallback(callback, context);
}

void clearPukccCallback() { Crypto::clearPukccCallback(); }

bool selfTestAsync(pukcc::SelfTestResult &result) {
  return Crypto::selfTestAsync(result);
}

bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result) {
  return Crypto::clearFlagsAsync(initialFlags, result);
}

bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result) {
  return Crypto::fillCryptoRamAsync(offset, length, fillValue, result);
}

} // namespace Crypto::MbedTlsPort

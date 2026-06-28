#include "Crypto.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE

#include <Arduino.h>

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

bool randomWord(uint32_t &value, uint32_t timeoutMillis) {
  if (!hasTRNG())
    return false;

  trng::begin();
  const uint32_t start = millis();
  while ((millis() - start) < timeoutMillis) {
    if (trng::read(value)) {
      trng::end();
      return true;
    }
  }

  trng::end();
  return false;
}

namespace {
bool processEcb128Block(aes::Direction direction, const uint32_t key[4],
                        const uint32_t input[4], uint32_t output[4],
                        uint32_t timeoutMillis) {
  if (!hasAES() || key == nullptr || input == nullptr || output == nullptr)
    return false;

  aes::begin();
  aes::configure(aes::Mode::Ecb, aes::KeySize::Bits128, direction);
  if (!aes::writeKey(key, 4)) {
    aes::end();
    return false;
  }

  aes::beginMessage();
  aes::writeInputBlock(input);
  aes::start();

  const uint32_t start = millis();
  while (!aes::operationComplete() && ((millis() - start) < timeoutMillis)) {
  }

  if (!aes::operationComplete()) {
    aes::end();
    return false;
  }

  aes::readOutputBlock(output);
  aes::end();
  return true;
}
} // namespace

bool encryptEcb128(const uint32_t key[4], const uint32_t plaintext[4],
                   uint32_t ciphertext[4], uint32_t timeoutMillis) {
  return processEcb128Block(aes::Direction::Encrypt, key, plaintext, ciphertext,
                            timeoutMillis);
}

bool decryptEcb128(const uint32_t key[4], const uint32_t ciphertext[4],
                   uint32_t plaintext[4], uint32_t timeoutMillis) {
  return processEcb128Block(aes::Direction::Decrypt, key, ciphertext, plaintext,
                            timeoutMillis);
}

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

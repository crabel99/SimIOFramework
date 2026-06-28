#include "MbedTlsPort.h"

#include <Crypto.h>

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif
#include <mbedtls/private/aes.h>
#include <mbedtls/private/ctr_drbg.h>

namespace Crypto::MbedTlsPort {

bool entropyAvailable() {
#ifdef CRYPTO_HARDWARE_AVAILABLE
  return Crypto::hasTRNG();
#else
  return false;
#endif
}

bool fillEntropy(uint8_t *buffer, size_t length, uint32_t timeoutMillis) {
  if (!entropyAvailable() || buffer == nullptr)
    return false;
  if (length == 0u)
    return true;

  size_t offset = 0;
  while (offset < length) {
    uint32_t word = 0;
#ifdef CRYPTO_HARDWARE_AVAILABLE
    if (!Crypto::randomWord(word, timeoutMillis))
      return false;
#else
    (void)timeoutMillis;
    return false;
#endif

    for (uint8_t byteIndex = 0; byteIndex < sizeof(word) && offset < length;
         ++byteIndex) {
      buffer[offset++] = static_cast<uint8_t>(word >> (byteIndex * 8u));
    }
  }

  return true;
}

int hardwareEntropy(void *context, unsigned char *output, size_t length,
                    size_t *outputLength) {
  (void)context;

  if (outputLength != nullptr)
    *outputLength = 0;

  if (output == nullptr)
    return -1;

  if (!fillEntropy(output, length))
    return -1;

  if (outputLength != nullptr)
    *outputLength = length;
  return 0;
}

namespace {
void wordsToBytes(const uint32_t words[4], unsigned char bytes[16]) {
  for (uint8_t wordIndex = 0; wordIndex < 4u; ++wordIndex) {
    const uint32_t word = words[wordIndex];
    bytes[(wordIndex * 4u) + 0u] = static_cast<unsigned char>(word);
    bytes[(wordIndex * 4u) + 1u] = static_cast<unsigned char>(word >> 8u);
    bytes[(wordIndex * 4u) + 2u] = static_cast<unsigned char>(word >> 16u);
    bytes[(wordIndex * 4u) + 3u] = static_cast<unsigned char>(word >> 24u);
  }
}

void bytesToWords(const unsigned char bytes[16], uint32_t words[4]) {
  for (uint8_t wordIndex = 0; wordIndex < 4u; ++wordIndex) {
    words[wordIndex] = static_cast<uint32_t>(bytes[(wordIndex * 4u) + 0u]) |
                       (static_cast<uint32_t>(bytes[(wordIndex * 4u) + 1u])
                        << 8u) |
                       (static_cast<uint32_t>(bytes[(wordIndex * 4u) + 2u])
                        << 16u) |
                       (static_cast<uint32_t>(bytes[(wordIndex * 4u) + 3u])
                        << 24u);
  }
}

int drbgEntropy(void *context, unsigned char *output, size_t length) {
  (void)context;
  return fillEntropy(output, length) ? 0 : -1;
}

bool aesEcb128(const uint32_t key[4], const uint32_t input[4],
               uint32_t output[4], int mode) {
  if (key == nullptr || input == nullptr || output == nullptr)
    return false;

#ifdef CRYPTO_HARDWARE_AVAILABLE
  if (Crypto::hasAES()) {
    return (mode == MBEDTLS_AES_ENCRYPT)
               ? Crypto::encryptEcb128(key, input, output)
               : Crypto::decryptEcb128(key, input, output);
  }
#endif

  unsigned char keyBytes[16] = {};
  unsigned char inputBytes[16] = {};
  unsigned char outputBytes[16] = {};
  wordsToBytes(key, keyBytes);
  wordsToBytes(input, inputBytes);

  mbedtls_aes_context context;
  mbedtls_aes_init(&context);

  const int keyResult =
      (mode == MBEDTLS_AES_ENCRYPT)
          ? mbedtls_aes_setkey_enc(&context, keyBytes, 128u)
          : mbedtls_aes_setkey_dec(&context, keyBytes, 128u);
  if (keyResult != 0) {
    mbedtls_aes_free(&context);
    return false;
  }

  const int cryptResult =
      mbedtls_aes_crypt_ecb(&context, mode, inputBytes, outputBytes);
  mbedtls_aes_free(&context);

  if (cryptResult != 0)
    return false;

  bytesToWords(outputBytes, output);
  return true;
}
} // namespace

bool drbgRandom(uint8_t *buffer, size_t length) {
  if (buffer == nullptr)
    return false;
  if (length == 0u)
    return true;

  mbedtls_ctr_drbg_context context;
  mbedtls_ctr_drbg_init(&context);

  const int seedResult = mbedtls_ctr_drbg_seed(&context, drbgEntropy, nullptr,
                                               nullptr, 0);
  if (seedResult != 0) {
    mbedtls_ctr_drbg_free(&context);
    return false;
  }

  const int randomResult = mbedtls_ctr_drbg_random(&context, buffer, length);
  mbedtls_ctr_drbg_free(&context);
  return randomResult == 0;
}

bool aesEcb128Encrypt(const uint32_t key[4], const uint32_t plaintext[4],
                      uint32_t ciphertext[4]) {
  return aesEcb128(key, plaintext, ciphertext, MBEDTLS_AES_ENCRYPT);
}

bool aesEcb128Decrypt(const uint32_t key[4], const uint32_t ciphertext[4],
                      uint32_t plaintext[4]) {
  return aesEcb128(key, ciphertext, plaintext, MBEDTLS_AES_DECRYPT);
}

} // namespace Crypto::MbedTlsPort

#pragma once

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/SimIOMbedTlsConfig.h"
#endif

#include <Crypto.h>
#include <mbedtls/build_info.h>

#include <stdint.h>

namespace Crypto::MbedTlsPort {

/**
 * @brief Async Mbed TLS hardware adapter boundary.
 *
 * This layer is the only place where Mbed TLS-facing code may request SAME5x
 * crypto hardware work. It does not provide synchronous entropy, DRBG, or AES
 * helpers. Callers submit work and receive completion through the registered
 * peripheral callbacks.
 */

bool registerAesCallback(Crypto::AesCallback callback, void *context = nullptr);
void clearAesCallback();
bool aesEcb128EncryptAsync(const uint32_t key[4], const uint32_t plaintext[4],
                           uint32_t ciphertext[4]);
bool aesEcb128DecryptAsync(const uint32_t key[4], const uint32_t ciphertext[4],
                           uint32_t plaintext[4]);

bool registerTrngCallback(Crypto::TrngCallback callback,
                          void *context = nullptr);
void clearTrngCallback();
bool requestEntropyWordAsync();

bool registerPukccCallback(Crypto::PukccCallback callback,
                           void *context = nullptr);
void clearPukccCallback();
bool selfTestAsync(pukcc::SelfTestResult &result);
bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result);
bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result);

} // namespace Crypto::MbedTlsPort

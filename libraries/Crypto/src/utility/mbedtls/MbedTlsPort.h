#pragma once

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/SimIOMbedTlsConfig.h"
#endif

#include <mbedtls/build_info.h>

#include <stddef.h>
#include <stdint.h>

namespace Crypto::MbedTlsPort {

/**
 * @brief Return true when the platform has a hardware entropy source.
 *
 * This is the contract used by the Mbed TLS integration layer before it
 * registers the SimIO entropy source. On SAME5x targets it maps to the TRNG
 * peripheral through the public Crypto/TRNG boundary; it must fail closed on
 * targets without TRNG support.
 */
bool entropyAvailable();

/**
 * @brief Fill a buffer with hardware entropy using a bounded wait.
 *
 * The implementation pulls from the framework TRNG path and never fabricates
 * entropy. It returns false if the hardware source is unavailable, the buffer
 * pointer is invalid, or the timeout expires before all bytes are filled.
 */
bool fillEntropy(uint8_t *buffer, size_t length, uint32_t timeoutMillis = 100u);

/**
 * @brief Mbed TLS entropy source callback backed by SimIO hardware entropy.
 *
 * Signature matches `mbedtls_entropy_f_source_ptr`. It writes exactly the
 * number of bytes requested or fails; partial output is reported through
 * `outputLength` for Mbed TLS diagnostics.
 *
 * @return 0 on success, negative on entropy failure.
 */
int hardwareEntropy(void *context, unsigned char *output, size_t length,
                    size_t *outputLength);

/**
 * @brief Fill a buffer with bytes from Mbed TLS CTR_DRBG seeded by TRNG.
 *
 * This proves that production randomness flows through Mbed TLS rather than
 * bypassing it. The seed callback is `fillEntropy()`, so the function fails
 * closed when hardware entropy is unavailable.
 */
bool drbgRandom(uint8_t *buffer, size_t length);

/**
 * @brief Encrypt one AES-128 ECB block through the selected Mbed TLS backend.
 *
 * This is a narrow integration proof for the Mbed TLS AES source selected by
 * the Crypto library manifest. It does not claim SAME5x AES acceleration yet;
 * hardware acceleration belongs behind the Mbed TLS AES/PSA backend boundary in
 * a later slice.
 */
bool aesEcb128Encrypt(const uint32_t key[4], const uint32_t plaintext[4],
                      uint32_t ciphertext[4]);

/**
 * @brief Decrypt one AES-128 ECB block through the selected Mbed TLS backend.
 *
 * The word order matches the existing SAME5x AES hardware proof vectors:
 * little-endian words map to canonical AES byte strings.
 */
bool aesEcb128Decrypt(const uint32_t key[4], const uint32_t ciphertext[4],
                      uint32_t plaintext[4]);

} // namespace Crypto::MbedTlsPort

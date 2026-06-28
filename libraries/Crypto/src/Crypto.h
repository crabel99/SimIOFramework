#pragma once

#include <AES.h>
#include <PUKCC.h>
#include <TRNG.h>

#include <stdint.h>

#ifdef CRYPTO_HARDWARE_AVAILABLE
/**
 * @brief Public crypto adapter consumed by SecureClient and provisioning code.
 *
 * The Crypto library is not a home-grown TLS or cryptographic algorithm
 * library. It is the framework-facing API boundary that higher layers consume.
 * Production TLS, certificate parsing, DRBG construction, authenticated modes,
 * and public-key algorithms must be provided by Mbed TLS. The SAME5x `AES`,
 * `PUKCC`, and `TRNG` core modules are hardware backends routed through that
 * library where doing so is correct and testable. Direct primitive helpers in
 * this namespace exist only to prove hardware behavior and to support the
 * Mbed TLS integration layer; they must not become parallel protocol logic.
 */
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

/**
 * @brief Read one random word from the hardware TRNG with a bounded wait.
 *
 * This is a direct hardware service helper. It starts the TRNG, polls the
 * non-blocking core `trng::read()` API until a word is available or the timeout
 * expires, then stops the TRNG. It does not own entropy pooling, DRBG state, or
 * TLS nonce/key policy.
 *
 * @param value Filled with the random word when the call returns true.
 * @param timeoutMillis Maximum time to wait for DATARDY.
 * @return true when a word was read, false when TRNG is unavailable or timed out.
 */
bool randomWord(uint32_t &value, uint32_t timeoutMillis = 100u);

/**
 * @brief Encrypt one 128-bit block with AES-128 ECB.
 *
 * This helper is intentionally a primitive testable block operation. It does
 * not apply padding, authenticate data, choose IVs, or make ECB safe for bulk
 * messages. Higher layers must provide secure mode policy.
 */
bool encryptEcb128(const uint32_t key[4], const uint32_t plaintext[4],
                   uint32_t ciphertext[4], uint32_t timeoutMillis = 100u);

/**
 * @brief Decrypt one 128-bit block with AES-128 ECB.
 *
 * This helper mirrors `encryptEcb128()` for primitive validation and hardware
 * backend use. Higher layers own message framing and secure mode policy.
 */
bool decryptEcb128(const uint32_t key[4], const uint32_t ciphertext[4],
                   uint32_t plaintext[4], uint32_t timeoutMillis = 100u);

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

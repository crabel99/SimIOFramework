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

using AesCallback = aes::EventCallback;
using TrngCallback = trng::EventCallback;
using PukccCallback = pukcc::EventCallback;

bool registerAesCallback(AesCallback callback, void *context = nullptr);
void clearAesCallback();
bool encryptEcb128Async(const uint32_t key[4], const uint32_t plaintext[4],
                        uint32_t ciphertext[4]);
bool decryptEcb128Async(const uint32_t key[4], const uint32_t ciphertext[4],
                        uint32_t plaintext[4]);
bool galoisMultiplyAsync(const uint32_t hashKey[4], const uint32_t input[4],
                         uint32_t output[4]);

bool registerTrngCallback(TrngCallback callback, void *context = nullptr);
void clearTrngCallback();
bool randomWordAsync(bool stopAfterWord = true);

bool registerPukccCallback(PukccCallback callback, void *context = nullptr);
void clearPukccCallback();
bool selfTestAsync(pukcc::SelfTestResult &result);
bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result);
bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result);
bool pukccServiceAsync(uint8_t serviceId, pukcc::ServiceParamHeader &param,
                       pukcc::ServiceResult &result);

} // namespace Crypto
#endif /* CRYPTO_HARDWARE_AVAILABLE */

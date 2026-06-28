#pragma once

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/TlsConfig.h"
#endif

#include <Crypto.h>
#include <utility/tls/TlsClientSession.h>
#include <mbedtls/build_info.h>
#include <mbedtls/private/ctr_drbg.h>

#include <stddef.h>
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

struct AesEcb128Context;

using AesEcb128Callback =
    void (*)(aes::EventMask events, AesEcb128Context &context, void *user);

/**
 * @brief Async AES-128 ECB operation context for the Mbed TLS adapter.
 *
 * This context mirrors the Mbed TLS pattern of owning key material and
 * operation direction, but it never performs work synchronously. A caller sets
 * the key direction, registers a completion callback, and submits one block.
 * Completion is delivered from the AES PendSV service after the SAME5x AES
 * peripheral has raised its interrupt.
 */
struct AesEcb128Context {
  uint32_t key[4] = {};
  aes::Direction direction = aes::Direction::Encrypt;
  bool keyConfigured = false;
  bool busy = false;
  AesEcb128Callback callback = nullptr;
  void *callbackContext = nullptr;
};

void aesEcb128Init(AesEcb128Context &context);
void aesEcb128Free(AesEcb128Context &context);
bool aesEcb128SetEncryptKey(AesEcb128Context &context, const uint32_t key[4]);
bool aesEcb128SetDecryptKey(AesEcb128Context &context, const uint32_t key[4]);
bool aesEcb128SetCallback(AesEcb128Context &context,
                          AesEcb128Callback callback,
                          void *callbackContext = nullptr);
bool aesEcb128CryptAsync(AesEcb128Context &context, const uint32_t input[4],
                         uint32_t output[4]);

struct EntropyContext;

using EntropyCallback =
    void (*)(bool success, EntropyContext &context, void *user);

/**
 * @brief Async TRNG-backed entropy collection context.
 *
 * The context fills caller-provided memory from SAME5x TRNG callbacks. It never
 * spins waiting for entropy. Consumers must submit a request and continue only
 * after the callback reports completion.
 */
struct EntropyContext {
  uint8_t *buffer = nullptr;
  size_t requestedLength = 0;
  size_t producedLength = 0;
  bool busy = false;
  EntropyCallback callback = nullptr;
  void *callbackContext = nullptr;
};

void entropyInit(EntropyContext &context);
void entropyFree(EntropyContext &context);
bool entropySetCallback(EntropyContext &context, EntropyCallback callback,
                        void *callbackContext = nullptr);
bool entropyRequestAsync(EntropyContext &context, uint8_t *buffer,
                         size_t length);

struct RandomContext;

using RandomCallback =
    void (*)(bool success, RandomContext &context, void *user);

/**
 * @brief Async random-byte prefetch context for TLS consumers.
 *
 * This is not a replacement for Mbed TLS DRBG policy. It is the async boundary
 * that keeps the future DRBG/TLS state machine from blocking inside an RNG
 * callback. Callers prefetch entropy-backed bytes, receive callback completion,
 * and then consume available bytes with `randomRead()`.
 */
struct RandomContext {
  static constexpr size_t PoolSize = 64;

  EntropyContext entropy = {};
  uint8_t pool[PoolSize] = {};
  size_t availableLength = 0;
  size_t readOffset = 0;
  bool busy = false;
  RandomCallback callback = nullptr;
  void *callbackContext = nullptr;
};

void randomInit(RandomContext &context);
void randomFree(RandomContext &context);
bool randomSetCallback(RandomContext &context, RandomCallback callback,
                       void *callbackContext = nullptr);
bool randomPrefetchAsync(RandomContext &context, size_t length);
size_t randomAvailable(const RandomContext &context);
bool randomRead(RandomContext &context, uint8_t *buffer, size_t length);

struct DrbgSeedContext;

using DrbgSeedCallback =
    void (*)(bool success, DrbgSeedContext &context, void *user);

/**
 * @brief Async seed-material context for Mbed TLS DRBG setup.
 *
 * This context does not implement a DRBG. It gathers entropy-backed seed
 * material asynchronously so the later Mbed TLS CTR_DRBG seed step can run from
 * already-available bytes. If the seed material is not ready, the TLS state
 * machine must report WaitingCrypto instead of calling a blocking entropy
 * callback.
 */
struct DrbgSeedContext {
  static constexpr size_t SeedSize = 48;

  RandomContext random = {};
  uint8_t seed[SeedSize] = {};
  bool ready = false;
  bool busy = false;
  DrbgSeedCallback callback = nullptr;
  void *callbackContext = nullptr;
};

void drbgSeedInit(DrbgSeedContext &context);
void drbgSeedFree(DrbgSeedContext &context);
bool drbgSeedSetCallback(DrbgSeedContext &context, DrbgSeedCallback callback,
                         void *callbackContext = nullptr);
bool drbgSeedAsync(DrbgSeedContext &context);
bool drbgSeedRead(DrbgSeedContext &context, uint8_t *buffer, size_t length);

struct CtrDrbgContext;

using CtrDrbgCallback =
    void (*)(bool success, CtrDrbgContext &context, void *user);

/**
 * @brief Async-safe Mbed TLS CTR_DRBG wrapper.
 *
 * The underlying CTR_DRBG implementation is Mbed TLS. This wrapper only
 * controls when Mbed TLS is allowed to run: instantiation first collects seed
 * material through `DrbgSeedContext`, then calls Mbed TLS with a non-blocking
 * entropy callback that copies already-ready bytes. Random generation is
 * fail-fast and bounded; it never waits on TRNG or hardware completion.
 */
struct CtrDrbgContext {
  static constexpr size_t MaxPersonalizationSize = 64;

  DrbgSeedContext seed = {};
  mbedtls_ctr_drbg_context drbg = {};
  uint8_t seedMaterial[DrbgSeedContext::SeedSize] = {};
  uint8_t personalization[MaxPersonalizationSize] = {};
  size_t seedReadOffset = 0;
  size_t personalizationLength = 0;
  bool initialized = false;
  bool busy = false;
  CtrDrbgCallback callback = nullptr;
  void *callbackContext = nullptr;
};

void ctrDrbgInit(CtrDrbgContext &context);
void ctrDrbgFree(CtrDrbgContext &context);
bool ctrDrbgSetCallback(CtrDrbgContext &context, CtrDrbgCallback callback,
                        void *callbackContext = nullptr);
bool ctrDrbgInstantiateAsync(CtrDrbgContext &context,
                             const uint8_t *personalization = nullptr,
                             size_t personalizationLength = 0);
bool ctrDrbgReady(const CtrDrbgContext &context);
bool ctrDrbgGenerate(CtrDrbgContext &context, uint8_t *buffer, size_t length);

/**
 * @brief Production TLS crypto-readiness provider backed by Mbed TLS.
 *
 * The provider owns the Mbed TLS CTR_DRBG wrapper used by TLS sessions. Starting
 * handshake crypto submits async TRNG-backed seed collection and reports
 * readiness through the `TlsCryptoProvider` callback. It never blocks waiting
 * for entropy or hardware completion. TLS protocol state remains owned by
 * `TlsClientSession`; this provider only owns RNG/crypto readiness.
 */
class MbedTlsCryptoProvider : public Crypto::TlsCryptoProvider {
public:
  MbedTlsCryptoProvider();
  ~MbedTlsCryptoProvider() override;

  bool beginHandshakeCrypto(Crypto::TlsCryptoReadyCallback callback,
                            void *context) override;
  void reset() override;
  bool ready() const override;
  bool generateRandom(uint8_t *buffer, size_t length);

private:
  static void handleDrbgReady(bool success, CtrDrbgContext &context,
                              void *user);

  CtrDrbgContext _drbg;
  Crypto::TlsCryptoReadyCallback _callback;
  void *_callbackContext;
};

bool registerPukccCallback(Crypto::PukccCallback callback,
                           void *context = nullptr);
void clearPukccCallback();
bool selfTestAsync(pukcc::SelfTestResult &result);
bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result);
bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result);

} // namespace Crypto::MbedTlsPort

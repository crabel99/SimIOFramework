#pragma once

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/TlsConfig.h"
#endif

#include <Crypto.h>
#include <utility/tls/TlsClientSession.h>
#ifdef CRYPTO_HARDWARE_AVAILABLE
#include <utility/pukcc/PukccEcc.h>
#endif
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

struct AesGcm128Context;

using AesGcm128Callback = void (*)(bool success, AesGcm128Context &context,
                                   void *user);

/**
 * @brief Async AES-128-GCM one-shot operation context.
 *
 * The context implements GCM as a hardware-backed state machine: AES-ECB
 * encrypts counter blocks, AES GFMUL advances GHASH, and the wrapper performs
 * only counter increment, XOR, padding, and tag comparison. Callers submit one
 * complete GCM record and receive completion from callbacks; no software AES or
 * software field multiplication is permitted on this path.
 */
struct AesGcm128Context {
  enum class Step : uint8_t {
    Idle,
    HashSubkey,
    Aad,
    PayloadKeystream,
    PayloadGhash,
    LengthBlock,
    TagMask,
    Complete,
    Error,
  };

  AesEcb128Context aes = {};
  uint32_t key[4] = {};
  uint32_t hashKey[4] = {};
  uint32_t workInput[4] = {};
  uint32_t workOutput[4] = {};
  uint8_t counter[16] = {};
  uint8_t j0[16] = {};
  uint8_t ghash[16] = {};
  const uint8_t *aad = nullptr;
  size_t aadLength = 0;
  size_t aadOffset = 0;
  const uint8_t *input = nullptr;
  uint8_t *output = nullptr;
  size_t length = 0;
  size_t payloadOffset = 0;
  uint8_t *tagOut = nullptr;
  const uint8_t *tagIn = nullptr;
  bool encrypt = true;
  bool keyConfigured = false;
  bool busy = false;
  Step step = Step::Idle;
  AesGcm128Callback callback = nullptr;
  void *callbackContext = nullptr;
};

void aesGcm128Init(AesGcm128Context &context);
void aesGcm128Free(AesGcm128Context &context);
bool aesGcm128SetKey(AesGcm128Context &context, const uint8_t key[16]);
bool aesGcm128SetCallback(AesGcm128Context &context, AesGcm128Callback callback,
                          void *callbackContext = nullptr);
bool aesGcm128EncryptAsync(AesGcm128Context &context, const uint8_t nonce[12],
                           const uint8_t *aad, size_t aadLength,
                           const uint8_t *plaintext, uint8_t *ciphertext,
                           size_t length, uint8_t tag[16]);
bool aesGcm128DecryptAsync(AesGcm128Context &context, const uint8_t nonce[12],
                           const uint8_t *aad, size_t aadLength,
                           const uint8_t *ciphertext, uint8_t *plaintext,
                           size_t length, const uint8_t tag[16]);

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
 * and then consume available bytes with `randomRead()`. The pool is sensitive
 * material: consumed bytes are zeroized immediately, failed fills zeroize the
 * pool, and `randomFree()` clears any unconsumed bytes. Callers own zeroizing
 * their destination buffers after use.
 */
struct RandomContext {
  static constexpr size_t PoolSize = 128;

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
 *
 * This is a bring-up boundary, not final hardware acceleration. Entropy
 * collection is async TRNG-backed, but the CTR_DRBG block computations still
 * execute inside Mbed TLS software until an exact async AES-backed DRBG path is
 * added and tested.
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
bool ctrDrbgInstantiateFromSeedAsync(CtrDrbgContext &context,
                                     const uint8_t *seedMaterial,
                                     size_t seedLength,
                                     const uint8_t *personalization = nullptr,
                                     size_t personalizationLength = 0);
bool ctrDrbgReady(const CtrDrbgContext &context);
bool ctrDrbgGenerate(CtrDrbgContext &context, uint8_t *buffer, size_t length);

bool setExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
void clearExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
bool generateExternalRandom(uint8_t *buffer, size_t length);

/**
 * @brief Production TLS crypto-readiness provider backed by async hardware.
 *
 * `randomBytesAsync()` is the production random contract: it fills
 * operation-owned buffers directly from TRNG callback completions without a
 * reusable provider pool. Starting handshake crypto still submits a bounded
 * TRNG-backed prefetch only for legacy Mbed TLS callback points that cannot
 * yield. `generateRandom()` consumes that transitional pool and fails closed
 * when it is exhausted; it never calls a software DRBG or waits for entropy.
 * TLS protocol state remains owned by `TlsClientSession`; this provider only
 * owns RNG/crypto readiness.
 *
 * The provider routes supported P-256 ECDH, ECDSA signing, and ECDSA
 * verification operations through async PUKCC hardware and fails closed on
 * invalid peer points before scalar multiplication or signature verification.
 * AES-128-GCM record protection is routed through the async AES/GHASH hardware
 * state machine.
 */
class MbedTlsCryptoProvider : public Crypto::TlsCryptoProvider {
public:
  MbedTlsCryptoProvider();
  ~MbedTlsCryptoProvider() override;

  bool beginHandshakeCrypto(Crypto::TlsCryptoReadyCallback callback,
                            void *context) override;
  void reset() override;
  bool ready() const override;
  bool generateRandom(uint8_t *buffer, size_t length) override;
  bool randomBytesAsync(uint8_t *buffer, size_t length,
                        Crypto::TlsRandomCallback callback,
                        void *context) override;
  bool ecdhP256SharedSecretAsync(const uint8_t privateScalar[32],
                                 const uint8_t peerPublicKey[65],
                                 uint8_t sharedSecret[32],
                                 Crypto::TlsEcdhP256Callback callback,
                                 void *context) override;
  bool ecdsaP256SignAsync(const uint8_t privateKey[32],
                          const uint8_t nonceScalar[32],
                          const uint8_t hash[32], uint8_t signature[64],
                          Crypto::TlsEcdsaP256SignCallback callback,
                          void *context) override;
  bool ecdsaP256VerifyAsync(const uint8_t publicKey[65], const uint8_t hash[32],
                            const uint8_t signature[64],
                            Crypto::TlsEcdsaP256VerifyCallback callback,
                            void *context) override;
  bool aesGcm128EncryptAsync(const uint8_t key[16], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aadLength,
                             const uint8_t *plaintext, uint8_t *ciphertext,
                             size_t length, uint8_t tag[16],
                             Crypto::TlsAesGcm128Callback callback,
                             void *context) override;
  bool aesGcm128DecryptAsync(const uint8_t key[16], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aadLength,
                             const uint8_t *ciphertext, uint8_t *plaintext,
                             size_t length, const uint8_t tag[16],
                             Crypto::TlsAesGcm128Callback callback,
                             void *context) override;

private:
#ifdef CRYPTO_HARDWARE_AVAILABLE
  enum class EcdsaVerifyStep : uint8_t {
    Idle,
    ReductionSetup,
    PublicKeyValidation,
    Verify,
    Complete,
    Error,
  };
  enum class EcdsaSignStep : uint8_t {
    Idle,
    ReductionSetup,
    Generate,
    Complete,
    Error,
  };
#endif

  static void handleRandomReady(bool success, RandomContext &context,
                                void *user);
  static void handleDirectRandomReady(bool success, EntropyContext &context,
                                      void *user);
  void finishDirectRandom(bool success);
#ifdef CRYPTO_HARDWARE_AVAILABLE
  static void handleEcdhComplete(bool success, pukcc::ServiceResult &result,
                                 Crypto::PukccEcc::EcdhSharedSecretOperation
                                     &operation,
                                 void *user);
  void finishEcdh(bool success);
  void clearEcdhWorkspace();
  static void handleEcdsaService(pukcc::EventMask events, uint8_t service,
                                 uint16_t status, void *user);
  bool submitEcdsaStep();
  void finishEcdsa(bool success);
  void clearEcdsaWorkspace();
  static void handleEcdsaSignService(pukcc::EventMask events, uint8_t service,
                                     uint16_t status, void *user);
  bool submitEcdsaSignStep();
  void finishEcdsaSign(bool success);
  void clearEcdsaSignWorkspace();
#endif
  static void handleGcmComplete(bool success, AesGcm128Context &operation,
                                void *user);
  void finishGcm(bool success);

  RandomContext _random;
  EntropyContext _directRandom;
  Crypto::TlsRandomCallback _directRandomCallback;
  void *_directRandomCallbackContext;
  bool _directRandomBusy;
  Crypto::TlsCryptoReadyCallback _callback;
  void *_callbackContext;
  AesGcm128Context _gcmOperation;
  Crypto::TlsAesGcm128Callback _gcmCallback;
  void *_gcmCallbackContext;
  bool _gcmBusy;
#ifdef CRYPTO_HARDWARE_AVAILABLE
  Crypto::PukccEcc::EcdhSharedSecretOperation _ecdhOperation;
  uint8_t *_ecdhSharedSecret;
  Crypto::TlsEcdhP256Callback _ecdhCallback;
  void *_ecdhCallbackContext;
  bool _ecdhBusy;
  Crypto::PukccEcc::ReductionSetupOperation _ecdsaSignReductionSetup;
  Crypto::PukccEcc::EcdsaGenerateOperation _ecdsaSign;
  pukcc::ServiceResult _ecdsaSignResult;
  uint8_t *_ecdsaSignature;
  Crypto::TlsEcdsaP256SignCallback _ecdsaSignCallback;
  void *_ecdsaSignCallbackContext;
  EcdsaSignStep _ecdsaSignStep;
  bool _ecdsaSignBusy;
  Crypto::PukccEcc::ReductionSetupOperation _ecdsaReductionSetup;
  Crypto::PukccEcc::PointIsOnCurveOperation _ecdsaPublicKeyValidation;
  Crypto::PukccEcc::EcdsaVerifyOperation _ecdsaVerify;
  pukcc::ServiceResult _ecdsaResult;
  Crypto::TlsEcdsaP256VerifyCallback _ecdsaCallback;
  void *_ecdsaCallbackContext;
  EcdsaVerifyStep _ecdsaStep;
  bool _ecdsaBusy;
#endif
};

bool registerPukccCallback(Crypto::PukccCallback callback,
                           void *context = nullptr);
void clearPukccCallback();
bool selfTestAsync(pukcc::SelfTestResult &result);
bool clearFlagsAsync(uint32_t initialFlags, pukcc::ServiceResult &result);
bool fillCryptoRamAsync(uint16_t offset, uint16_t length, uint32_t fillValue,
                        pukcc::ServiceResult &result);

} // namespace Crypto::MbedTlsPort

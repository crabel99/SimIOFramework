#include "MbedTlsPort.h"

#include <mbedtls/platform_util.h>

namespace Crypto::MbedTlsPort {

namespace {
#ifdef CRYPTO_HARDWARE_AVAILABLE
constexpr uint16_t P256Length = 32u;
constexpr uint16_t P256CoordinateStorageLength = P256Length + 4u;
constexpr uint16_t EcdhModulusOffset = 0u;
constexpr uint16_t EcdhModulusStorageLength = P256Length + 4u;
constexpr uint16_t EcdhConstantOffset =
    EcdhModulusOffset + EcdhModulusStorageLength;
constexpr uint16_t EcdhCurveAOffset = EcdhConstantOffset + P256Length + 12u;
constexpr uint16_t EcdhCurveBOffset = EcdhCurveAOffset + P256Length + 4u;
constexpr uint16_t EcdhPointOffset = EcdhCurveBOffset + P256Length + 4u;
constexpr uint16_t EcdhPointLength = P256Length * 3u + 20u;
constexpr uint16_t EcdhScalarOffset = EcdhPointOffset + EcdhPointLength;
constexpr uint16_t EcdhWorkspaceOffset = EcdhScalarOffset + P256Length + 4u;
constexpr uint16_t EcdhWorkspaceLength = P256Length * 6u;
constexpr uint16_t EcdhWorkspaceEnd = EcdhWorkspaceOffset + EcdhWorkspaceLength;

const uint8_t P256Prime[P256Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x01u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
const uint8_t P256A[P256Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x01u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu};
const uint8_t P256B[P256Length] = {
    0x5Au, 0xC6u, 0x35u, 0xD8u, 0xAAu, 0x3Au, 0x93u, 0xE7u,
    0xB3u, 0xEBu, 0xBDu, 0x55u, 0x76u, 0x98u, 0x86u, 0xBCu,
    0x65u, 0x1Du, 0x06u, 0xB0u, 0xCCu, 0x53u, 0xB0u, 0xF6u,
    0x3Bu, 0xCEu, 0x3Cu, 0x3Eu, 0x27u, 0xD2u, 0x60u, 0x4Bu};
const uint8_t ProjectiveOne[1] = {0x01u};

bool copyCryptoRamToBigEndian(uint16_t offset, uint8_t *destination,
                              uint16_t length) {
  if (destination == nullptr || !pukcc::validCryptoRamRange(offset, length))
    return false;

  volatile uint8_t *source = pukcc::cryptoRam(offset);
  for (uint16_t index = 0; index < length; ++index)
    destination[index] = source[length - 1u - index];
  return true;
}

void clearCryptoRamRange(uint16_t offset, uint16_t length) {
  if (!pukcc::validCryptoRamRange(offset, length))
    return;

  volatile uint8_t *memory = pukcc::cryptoRam(offset);
  for (uint16_t index = 0; index < length; ++index)
    memory[index] = 0;
}
#endif

void secureZero(void *buffer, size_t length) {
  if (buffer != nullptr && length != 0)
    mbedtls_platform_zeroize(buffer, length);
}

template <typename T, size_t N> void secureZeroArray(T (&buffer)[N]) {
  secureZero(buffer, sizeof(buffer));
}

void copyAesKey(uint32_t destination[4], const uint32_t source[4]) {
  for (uint8_t index = 0; index < 4; ++index)
    destination[index] = source[index];
}

void clearAesKey(uint32_t key[4]) { secureZero(key, sizeof(uint32_t) * 4); }

void aesContextCallback(aes::EventMask events, void *context) {
  auto *aesContext = static_cast<AesEcb128Context *>(context);
  if (aesContext == nullptr)
    return;

  aesContext->busy = false;
  if (aesContext->callback != nullptr)
    aesContext->callback(events, *aesContext, aesContext->callbackContext);
}

void clearEntropyRequest(EntropyContext &context) {
  context.buffer = nullptr;
  context.requestedLength = 0;
  context.producedLength = 0;
  context.busy = false;
}

void finishEntropy(EntropyContext &context, bool success) {
  context.busy = false;
  Crypto::clearTrngCallback();
  if (context.callback != nullptr)
    context.callback(success, context, context.callbackContext);
}

bool appendEntropyWord(EntropyContext &context, uint32_t value) {
  if (context.buffer == nullptr ||
      context.producedLength >= context.requestedLength)
    return false;

  for (uint8_t byteIndex = 0;
       byteIndex < 4 && context.producedLength < context.requestedLength;
       ++byteIndex) {
    context.buffer[context.producedLength++] =
        static_cast<uint8_t>((value >> (8u * byteIndex)) & 0xFFu);
  }

  return true;
}

void entropyTrngCallback(trng::EventMask events, uint32_t value, void *context) {
  auto *entropyContext = static_cast<EntropyContext *>(context);
  if (entropyContext == nullptr || !entropyContext->busy)
    return;

  if ((events & trng::EventDataReady) == 0 ||
      !appendEntropyWord(*entropyContext, value)) {
    finishEntropy(*entropyContext, false);
    return;
  }

  if (entropyContext->producedLength >= entropyContext->requestedLength) {
    finishEntropy(*entropyContext, true);
    return;
  }

  if (!Crypto::randomWordAsync())
    finishEntropy(*entropyContext, false);
}

void randomEntropyCallback(bool success, EntropyContext &entropy, void *context) {
  auto *randomContext = static_cast<RandomContext *>(context);
  if (randomContext == nullptr || !randomContext->busy)
    return;

  randomContext->busy = false;
  randomContext->readOffset = 0;
  randomContext->availableLength = success ? entropy.producedLength : 0;
  if (randomContext->callback != nullptr)
    randomContext->callback(success, *randomContext,
                            randomContext->callbackContext);
}

void drbgSeedRandomCallback(bool success, RandomContext &random, void *context) {
  auto *seedContext = static_cast<DrbgSeedContext *>(context);
  if (seedContext == nullptr || !seedContext->busy)
    return;

  seedContext->ready = false;
  if (success) {
    seedContext->ready =
        randomRead(random, seedContext->seed, DrbgSeedContext::SeedSize);
  }

  seedContext->busy = false;
  if (seedContext->callback != nullptr)
    seedContext->callback(seedContext->ready, *seedContext,
                          seedContext->callbackContext);
}

int ctrDrbgEntropyCallback(void *context, unsigned char *buffer,
                           size_t length) {
  auto *drbgContext = static_cast<CtrDrbgContext *>(context);
  if (drbgContext == nullptr || buffer == nullptr ||
      drbgContext->seedReadOffset + length > DrbgSeedContext::SeedSize) {
    return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
  }

  for (size_t index = 0; index < length; ++index) {
    const size_t seedIndex = drbgContext->seedReadOffset + index;
    buffer[index] = drbgContext->seedMaterial[seedIndex];
    drbgContext->seedMaterial[seedIndex] = 0;
  }
  drbgContext->seedReadOffset += length;
  return 0;
}

void clearCtrDrbgPersonalization(CtrDrbgContext &context) {
  secureZeroArray(context.personalization);
  context.personalizationLength = 0;
}

void ctrDrbgSeedCallback(bool success, DrbgSeedContext &seedContext,
                         void *context) {
  auto *drbgContext = static_cast<CtrDrbgContext *>(context);
  if (drbgContext == nullptr || !drbgContext->busy)
    return;

  bool ready = false;
  if (success &&
      drbgSeedRead(seedContext, drbgContext->seedMaterial,
                   DrbgSeedContext::SeedSize)) {
    mbedtls_ctr_drbg_free(&drbgContext->drbg);
    mbedtls_ctr_drbg_init(&drbgContext->drbg);
    mbedtls_ctr_drbg_set_prediction_resistance(&drbgContext->drbg,
                                               MBEDTLS_CTR_DRBG_PR_OFF);
    mbedtls_ctr_drbg_set_entropy_len(&drbgContext->drbg,
                                     MBEDTLS_CTR_DRBG_ENTROPY_LEN);
    (void)mbedtls_ctr_drbg_set_nonce_len(
        &drbgContext->drbg,
        DrbgSeedContext::SeedSize - MBEDTLS_CTR_DRBG_ENTROPY_LEN);
    drbgContext->seedReadOffset = 0;
    const unsigned char *personalization =
        drbgContext->personalizationLength == 0
            ? nullptr
            : drbgContext->personalization;
    ready = mbedtls_ctr_drbg_seed(&drbgContext->drbg, ctrDrbgEntropyCallback,
                                  drbgContext, personalization,
                                  drbgContext->personalizationLength) == 0;
  }

  secureZeroArray(drbgContext->seedMaterial);
  clearCtrDrbgPersonalization(*drbgContext);
  drbgContext->initialized = ready;
  drbgContext->busy = false;
  if (!ready)
    mbedtls_ctr_drbg_free(&drbgContext->drbg);
  if (drbgContext->callback != nullptr)
    drbgContext->callback(ready, *drbgContext, drbgContext->callbackContext);
}
} // namespace

void aesEcb128Init(AesEcb128Context &context) {
  clearAesKey(context.key);
  context.direction = aes::Direction::Encrypt;
  context.keyConfigured = false;
  context.busy = false;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void aesEcb128Free(AesEcb128Context &context) {
  if (context.busy)
    Crypto::clearAesCallback();
  aesEcb128Init(context);
}

bool aesEcb128SetEncryptKey(AesEcb128Context &context, const uint32_t key[4]) {
  if (key == nullptr || context.busy)
    return false;

  copyAesKey(context.key, key);
  context.direction = aes::Direction::Encrypt;
  context.keyConfigured = true;
  return true;
}

bool aesEcb128SetDecryptKey(AesEcb128Context &context, const uint32_t key[4]) {
  if (key == nullptr || context.busy)
    return false;

  copyAesKey(context.key, key);
  context.direction = aes::Direction::Decrypt;
  context.keyConfigured = true;
  return true;
}

bool aesEcb128SetCallback(AesEcb128Context &context,
                          AesEcb128Callback callback, void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool aesEcb128CryptAsync(AesEcb128Context &context, const uint32_t input[4],
                         uint32_t output[4]) {
  if (input == nullptr || output == nullptr || !context.keyConfigured ||
      context.callback == nullptr || context.busy) {
    return false;
  }

  if (!Crypto::registerAesCallback(aesContextCallback, &context))
    return false;

  context.busy = true;
  const bool submitted =
      (context.direction == aes::Direction::Encrypt)
          ? Crypto::encryptEcb128Async(context.key, input, output)
          : Crypto::decryptEcb128Async(context.key, input, output);
  if (!submitted) {
    context.busy = false;
    Crypto::clearAesCallback();
  }

  return submitted;
}

void entropyInit(EntropyContext &context) {
  clearEntropyRequest(context);
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void entropyFree(EntropyContext &context) {
  if (context.busy)
    Crypto::clearTrngCallback();
  entropyInit(context);
}

bool entropySetCallback(EntropyContext &context, EntropyCallback callback,
                        void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool entropyRequestAsync(EntropyContext &context, uint8_t *buffer,
                         size_t length) {
  if (context.busy || context.callback == nullptr || buffer == nullptr ||
      length == 0) {
    return false;
  }

  context.buffer = buffer;
  context.requestedLength = length;
  context.producedLength = 0;
  context.busy = true;

  if (!Crypto::registerTrngCallback(entropyTrngCallback, &context) ||
      !Crypto::randomWordAsync()) {
    clearEntropyRequest(context);
    Crypto::clearTrngCallback();
    return false;
  }

  return true;
}

void randomInit(RandomContext &context) {
  entropyInit(context.entropy);
  secureZeroArray(context.pool);
  context.availableLength = 0;
  context.readOffset = 0;
  context.busy = false;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void randomFree(RandomContext &context) {
  if (context.busy)
    entropyFree(context.entropy);
  randomInit(context);
}

bool randomSetCallback(RandomContext &context, RandomCallback callback,
                       void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool randomPrefetchAsync(RandomContext &context, size_t length) {
  if (context.busy || context.callback == nullptr || length == 0 ||
      length > RandomContext::PoolSize) {
    return false;
  }

  context.availableLength = 0;
  context.readOffset = 0;
  context.busy = true;
  if (!entropySetCallback(context.entropy, randomEntropyCallback, &context) ||
      !entropyRequestAsync(context.entropy, context.pool, length)) {
    context.busy = false;
    context.availableLength = 0;
    context.readOffset = 0;
    entropyFree(context.entropy);
    return false;
  }

  return true;
}

size_t randomAvailable(const RandomContext &context) {
  if (context.availableLength < context.readOffset)
    return 0;

  return context.availableLength - context.readOffset;
}

bool randomRead(RandomContext &context, uint8_t *buffer, size_t length) {
  if (context.busy || buffer == nullptr || length == 0 ||
      length > randomAvailable(context)) {
    return false;
  }

  for (size_t index = 0; index < length; ++index)
    buffer[index] = context.pool[context.readOffset + index];

  secureZero(context.pool + context.readOffset, length);
  context.readOffset += length;
  return true;
}

void drbgSeedInit(DrbgSeedContext &context) {
  randomInit(context.random);
  secureZeroArray(context.seed);
  context.ready = false;
  context.busy = false;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void drbgSeedFree(DrbgSeedContext &context) {
  if (context.busy)
    randomFree(context.random);
  drbgSeedInit(context);
}

bool drbgSeedSetCallback(DrbgSeedContext &context, DrbgSeedCallback callback,
                         void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool drbgSeedAsync(DrbgSeedContext &context) {
  if (context.busy || context.callback == nullptr)
    return false;

  context.ready = false;
  context.busy = true;
  if (!randomSetCallback(context.random, drbgSeedRandomCallback, &context) ||
      !randomPrefetchAsync(context.random, DrbgSeedContext::SeedSize)) {
    context.busy = false;
    randomFree(context.random);
    return false;
  }

  return true;
}

bool drbgSeedRead(DrbgSeedContext &context, uint8_t *buffer, size_t length) {
  if (!context.ready || context.busy || buffer == nullptr ||
      length != DrbgSeedContext::SeedSize) {
    return false;
  }

  for (size_t index = 0; index < DrbgSeedContext::SeedSize; ++index)
    buffer[index] = context.seed[index];

  secureZeroArray(context.seed);
  context.ready = false;
  return true;
}

void ctrDrbgInit(CtrDrbgContext &context) {
  drbgSeedInit(context.seed);
  mbedtls_ctr_drbg_init(&context.drbg);
  secureZeroArray(context.seedMaterial);
  clearCtrDrbgPersonalization(context);
  context.seedReadOffset = 0;
  context.initialized = false;
  context.busy = false;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void ctrDrbgFree(CtrDrbgContext &context) {
  if (context.busy)
    drbgSeedFree(context.seed);
  mbedtls_ctr_drbg_free(&context.drbg);
  ctrDrbgInit(context);
}

bool ctrDrbgSetCallback(CtrDrbgContext &context, CtrDrbgCallback callback,
                        void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool ctrDrbgInstantiateAsync(CtrDrbgContext &context,
                             const uint8_t *personalization,
                             size_t personalizationLength) {
  if (context.busy || context.callback == nullptr ||
      personalizationLength > CtrDrbgContext::MaxPersonalizationSize ||
      (personalization == nullptr && personalizationLength != 0)) {
    return false;
  }

  clearCtrDrbgPersonalization(context);
  for (size_t index = 0; index < personalizationLength; ++index)
    context.personalization[index] = personalization[index];
  context.personalizationLength = personalizationLength;
  context.seedReadOffset = 0;
  context.initialized = false;
  context.busy = true;

  if (!drbgSeedSetCallback(context.seed, ctrDrbgSeedCallback, &context) ||
      !drbgSeedAsync(context.seed)) {
    context.busy = false;
    drbgSeedFree(context.seed);
    return false;
  }

  return true;
}

bool ctrDrbgInstantiateFromSeedAsync(CtrDrbgContext &context,
                                     const uint8_t *seedMaterial,
                                     size_t seedLength,
                                     const uint8_t *personalization,
                                     size_t personalizationLength) {
  if (context.busy || context.callback == nullptr || seedMaterial == nullptr ||
      seedLength != DrbgSeedContext::SeedSize ||
      personalizationLength > CtrDrbgContext::MaxPersonalizationSize ||
      (personalization == nullptr && personalizationLength != 0)) {
    return false;
  }

  clearCtrDrbgPersonalization(context);
  for (size_t index = 0; index < seedLength; ++index)
    context.seedMaterial[index] = seedMaterial[index];
  for (size_t index = 0; index < personalizationLength; ++index)
    context.personalization[index] = personalization[index];
  context.personalizationLength = personalizationLength;
  context.seedReadOffset = 0;
  context.initialized = false;
  context.busy = true;

  mbedtls_ctr_drbg_free(&context.drbg);
  mbedtls_ctr_drbg_init(&context.drbg);
  mbedtls_ctr_drbg_set_prediction_resistance(&context.drbg,
                                             MBEDTLS_CTR_DRBG_PR_OFF);
  mbedtls_ctr_drbg_set_entropy_len(&context.drbg, MBEDTLS_CTR_DRBG_ENTROPY_LEN);
  (void)mbedtls_ctr_drbg_set_nonce_len(
      &context.drbg, DrbgSeedContext::SeedSize - MBEDTLS_CTR_DRBG_ENTROPY_LEN);
  const unsigned char *personalizationBuffer =
      context.personalizationLength == 0 ? nullptr : context.personalization;
  const bool ready =
      mbedtls_ctr_drbg_seed(&context.drbg, ctrDrbgEntropyCallback, &context,
                            personalizationBuffer,
                            context.personalizationLength) == 0;

  secureZeroArray(context.seedMaterial);
  clearCtrDrbgPersonalization(context);
  context.initialized = ready;
  context.busy = false;
  if (!ready)
    mbedtls_ctr_drbg_free(&context.drbg);
  if (context.callback != nullptr)
    context.callback(ready, context, context.callbackContext);
  return ready;
}

bool ctrDrbgReady(const CtrDrbgContext &context) {
  return context.initialized && !context.busy;
}

bool ctrDrbgGenerate(CtrDrbgContext &context, uint8_t *buffer, size_t length) {
  if (!ctrDrbgReady(context) || buffer == nullptr || length == 0)
    return false;

  return mbedtls_ctr_drbg_random(&context.drbg, buffer, length) == 0;
}

MbedTlsCryptoProvider::MbedTlsCryptoProvider()
    : _callback(nullptr), _callbackContext(nullptr)
#ifdef CRYPTO_HARDWARE_AVAILABLE
      ,
      _ecdhOperation(), _ecdhSharedSecret(nullptr), _ecdhCallback(nullptr),
      _ecdhCallbackContext(nullptr), _ecdhBusy(false)
#endif
{
  ctrDrbgInit(_drbg);
}

MbedTlsCryptoProvider::~MbedTlsCryptoProvider() { reset(); }

bool MbedTlsCryptoProvider::beginHandshakeCrypto(
    Crypto::TlsCryptoReadyCallback callback, void *context) {
  if (callback == nullptr || _drbg.busy)
    return false;

  _callback = callback;
  _callbackContext = context;
  if (ctrDrbgReady(_drbg)) {
    Crypto::TlsCryptoReadyCallback readyCallback = _callback;
    void *readyContext = _callbackContext;
    _callback = nullptr;
    _callbackContext = nullptr;
    readyCallback(true, readyContext);
    return true;
  }

  if (!ctrDrbgSetCallback(_drbg, MbedTlsCryptoProvider::handleDrbgReady,
                          this) ||
      !ctrDrbgInstantiateAsync(_drbg)) {
    _callback = nullptr;
    _callbackContext = nullptr;
    return false;
  }

  return true;
}

void MbedTlsCryptoProvider::reset() {
  ctrDrbgFree(_drbg);
  _callback = nullptr;
  _callbackContext = nullptr;
#ifdef CRYPTO_HARDWARE_AVAILABLE
  if (_ecdhBusy)
    Crypto::clearPukccCallback();
  clearEcdhWorkspace();
  _ecdhOperation = {};
  _ecdhSharedSecret = nullptr;
  _ecdhCallback = nullptr;
  _ecdhCallbackContext = nullptr;
  _ecdhBusy = false;
#endif
}

bool MbedTlsCryptoProvider::ready() const { return ctrDrbgReady(_drbg); }

bool MbedTlsCryptoProvider::generateRandom(uint8_t *buffer, size_t length) {
  return ctrDrbgGenerate(_drbg, buffer, length);
}

bool MbedTlsCryptoProvider::ecdhP256SharedSecretAsync(
    const uint8_t privateScalar[32], const uint8_t peerPublicKey[65],
    uint8_t sharedSecret[32], Crypto::TlsEcdhP256Callback callback,
    void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)privateScalar;
  (void)peerPublicKey;
  (void)sharedSecret;
  (void)callback;
  (void)context;
  return false;
#else
  if (_ecdhBusy || privateScalar == nullptr || peerPublicKey == nullptr ||
      sharedSecret == nullptr || callback == nullptr ||
      peerPublicKey[0] != 0x04u) {
    return false;
  }

  clearEcdhWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhModulusOffset, EcdhModulusStorageLength, P256Prime,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhConstantOffset, P256Length + 12u, P256Prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhCurveAOffset, P256Length + 4u, P256A, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhCurveBOffset, P256Length + 4u, P256B, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset, EcdhPointLength, P256Prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset, P256CoordinateStorageLength, peerPublicKey + 1u,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + P256CoordinateStorageLength,
          P256CoordinateStorageLength, peerPublicKey + 1u + P256Length,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + P256CoordinateStorageLength * 2u,
          P256CoordinateStorageLength, ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhScalarOffset, P256Length + 4u, privateScalar, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhWorkspaceOffset, EcdhWorkspaceLength, P256Prime, 0u)) {
    clearEcdhWorkspace();
    return false;
  }

  _ecdhOperation = {};
  _ecdhOperation.reductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.reductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.reductionSetup.modulusLength = P256Length;
  _ecdhOperation.reductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);
  _ecdhOperation.reductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdhWorkspaceOffset + P256Length * 2u + 4u));
  _ecdhOperation.peerPointValidation.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.peerPointValidation.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.peerPointValidation.modulusLength = P256Length;
  _ecdhOperation.peerPointValidation.curveA =
      pukcc::cryptoRamNearPointer(EcdhCurveAOffset);
  _ecdhOperation.peerPointValidation.curveB =
      pukcc::cryptoRamNearPointer(EcdhCurveBOffset);
  _ecdhOperation.peerPointValidation.point =
      pukcc::cryptoRamNearPointer(EcdhPointOffset);
  _ecdhOperation.peerPointValidation.workspace =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);
  _ecdhOperation.multiply.point = pukcc::cryptoRamNearPointer(EcdhPointOffset);
  _ecdhOperation.multiply.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.multiply.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.multiply.scalar =
      pukcc::cryptoRamNearPointer(EcdhScalarOffset);
  _ecdhOperation.multiply.curveA =
      pukcc::cryptoRamNearPointer(EcdhCurveAOffset);
  _ecdhOperation.multiply.workspace =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);
  _ecdhOperation.multiply.modulusLength = P256Length;
  _ecdhOperation.multiply.scalarLength = P256Length;
  _ecdhOperation.affine.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.affine.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.affine.modulusLength = P256Length;
  _ecdhOperation.affine.point = pukcc::cryptoRamNearPointer(EcdhPointOffset);
  _ecdhOperation.affine.workspace =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);

  _ecdhSharedSecret = sharedSecret;
  _ecdhCallback = callback;
  _ecdhCallbackContext = context;
  _ecdhBusy = true;
  if (!Crypto::PukccEcc::startEcdhSharedSecretAsync(
          _ecdhOperation, MbedTlsCryptoProvider::handleEcdhComplete, this)) {
    finishEcdh(false);
    return false;
  }

  return true;
#endif
}

void MbedTlsCryptoProvider::handleDrbgReady(bool success,
                                            CtrDrbgContext &context,
                                            void *user) {
  (void)context;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr)
    return;

  Crypto::TlsCryptoReadyCallback callback = provider->_callback;
  void *callbackContext = provider->_callbackContext;
  provider->_callback = nullptr;
  provider->_callbackContext = nullptr;
  if (callback != nullptr)
    callback(success, callbackContext);
}

#ifdef CRYPTO_HARDWARE_AVAILABLE
void MbedTlsCryptoProvider::handleEcdhComplete(
    bool success, pukcc::ServiceResult &result,
    Crypto::PukccEcc::EcdhSharedSecretOperation &operation, void *user) {
  (void)result;
  (void)operation;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr)
    return;

  provider->finishEcdh(success);
}

void MbedTlsCryptoProvider::finishEcdh(bool success) {
  bool completed = false;
  if (success && _ecdhSharedSecret != nullptr) {
    completed = copyCryptoRamToBigEndian(EcdhPointOffset, _ecdhSharedSecret,
                                         P256Length);
  }

  Crypto::TlsEcdhP256Callback callback = _ecdhCallback;
  void *callbackContext = _ecdhCallbackContext;
  _ecdhOperation = {};
  _ecdhSharedSecret = nullptr;
  _ecdhCallback = nullptr;
  _ecdhCallbackContext = nullptr;
  _ecdhBusy = false;
  clearEcdhWorkspace();

  if (callback != nullptr)
    callback(success && completed, callbackContext);
}

void MbedTlsCryptoProvider::clearEcdhWorkspace() {
  clearCryptoRamRange(EcdhModulusOffset, EcdhWorkspaceEnd - EcdhModulusOffset);
}
#endif

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

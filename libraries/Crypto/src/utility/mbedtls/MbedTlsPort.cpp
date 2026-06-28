#include "MbedTlsPort.h"

namespace Crypto::MbedTlsPort {

namespace {
void copyAesKey(uint32_t destination[4], const uint32_t source[4]) {
  for (uint8_t index = 0; index < 4; ++index)
    destination[index] = source[index];
}

void clearAesKey(uint32_t key[4]) {
  for (uint8_t index = 0; index < 4; ++index)
    key[index] = 0;
}

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
    buffer[index] =
        drbgContext->seedMaterial[drbgContext->seedReadOffset + index];
  }
  drbgContext->seedReadOffset += length;
  return 0;
}

void clearCtrDrbgPersonalization(CtrDrbgContext &context) {
  for (size_t index = 0; index < CtrDrbgContext::MaxPersonalizationSize; ++index)
    context.personalization[index] = 0;
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
  for (size_t index = 0; index < RandomContext::PoolSize; ++index)
    context.pool[index] = 0;
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

  context.readOffset += length;
  return true;
}

void drbgSeedInit(DrbgSeedContext &context) {
  randomInit(context.random);
  for (size_t index = 0; index < DrbgSeedContext::SeedSize; ++index)
    context.seed[index] = 0;
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

  context.ready = false;
  return true;
}

void ctrDrbgInit(CtrDrbgContext &context) {
  drbgSeedInit(context.seed);
  mbedtls_ctr_drbg_init(&context.drbg);
  for (size_t index = 0; index < DrbgSeedContext::SeedSize; ++index)
    context.seedMaterial[index] = 0;
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

bool ctrDrbgReady(const CtrDrbgContext &context) {
  return context.initialized && !context.busy;
}

bool ctrDrbgGenerate(CtrDrbgContext &context, uint8_t *buffer, size_t length) {
  if (!ctrDrbgReady(context) || buffer == nullptr || length == 0)
    return false;

  return mbedtls_ctr_drbg_random(&context.drbg, buffer, length) == 0;
}

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

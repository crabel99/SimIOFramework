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
constexpr uint16_t EcdsaModulusOffset = 0u;
constexpr uint16_t EcdsaModulusStorageLength = P256Length + 4u;
constexpr uint16_t EcdsaConstantOffset =
    EcdsaModulusOffset + EcdsaModulusStorageLength;
constexpr uint16_t EcdsaOrderOffset = EcdsaConstantOffset + P256Length + 12u;
constexpr uint16_t EcdsaSignatureOffset = EcdsaOrderOffset + P256Length + 12u;
constexpr uint16_t EcdsaHashOffset =
    EcdsaSignatureOffset + P256Length * 2u + 8u;
constexpr uint16_t EcdsaBasePointOffset = EcdsaHashOffset + P256Length + 4u;
constexpr uint16_t EcdsaPublicKeyOffset =
    EcdsaBasePointOffset + P256CoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveAOffset =
    EcdsaPublicKeyOffset + P256CoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveBOffset = EcdsaCurveAOffset + P256Length + 4u;
constexpr uint16_t EcdsaWorkspaceOffset = EcdsaCurveBOffset + P256Length + 4u;
constexpr uint16_t EcdsaWorkspaceLength = P256Length * 8u + 44u;
constexpr uint16_t EcdsaWorkspaceEnd =
    EcdsaWorkspaceOffset + EcdsaWorkspaceLength;
constexpr uint16_t EcdsaSignModulusOffset = 0u;
constexpr uint16_t EcdsaSignModulusStorageLength = P256Length + 4u;
constexpr uint16_t EcdsaSignConstantOffset =
    EcdsaSignModulusOffset + EcdsaSignModulusStorageLength;
constexpr uint16_t EcdsaSignBasePointOffset =
    EcdsaSignConstantOffset + P256Length + 12u;
constexpr uint16_t EcdsaSignCurveAOffset =
    EcdsaSignBasePointOffset + P256CoordinateStorageLength * 3u;
constexpr uint16_t EcdsaSignPrivateKeyOffset =
    EcdsaSignCurveAOffset + P256Length + 4u;
constexpr uint16_t EcdsaSignScalarOffset =
    EcdsaSignPrivateKeyOffset + P256Length + 4u;
constexpr uint16_t EcdsaSignOrderOffset =
    EcdsaSignScalarOffset + P256Length + 4u;
constexpr uint16_t EcdsaSignHashOffset =
    EcdsaSignOrderOffset + P256Length + 4u;
constexpr uint16_t EcdsaSignWorkspaceOffset =
    EcdsaSignHashOffset + P256Length + 4u;
constexpr uint16_t EcdsaSignWorkspaceLength = P256Length * 8u + 44u;
constexpr uint16_t EcdsaSignWorkspaceEnd =
    EcdsaSignWorkspaceOffset + EcdsaSignWorkspaceLength;

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
const uint8_t P256Order[P256Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xBCu, 0xE6u, 0xFAu, 0xADu, 0xA7u, 0x17u,
    0x9Eu, 0x84u, 0xF3u, 0xB9u, 0xCAu, 0xC2u, 0xFCu, 0x63u, 0x25u, 0x51u};
const uint8_t P256Gx[P256Length] = {
    0x6Bu, 0x17u, 0xD1u, 0xF2u, 0xE1u, 0x2Cu, 0x42u, 0x47u, 0xF8u, 0xBCu, 0xE6u,
    0xE5u, 0x63u, 0xA4u, 0x40u, 0xF2u, 0x77u, 0x03u, 0x7Du, 0x81u, 0x2Du, 0xEBu,
    0x33u, 0xA0u, 0xF4u, 0xA1u, 0x39u, 0x45u, 0xD8u, 0x98u, 0xC2u, 0x96u};
const uint8_t P256Gy[P256Length] = {
    0x4Fu, 0xE3u, 0x42u, 0xE2u, 0xFEu, 0x1Au, 0x7Fu, 0x9Bu, 0x8Eu, 0xE7u, 0xEBu,
    0x4Au, 0x7Cu, 0x0Fu, 0x9Eu, 0x16u, 0x2Bu, 0xCEu, 0x33u, 0x57u, 0x6Bu, 0x31u,
    0x5Eu, 0xCEu, 0xCBu, 0xB6u, 0x40u, 0x68u, 0x37u, 0xBFu, 0x51u, 0xF5u};
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

void loadWordsFromBytes(uint32_t words[4], const uint8_t bytes[16]) {
  for (uint8_t word = 0; word < 4; ++word) {
    words[word] = static_cast<uint32_t>(bytes[word * 4u]) |
                  (static_cast<uint32_t>(bytes[word * 4u + 1u]) << 8u) |
                  (static_cast<uint32_t>(bytes[word * 4u + 2u]) << 16u) |
                  (static_cast<uint32_t>(bytes[word * 4u + 3u]) << 24u);
  }
}

void storeBytesFromWords(uint8_t bytes[16], const uint32_t words[4]) {
  for (uint8_t word = 0; word < 4; ++word) {
    bytes[word * 4u] = static_cast<uint8_t>(words[word] & 0xFFu);
    bytes[word * 4u + 1u] = static_cast<uint8_t>((words[word] >> 8u) & 0xFFu);
    bytes[word * 4u + 2u] = static_cast<uint8_t>((words[word] >> 16u) & 0xFFu);
    bytes[word * 4u + 3u] = static_cast<uint8_t>((words[word] >> 24u) & 0xFFu);
  }
}

void incrementGcmCounter(uint8_t counter[16]) {
  for (int8_t index = 15; index >= 12; --index) {
    ++counter[index];
    if (counter[index] != 0)
      break;
  }
}

void storeGcmLengthBlock(uint8_t block[16], uint64_t aadLength,
                         uint64_t cipherLength) {
  const uint64_t aadBits = aadLength * 8u;
  const uint64_t cipherBits = cipherLength * 8u;
  for (uint8_t index = 0; index < 8; ++index) {
    block[index] = static_cast<uint8_t>(aadBits >> (56u - index * 8u));
    block[index + 8u] = static_cast<uint8_t>(cipherBits >> (56u - index * 8u));
  }
}

void prepareGhashInput(AesGcm128Context &context, const uint8_t *data,
                       size_t length) {
  uint8_t block[16] = {};
  if (data != nullptr) {
    for (size_t index = 0; index < length && index < sizeof(block); ++index)
      block[index] = data[index];
  }

  for (uint8_t index = 0; index < sizeof(block); ++index)
    block[index] ^= context.ghash[index];
  loadWordsFromBytes(context.workInput, block);
  secureZeroArray(block);
}

void finishAesGcm(AesGcm128Context &context, bool success) {
  Crypto::clearAesCallback();
  context.aes.busy = false;
  context.busy = false;
  context.step = success ? AesGcm128Context::Step::Complete
                         : AesGcm128Context::Step::Error;
  context.aad = nullptr;
  context.aadLength = 0;
  context.aadOffset = 0;
  context.input = nullptr;
  context.output = nullptr;
  context.length = 0;
  context.payloadOffset = 0;
  context.tagOut = nullptr;
  context.tagIn = nullptr;
  secureZeroArray(context.hashKey);
  secureZeroArray(context.workInput);
  secureZeroArray(context.workOutput);
  secureZeroArray(context.counter);
  secureZeroArray(context.j0);
  secureZeroArray(context.ghash);

  if (context.callback != nullptr)
    context.callback(success, context, context.callbackContext);
}

bool submitAesGcmEcb(AesGcm128Context &context, AesGcm128Context::Step step,
                     void (*callback)(aes::EventMask, AesEcb128Context &,
                                      void *),
                     const uint32_t input[4]) {
  context.step = step;
  if (!aesEcb128SetEncryptKey(context.aes, context.key) ||
      !aesEcb128SetCallback(context.aes, callback, &context)) {
    return false;
  }
  return aesEcb128CryptAsync(context.aes, input, context.workOutput);
}

bool submitAesGcmGhash(AesGcm128Context &context, AesGcm128Context::Step step,
                       void (*callback)(aes::EventMask, void *)) {
  context.step = step;
  if (!Crypto::registerAesCallback(callback, &context))
    return false;
  return Crypto::galoisMultiplyAsync(context.hashKey, context.workInput,
                                     context.workOutput);
}

bool advanceAesGcm(AesGcm128Context &context);

void aesGcmGhashCallback(aes::EventMask events, void *user) {
  auto *context = static_cast<AesGcm128Context *>(user);
  if (context == nullptr || !context->busy)
    return;
  if ((events & aes::EventGaloisComplete) == 0u) {
    finishAesGcm(*context, false);
    return;
  }

  storeBytesFromWords(context->ghash, context->workOutput);
  if (context->step == AesGcm128Context::Step::PayloadGhash)
    context->payloadOffset += ((context->length - context->payloadOffset) > 16u)
                                  ? 16u
                                  : (context->length - context->payloadOffset);
  else if (context->step == AesGcm128Context::Step::Aad)
    context->aadOffset += ((context->aadLength - context->aadOffset) > 16u)
                              ? 16u
                              : (context->aadLength - context->aadOffset);

  if (!advanceAesGcm(*context))
    finishAesGcm(*context, false);
}

void aesGcmEcbCallback(aes::EventMask events, AesEcb128Context &aesContext,
                       void *user) {
  (void)aesContext;
  auto *context = static_cast<AesGcm128Context *>(user);
  if (context == nullptr || !context->busy)
    return;
  if ((events & aes::EventComplete) == 0u) {
    finishAesGcm(*context, false);
    return;
  }

  if (context->step == AesGcm128Context::Step::HashSubkey) {
    for (uint8_t index = 0; index < 4; ++index)
      context->hashKey[index] = context->workOutput[index];
    if (!advanceAesGcm(*context))
      finishAesGcm(*context, false);
    return;
  }

  uint8_t stream[16] = {};
  storeBytesFromWords(stream, context->workOutput);

  if (context->step == AesGcm128Context::Step::PayloadKeystream) {
    const size_t remaining = context->length - context->payloadOffset;
    const size_t chunk =
        remaining > sizeof(stream) ? sizeof(stream) : remaining;
    if (!context->encrypt) {
      prepareGhashInput(*context, context->input + context->payloadOffset,
                        chunk);
    }
    for (size_t index = 0; index < chunk; ++index) {
      const uint8_t in = context->input[context->payloadOffset + index];
      context->output[context->payloadOffset + index] = in ^ stream[index];
    }

    if (context->encrypt) {
      prepareGhashInput(*context, context->output + context->payloadOffset,
                        chunk);
    }
    secureZeroArray(stream);
    if (!submitAesGcmGhash(*context, AesGcm128Context::Step::PayloadGhash,
                           aesGcmGhashCallback)) {
      finishAesGcm(*context, false);
    }
    return;
  }

  if (context->step == AesGcm128Context::Step::TagMask) {
    uint8_t computedTag[16] = {};
    for (uint8_t index = 0; index < sizeof(computedTag); ++index)
      computedTag[index] = context->ghash[index] ^ stream[index];

    bool success = true;
    if (context->encrypt) {
      for (uint8_t index = 0; index < sizeof(computedTag); ++index)
        context->tagOut[index] = computedTag[index];
    } else {
      uint8_t diff = 0;
      for (uint8_t index = 0; index < sizeof(computedTag); ++index)
        diff |= computedTag[index] ^ context->tagIn[index];
      success = diff == 0;
      if (!success && context->output != nullptr)
        secureZero(context->output, context->length);
    }

    secureZeroArray(computedTag);
    secureZeroArray(stream);
    finishAesGcm(*context, success);
    return;
  }

  secureZeroArray(stream);
  finishAesGcm(*context, false);
}

bool advanceAesGcm(AesGcm128Context &context) {
  if (context.aadOffset < context.aadLength) {
    const size_t remaining = context.aadLength - context.aadOffset;
    const size_t chunk = remaining > 16u ? 16u : remaining;
    prepareGhashInput(context, context.aad + context.aadOffset, chunk);
    return submitAesGcmGhash(context, AesGcm128Context::Step::Aad,
                             aesGcmGhashCallback);
  }

  if (context.payloadOffset < context.length) {
    incrementGcmCounter(context.counter);
    loadWordsFromBytes(context.workInput, context.counter);
    return submitAesGcmEcb(context, AesGcm128Context::Step::PayloadKeystream,
                           aesGcmEcbCallback, context.workInput);
  }

  if (context.step != AesGcm128Context::Step::LengthBlock &&
      context.step != AesGcm128Context::Step::TagMask) {
    uint8_t lengthBlock[16] = {};
    storeGcmLengthBlock(lengthBlock, context.aadLength, context.length);
    prepareGhashInput(context, lengthBlock, sizeof(lengthBlock));
    secureZeroArray(lengthBlock);
    return submitAesGcmGhash(context, AesGcm128Context::Step::LengthBlock,
                             aesGcmGhashCallback);
  }

  loadWordsFromBytes(context.workInput, context.j0);
  return submitAesGcmEcb(context, AesGcm128Context::Step::TagMask,
                         aesGcmEcbCallback, context.workInput);
}

void clearEntropyRequest(EntropyContext &context) {
  context.buffer = nullptr;
  context.requestedLength = 0;
  context.producedLength = 0;
  context.busy = false;
}

void finishEntropy(EntropyContext &context, bool success) {
  context.busy = false;
  trng::end();
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

  if (!Crypto::randomWordAsync(false))
    finishEntropy(*entropyContext, false);
}

void randomEntropyCallback(bool success, EntropyContext &entropy, void *context) {
  auto *randomContext = static_cast<RandomContext *>(context);
  if (randomContext == nullptr || !randomContext->busy)
    return;

  randomContext->busy = false;
  randomContext->readOffset = 0;
  randomContext->availableLength = success ? entropy.producedLength : 0;
  if (!success)
    secureZeroArray(randomContext->pool);
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

void aesGcm128Init(AesGcm128Context &context) {
  aesEcb128Init(context.aes);
  clearAesKey(context.key);
  secureZeroArray(context.hashKey);
  secureZeroArray(context.workInput);
  secureZeroArray(context.workOutput);
  secureZeroArray(context.counter);
  secureZeroArray(context.j0);
  secureZeroArray(context.ghash);
  context.aad = nullptr;
  context.aadLength = 0;
  context.aadOffset = 0;
  context.input = nullptr;
  context.output = nullptr;
  context.length = 0;
  context.payloadOffset = 0;
  context.tagOut = nullptr;
  context.tagIn = nullptr;
  context.encrypt = true;
  context.keyConfigured = false;
  context.busy = false;
  context.step = AesGcm128Context::Step::Idle;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void aesGcm128Free(AesGcm128Context &context) {
  if (context.busy)
    Crypto::clearAesCallback();
  aesGcm128Init(context);
}

bool aesGcm128SetKey(AesGcm128Context &context, const uint8_t key[16]) {
  if (context.busy || key == nullptr)
    return false;

  loadWordsFromBytes(context.key, key);
  context.keyConfigured = true;
  return true;
}

bool aesGcm128SetCallback(AesGcm128Context &context, AesGcm128Callback callback,
                          void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool startAesGcmOperation(AesGcm128Context &context, bool encrypt,
                          const uint8_t nonce[12], const uint8_t *aad,
                          size_t aadLength, const uint8_t *input,
                          uint8_t *output, size_t length, uint8_t *tagOut,
                          const uint8_t *tagIn) {
  if (context.busy || !context.keyConfigured || context.callback == nullptr ||
      nonce == nullptr || (aad == nullptr && aadLength != 0) ||
      (input == nullptr && length != 0) || (output == nullptr && length != 0) ||
      (encrypt && tagOut == nullptr) || (!encrypt && tagIn == nullptr)) {
    return false;
  }

  secureZeroArray(context.hashKey);
  secureZeroArray(context.workInput);
  secureZeroArray(context.workOutput);
  secureZeroArray(context.counter);
  secureZeroArray(context.j0);
  secureZeroArray(context.ghash);
  for (uint8_t index = 0; index < 12; ++index) {
    context.j0[index] = nonce[index];
    context.counter[index] = nonce[index];
  }
  context.j0[15] = 1u;
  context.counter[15] = 1u;
  context.aad = aad;
  context.aadLength = aadLength;
  context.aadOffset = 0;
  context.input = input;
  context.output = output;
  context.length = length;
  context.payloadOffset = 0;
  context.tagOut = tagOut;
  context.tagIn = tagIn;
  context.encrypt = encrypt;
  context.busy = true;
  context.step = AesGcm128Context::Step::HashSubkey;

  const uint32_t zeroBlock[4] = {};
  if (!submitAesGcmEcb(context, AesGcm128Context::Step::HashSubkey,
                       aesGcmEcbCallback, zeroBlock)) {
    finishAesGcm(context, false);
    return false;
  }

  return true;
}

bool aesGcm128EncryptAsync(AesGcm128Context &context, const uint8_t nonce[12],
                           const uint8_t *aad, size_t aadLength,
                           const uint8_t *plaintext, uint8_t *ciphertext,
                           size_t length, uint8_t tag[16]) {
  return startAesGcmOperation(context, true, nonce, aad, aadLength, plaintext,
                              ciphertext, length, tag, nullptr);
}

bool aesGcm128DecryptAsync(AesGcm128Context &context, const uint8_t nonce[12],
                           const uint8_t *aad, size_t aadLength,
                           const uint8_t *ciphertext, uint8_t *plaintext,
                           size_t length, const uint8_t tag[16]) {
  return startAesGcmOperation(context, false, nonce, aad, aadLength, ciphertext,
                              plaintext, length, nullptr, tag);
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
      !Crypto::randomWordAsync(false)) {
    trng::end();
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
    secureZeroArray(context.pool);
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
    : _directRandom(), _directRandomCallback(nullptr),
      _directRandomCallbackContext(nullptr), _directRandomBusy(false),
      _callback(nullptr), _callbackContext(nullptr), _gcmOperation(),
      _gcmCallback(nullptr), _gcmCallbackContext(nullptr), _gcmBusy(false)
#ifdef CRYPTO_HARDWARE_AVAILABLE
      ,
      _ecdhOperation(), _ecdhSharedSecret(nullptr), _ecdhCallback(nullptr),
      _ecdhCallbackContext(nullptr), _ecdhBusy(false),
      _ecdsaSignReductionSetup(), _ecdsaSign(), _ecdsaSignResult(),
      _ecdsaSignature(nullptr), _ecdsaSignCallback(nullptr),
      _ecdsaSignCallbackContext(nullptr), _ecdsaSignStep(EcdsaSignStep::Idle),
      _ecdsaSignBusy(false),
      _ecdsaReductionSetup(), _ecdsaPublicKeyValidation(), _ecdsaVerify(),
      _ecdsaResult(),
      _ecdsaCallback(nullptr), _ecdsaCallbackContext(nullptr),
      _ecdsaStep(EcdsaVerifyStep::Idle), _ecdsaBusy(false)
#endif
{
  randomInit(_random);
  entropyInit(_directRandom);
  aesGcm128Init(_gcmOperation);
}

MbedTlsCryptoProvider::~MbedTlsCryptoProvider() { reset(); }

bool MbedTlsCryptoProvider::beginHandshakeCrypto(
    Crypto::TlsCryptoReadyCallback callback, void *context) {
  if (callback == nullptr || _random.busy)
    return false;

  _callback = callback;
  _callbackContext = context;
  if (randomAvailable(_random) != 0) {
    Crypto::TlsCryptoReadyCallback readyCallback = _callback;
    void *readyContext = _callbackContext;
    _callback = nullptr;
    _callbackContext = nullptr;
    readyCallback(true, readyContext);
    return true;
  }

  if (!randomSetCallback(_random, MbedTlsCryptoProvider::handleRandomReady,
                         this) ||
      !randomPrefetchAsync(_random, RandomContext::PoolSize)) {
    _callback = nullptr;
    _callbackContext = nullptr;
    return false;
  }

  return true;
}

void MbedTlsCryptoProvider::reset() {
  randomFree(_random);
  entropyFree(_directRandom);
  _directRandomCallback = nullptr;
  _directRandomCallbackContext = nullptr;
  _directRandomBusy = false;
  _callback = nullptr;
  _callbackContext = nullptr;
  if (_gcmBusy)
    Crypto::clearAesCallback();
  aesGcm128Free(_gcmOperation);
  _gcmCallback = nullptr;
  _gcmCallbackContext = nullptr;
  _gcmBusy = false;
#ifdef CRYPTO_HARDWARE_AVAILABLE
  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy)
    Crypto::clearPukccCallback();
  clearEcdhWorkspace();
  clearEcdsaSignWorkspace();
  clearEcdsaWorkspace();
  _ecdhOperation = {};
  _ecdhSharedSecret = nullptr;
  _ecdhCallback = nullptr;
  _ecdhCallbackContext = nullptr;
  _ecdhBusy = false;
  _ecdsaSignReductionSetup = {};
  _ecdsaSign = {};
  _ecdsaSignResult = {};
  _ecdsaSignature = nullptr;
  _ecdsaSignCallback = nullptr;
  _ecdsaSignCallbackContext = nullptr;
  _ecdsaSignStep = EcdsaSignStep::Idle;
  _ecdsaSignBusy = false;
  _ecdsaReductionSetup = {};
  _ecdsaPublicKeyValidation = {};
  _ecdsaVerify = {};
  _ecdsaResult = {};
  _ecdsaCallback = nullptr;
  _ecdsaCallbackContext = nullptr;
  _ecdsaStep = EcdsaVerifyStep::Idle;
  _ecdsaBusy = false;
#endif
}

bool MbedTlsCryptoProvider::ready() const {
  return !_random.busy && randomAvailable(_random) != 0;
}

bool MbedTlsCryptoProvider::generateRandom(uint8_t *buffer, size_t length) {
  return randomRead(_random, buffer, length);
}

bool MbedTlsCryptoProvider::randomBytesAsync(
    uint8_t *buffer, size_t length, Crypto::TlsRandomCallback callback,
    void *context) {
  if (_directRandomBusy || buffer == nullptr || length == 0 ||
      callback == nullptr) {
    return false;
  }

  entropyFree(_directRandom);
  _directRandomCallback = callback;
  _directRandomCallbackContext = context;
  _directRandomBusy = true;

  if (!entropySetCallback(_directRandom,
                          MbedTlsCryptoProvider::handleDirectRandomReady,
                          this) ||
      !entropyRequestAsync(_directRandom, buffer, length)) {
    secureZero(buffer, length);
    _directRandomCallback = nullptr;
    _directRandomCallbackContext = nullptr;
    _directRandomBusy = false;
    entropyFree(_directRandom);
    return false;
  }

  return true;
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
  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || privateScalar == nullptr ||
      peerPublicKey == nullptr || sharedSecret == nullptr ||
      callback == nullptr || peerPublicKey[0] != 0x04u) {
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

bool MbedTlsCryptoProvider::ecdsaP256SignAsync(
    const uint8_t privateKey[32], const uint8_t nonceScalar[32],
    const uint8_t hash[32], uint8_t signature[64],
    Crypto::TlsEcdsaP256SignCallback callback, void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)privateKey;
  (void)nonceScalar;
  (void)hash;
  (void)signature;
  (void)callback;
  (void)context;
  return false;
#else
  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || privateKey == nullptr ||
      nonceScalar == nullptr || hash == nullptr || signature == nullptr ||
      callback == nullptr) {
    return false;
  }

  clearEcdsaSignWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignModulusOffset, EcdsaSignModulusStorageLength, P256Prime,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignConstantOffset, P256Length + 12u, P256Prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset, P256CoordinateStorageLength * 3u,
          P256Prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset, P256CoordinateStorageLength, P256Gx,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset + P256CoordinateStorageLength,
          P256CoordinateStorageLength, P256Gy, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset + P256CoordinateStorageLength * 2u,
          P256CoordinateStorageLength, ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignCurveAOffset, P256Length + 4u, P256A, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignPrivateKeyOffset, P256Length + 4u, privateKey,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignScalarOffset, P256Length + 4u, nonceScalar, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignOrderOffset, P256Length + 4u, P256Order, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignHashOffset, P256Length + 4u, hash, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignWorkspaceOffset, EcdsaSignWorkspaceLength, P256Prime, 0u)) {
    clearEcdsaSignWorkspace();
    return false;
  }

  _ecdsaSign = {};
  _ecdsaSignReductionSetup = {};
  _ecdsaSignReductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdsaSignModulusOffset);
  _ecdsaSignReductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaSignConstantOffset);
  _ecdsaSignReductionSetup.modulusLength = P256Length;
  _ecdsaSignReductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdsaSignWorkspaceOffset);
  _ecdsaSignReductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdsaSignWorkspaceOffset + P256Length * 2u + 4u));
  _ecdsaSign.basePoint = pukcc::cryptoRamNearPointer(EcdsaSignBasePointOffset);
  _ecdsaSign.order = pukcc::cryptoRamNearPointer(EcdsaSignOrderOffset);
  _ecdsaSign.modulus = pukcc::cryptoRamNearPointer(EcdsaSignModulusOffset);
  _ecdsaSign.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaSignConstantOffset);
  _ecdsaSign.privateKey =
      pukcc::cryptoRamNearPointer(EcdsaSignPrivateKeyOffset);
  _ecdsaSign.scalarNumber =
      pukcc::cryptoRamNearPointer(EcdsaSignScalarOffset);
  _ecdsaSign.curveA = pukcc::cryptoRamNearPointer(EcdsaSignCurveAOffset);
  _ecdsaSign.hash = pukcc::cryptoRamNearPointer(EcdsaSignHashOffset);
  _ecdsaSign.workspace = pukcc::cryptoRamNearPointer(EcdsaSignWorkspaceOffset);
  _ecdsaSign.modulusLength = P256Length;
  _ecdsaSign.scalarLength = P256Length;

  if (!Crypto::registerPukccCallback(
          MbedTlsCryptoProvider::handleEcdsaSignService, this)) {
    clearEcdsaSignWorkspace();
    return false;
  }

  _ecdsaSignResult = {};
  _ecdsaSignature = signature;
  _ecdsaSignCallback = callback;
  _ecdsaSignCallbackContext = context;
  _ecdsaSignStep = EcdsaSignStep::ReductionSetup;
  _ecdsaSignBusy = true;
  if (!submitEcdsaSignStep()) {
    finishEcdsaSign(false);
    return false;
  }

  return true;
#endif
}

bool MbedTlsCryptoProvider::ecdsaP256VerifyAsync(
    const uint8_t publicKey[65], const uint8_t hash[32],
    const uint8_t signature[64], Crypto::TlsEcdsaP256VerifyCallback callback,
    void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)publicKey;
  (void)hash;
  (void)signature;
  (void)callback;
  (void)context;
  return false;
#else
  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || publicKey == nullptr ||
      hash == nullptr || signature == nullptr || callback == nullptr ||
      publicKey[0] != 0x04u) {
    return false;
  }

  clearEcdsaWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(EcdsaModulusOffset,
                                                  EcdsaModulusStorageLength,
                                                  P256Prime, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaConstantOffset, P256Length + 12u, P256Prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaOrderOffset, P256Length + 12u, P256Order, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset, P256Length + 4u, signature, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset + P256Length + 4u, P256Length + 4u,
          signature + P256Length, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaHashOffset, P256Length + 4u, hash, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset, P256CoordinateStorageLength * 3u, P256Prime,
          0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(EcdsaBasePointOffset,
                                                  P256CoordinateStorageLength,
                                                  P256Gx, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset + P256CoordinateStorageLength,
          P256CoordinateStorageLength, P256Gy, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset + P256CoordinateStorageLength * 2u,
          P256CoordinateStorageLength, ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset, P256CoordinateStorageLength * 3u, P256Prime,
          0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(EcdsaPublicKeyOffset,
                                                  P256CoordinateStorageLength,
                                                  publicKey + 1u, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset + P256CoordinateStorageLength,
          P256CoordinateStorageLength, publicKey + 1u + P256Length,
          P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset + P256CoordinateStorageLength * 2u,
          P256CoordinateStorageLength, ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaCurveAOffset, P256Length + 4u, P256A, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaCurveBOffset, P256Length + 4u, P256B, P256Length) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaWorkspaceOffset, EcdsaWorkspaceLength, P256Prime, 0u)) {
    clearEcdsaWorkspace();
    return false;
  }

  _ecdsaReductionSetup = {};
  _ecdsaReductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaReductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaReductionSetup.modulusLength = P256Length;
  _ecdsaReductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdsaWorkspaceOffset);
  _ecdsaReductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdsaWorkspaceOffset + P256Length * 2u + 4u));
  _ecdsaPublicKeyValidation = {};
  _ecdsaPublicKeyValidation.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaPublicKeyValidation.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaPublicKeyValidation.modulusLength = P256Length;
  _ecdsaPublicKeyValidation.curveA =
      pukcc::cryptoRamNearPointer(EcdsaCurveAOffset);
  _ecdsaPublicKeyValidation.curveB =
      pukcc::cryptoRamNearPointer(EcdsaCurveBOffset);
  _ecdsaPublicKeyValidation.point =
      pukcc::cryptoRamNearPointer(EcdsaPublicKeyOffset);
  _ecdsaPublicKeyValidation.workspace =
      pukcc::cryptoRamNearPointer(EcdsaWorkspaceOffset);
  _ecdsaVerify = {};
  _ecdsaVerify.basePoint = pukcc::cryptoRamNearPointer(EcdsaBasePointOffset);
  _ecdsaVerify.order = pukcc::cryptoRamNearPointer(EcdsaOrderOffset);
  _ecdsaVerify.modulus = pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaVerify.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaVerify.publicKey = pukcc::cryptoRamNearPointer(EcdsaPublicKeyOffset);
  _ecdsaVerify.signature = pukcc::cryptoRamNearPointer(EcdsaSignatureOffset);
  _ecdsaVerify.curveA = pukcc::cryptoRamNearPointer(EcdsaCurveAOffset);
  _ecdsaVerify.hash = pukcc::cryptoRamNearPointer(EcdsaHashOffset);
  _ecdsaVerify.workspace = pukcc::cryptoRamNearPointer(EcdsaWorkspaceOffset);
  _ecdsaVerify.modulusLength = P256Length;
  _ecdsaVerify.scalarLength = P256Length;

  if (!Crypto::registerPukccCallback(MbedTlsCryptoProvider::handleEcdsaService,
                                     this)) {
    clearEcdsaWorkspace();
    return false;
  }

  _ecdsaResult = {};
  _ecdsaCallback = callback;
  _ecdsaCallbackContext = context;
  _ecdsaStep = EcdsaVerifyStep::ReductionSetup;
  _ecdsaBusy = true;
  if (!submitEcdsaStep()) {
    finishEcdsa(false);
    return false;
  }

  return true;
#endif
}

bool MbedTlsCryptoProvider::aesGcm128EncryptAsync(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *plaintext, uint8_t *ciphertext,
    size_t length, uint8_t tag[16], Crypto::TlsAesGcm128Callback callback,
    void *context) {
  if (_gcmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesGcm128SetKey(_gcmOperation, key) ||
      !Crypto::MbedTlsPort::aesGcm128SetCallback(
          _gcmOperation, MbedTlsCryptoProvider::handleGcmComplete, this)) {
    return false;
  }

  _gcmCallback = callback;
  _gcmCallbackContext = context;
  _gcmBusy = true;
  if (!Crypto::MbedTlsPort::aesGcm128EncryptAsync(_gcmOperation, nonce, aad,
                                                  aadLength, plaintext,
                                                  ciphertext, length, tag)) {
    finishGcm(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::aesGcm128DecryptAsync(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *ciphertext, uint8_t *plaintext,
    size_t length, const uint8_t tag[16], Crypto::TlsAesGcm128Callback callback,
    void *context) {
  if (_gcmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesGcm128SetKey(_gcmOperation, key) ||
      !Crypto::MbedTlsPort::aesGcm128SetCallback(
          _gcmOperation, MbedTlsCryptoProvider::handleGcmComplete, this)) {
    return false;
  }

  _gcmCallback = callback;
  _gcmCallbackContext = context;
  _gcmBusy = true;
  if (!Crypto::MbedTlsPort::aesGcm128DecryptAsync(_gcmOperation, nonce, aad,
                                                  aadLength, ciphertext,
                                                  plaintext, length, tag)) {
    finishGcm(false);
    return false;
  }

  return true;
}

void MbedTlsCryptoProvider::handleRandomReady(bool success,
                                              RandomContext &context,
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

void MbedTlsCryptoProvider::handleDirectRandomReady(bool success,
                                                    EntropyContext &context,
                                                    void *user) {
  (void)context;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr)
    return;

  provider->finishDirectRandom(success);
}

void MbedTlsCryptoProvider::finishDirectRandom(bool success) {
  Crypto::TlsRandomCallback callback = _directRandomCallback;
  void *callbackContext = _directRandomCallbackContext;

  if (!success && _directRandom.buffer != nullptr &&
      _directRandom.requestedLength != 0) {
    secureZero(_directRandom.buffer, _directRandom.requestedLength);
  }

  _directRandomCallback = nullptr;
  _directRandomCallbackContext = nullptr;
  _directRandomBusy = false;
  entropyFree(_directRandom);

  if (callback != nullptr)
    callback(success, callbackContext);
}

void MbedTlsCryptoProvider::handleGcmComplete(bool success,
                                              AesGcm128Context &operation,
                                              void *user) {
  (void)operation;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr)
    return;

  provider->finishGcm(success);
}

void MbedTlsCryptoProvider::finishGcm(bool success) {
  Crypto::TlsAesGcm128Callback callback = _gcmCallback;
  void *callbackContext = _gcmCallbackContext;
  _gcmCallback = nullptr;
  _gcmCallbackContext = nullptr;
  _gcmBusy = false;
  Crypto::MbedTlsPort::aesGcm128Free(_gcmOperation);

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
  Crypto::clearPukccCallback();
  clearEcdhWorkspace();

  if (callback != nullptr)
    callback(success && completed, callbackContext);
}

void MbedTlsCryptoProvider::clearEcdhWorkspace() {
  clearCryptoRamRange(EcdhModulusOffset, EcdhWorkspaceEnd - EcdhModulusOffset);
}

void MbedTlsCryptoProvider::handleEcdsaSignService(pukcc::EventMask events,
                                                   uint8_t service,
                                                   uint16_t status,
                                                   void *user) {
  (void)service;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr || !provider->_ecdsaSignBusy)
    return;

  if ((events & pukcc::EventComplete) == 0 || status != pukcc::StatusOk) {
    provider->finishEcdsaSign(false);
    return;
  }

  switch (provider->_ecdsaSignStep) {
  case EcdsaSignStep::ReductionSetup:
    provider->_ecdsaSignStep = EcdsaSignStep::Generate;
    break;
  case EcdsaSignStep::Generate:
    provider->finishEcdsaSign(true);
    return;
  case EcdsaSignStep::Idle:
  case EcdsaSignStep::Complete:
  case EcdsaSignStep::Error:
    provider->finishEcdsaSign(false);
    return;
  }

  if (!provider->submitEcdsaSignStep())
    provider->finishEcdsaSign(false);
}

bool MbedTlsCryptoProvider::submitEcdsaSignStep() {
  switch (_ecdsaSignStep) {
  case EcdsaSignStep::ReductionSetup:
    return Crypto::PukccEcc::startReductionSetupAsync(_ecdsaSignReductionSetup,
                                                      _ecdsaSignResult);
  case EcdsaSignStep::Generate:
    return Crypto::PukccEcc::startEcdsaGenerateAsync(_ecdsaSign,
                                                     _ecdsaSignResult);
  case EcdsaSignStep::Idle:
  case EcdsaSignStep::Complete:
  case EcdsaSignStep::Error:
    return false;
  }

  return false;
}

void MbedTlsCryptoProvider::finishEcdsaSign(bool success) {
  bool completed = false;
  if (success && _ecdsaSignature != nullptr) {
    completed =
        copyCryptoRamToBigEndian(EcdsaSignBasePointOffset, _ecdsaSignature,
                                 P256Length) &&
        copyCryptoRamToBigEndian(
            static_cast<uint16_t>(EcdsaSignBasePointOffset +
                                  P256CoordinateStorageLength),
            _ecdsaSignature + P256Length, P256Length);
  }

  Crypto::TlsEcdsaP256SignCallback callback = _ecdsaSignCallback;
  void *callbackContext = _ecdsaSignCallbackContext;
  _ecdsaSignReductionSetup = {};
  _ecdsaSign = {};
  _ecdsaSignResult = {};
  _ecdsaSignature = nullptr;
  _ecdsaSignCallback = nullptr;
  _ecdsaSignCallbackContext = nullptr;
  _ecdsaSignStep = success ? EcdsaSignStep::Complete : EcdsaSignStep::Error;
  _ecdsaSignBusy = false;
  Crypto::clearPukccCallback();
  clearEcdsaSignWorkspace();

  if (callback != nullptr)
    callback(success && completed, callbackContext);
}

void MbedTlsCryptoProvider::clearEcdsaSignWorkspace() {
  clearCryptoRamRange(EcdsaSignModulusOffset,
                      EcdsaSignWorkspaceEnd - EcdsaSignModulusOffset);
}

void MbedTlsCryptoProvider::handleEcdsaService(pukcc::EventMask events,
                                               uint8_t service, uint16_t status,
                                               void *user) {
  (void)service;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr || !provider->_ecdsaBusy)
    return;

  if ((events & pukcc::EventComplete) == 0 || status != pukcc::StatusOk) {
    provider->finishEcdsa(false);
    return;
  }

  switch (provider->_ecdsaStep) {
  case EcdsaVerifyStep::ReductionSetup:
    provider->_ecdsaStep = EcdsaVerifyStep::PublicKeyValidation;
    break;
  case EcdsaVerifyStep::PublicKeyValidation:
    provider->_ecdsaStep = EcdsaVerifyStep::Verify;
    break;
  case EcdsaVerifyStep::Verify:
    provider->finishEcdsa(true);
    return;
  case EcdsaVerifyStep::Idle:
  case EcdsaVerifyStep::Complete:
  case EcdsaVerifyStep::Error:
    provider->finishEcdsa(false);
    return;
  }

  if (!provider->submitEcdsaStep())
    provider->finishEcdsa(false);
}

bool MbedTlsCryptoProvider::submitEcdsaStep() {
  switch (_ecdsaStep) {
  case EcdsaVerifyStep::ReductionSetup:
    return Crypto::PukccEcc::startReductionSetupAsync(_ecdsaReductionSetup,
                                                      _ecdsaResult);
  case EcdsaVerifyStep::PublicKeyValidation:
    return Crypto::PukccEcc::startPointIsOnCurveAsync(_ecdsaPublicKeyValidation,
                                                      _ecdsaResult);
  case EcdsaVerifyStep::Verify:
    return Crypto::PukccEcc::startEcdsaVerifyAsync(_ecdsaVerify, _ecdsaResult);
  case EcdsaVerifyStep::Idle:
  case EcdsaVerifyStep::Complete:
  case EcdsaVerifyStep::Error:
    return false;
  }

  return false;
}

void MbedTlsCryptoProvider::finishEcdsa(bool success) {
  Crypto::TlsEcdsaP256VerifyCallback callback = _ecdsaCallback;
  void *callbackContext = _ecdsaCallbackContext;
  _ecdsaReductionSetup = {};
  _ecdsaPublicKeyValidation = {};
  _ecdsaVerify = {};
  _ecdsaResult = {};
  _ecdsaCallback = nullptr;
  _ecdsaCallbackContext = nullptr;
  _ecdsaStep = success ? EcdsaVerifyStep::Complete : EcdsaVerifyStep::Error;
  _ecdsaBusy = false;
  Crypto::clearPukccCallback();
  clearEcdsaWorkspace();

  if (callback != nullptr)
    callback(success, callbackContext);
}

void MbedTlsCryptoProvider::clearEcdsaWorkspace() {
  clearCryptoRamRange(EcdsaModulusOffset,
                      EcdsaWorkspaceEnd - EcdsaModulusOffset);
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

#include "MbedTlsPort.h"

#include <mbedtls/platform_util.h>

#include <string.h>

namespace Crypto::MbedTlsPort {

namespace {
#ifdef CRYPTO_HARDWARE_AVAILABLE
constexpr uint16_t P256Length = 32u;
constexpr uint16_t P384Length = 48u;
constexpr uint16_t MaxEccLength = P384Length;
constexpr uint16_t MaxEccCoordinateStorageLength = MaxEccLength + 4u;
constexpr uint16_t EcdhModulusOffset = 0u;
constexpr uint16_t EcdhModulusStorageLength = MaxEccLength + 4u;
constexpr uint16_t EcdhConstantOffset =
    EcdhModulusOffset + EcdhModulusStorageLength;
constexpr uint16_t EcdhCurveAOffset = EcdhConstantOffset + MaxEccLength + 12u;
constexpr uint16_t EcdhCurveBOffset = EcdhCurveAOffset + MaxEccLength + 4u;
constexpr uint16_t EcdhPointOffset = EcdhCurveBOffset + MaxEccLength + 4u;
constexpr uint16_t EcdhPointLength = MaxEccLength * 3u + 20u;
constexpr uint16_t EcdhScalarOffset = EcdhPointOffset + EcdhPointLength;
constexpr uint16_t EcdhWorkspaceOffset = EcdhScalarOffset + MaxEccLength + 4u;
constexpr uint16_t EcdhWorkspaceLength = MaxEccLength * 6u;
constexpr uint16_t EcdhWorkspaceEnd = EcdhWorkspaceOffset + EcdhWorkspaceLength;
constexpr uint16_t EcdsaModulusOffset = 0u;
constexpr uint16_t EcdsaModulusStorageLength = MaxEccLength + 4u;
constexpr uint16_t EcdsaConstantOffset =
    EcdsaModulusOffset + EcdsaModulusStorageLength;
constexpr uint16_t EcdsaOrderOffset = EcdsaConstantOffset + MaxEccLength + 12u;
constexpr uint16_t EcdsaSignatureOffset = EcdsaOrderOffset + MaxEccLength + 12u;
constexpr uint16_t EcdsaHashOffset =
    EcdsaSignatureOffset + MaxEccLength * 2u + 8u;
constexpr uint16_t EcdsaBasePointOffset = EcdsaHashOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaPublicKeyOffset =
    EcdsaBasePointOffset + MaxEccCoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveAOffset =
    EcdsaPublicKeyOffset + MaxEccCoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveBOffset = EcdsaCurveAOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaWorkspaceOffset = EcdsaCurveBOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaWorkspaceLength = MaxEccLength * 8u + 44u;
constexpr uint16_t EcdsaWorkspaceEnd =
    EcdsaWorkspaceOffset + EcdsaWorkspaceLength;
constexpr uint16_t EcdsaSignModulusOffset = 0u;
constexpr uint16_t EcdsaSignModulusStorageLength = MaxEccLength + 4u;
constexpr uint16_t EcdsaSignConstantOffset =
    EcdsaSignModulusOffset + EcdsaSignModulusStorageLength;
constexpr uint16_t EcdsaSignBasePointOffset =
    EcdsaSignConstantOffset + MaxEccLength + 12u;
constexpr uint16_t EcdsaSignCurveAOffset =
    EcdsaSignBasePointOffset + MaxEccCoordinateStorageLength * 3u;
constexpr uint16_t EcdsaSignPrivateKeyOffset =
    EcdsaSignCurveAOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaSignScalarOffset =
    EcdsaSignPrivateKeyOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaSignOrderOffset =
    EcdsaSignScalarOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaSignHashOffset =
    EcdsaSignOrderOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaSignWorkspaceOffset =
    EcdsaSignHashOffset + MaxEccLength + 4u;
constexpr uint16_t EcdsaSignWorkspaceLength = MaxEccLength * 8u + 44u;
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
const uint8_t P384Prime[P384Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
const uint8_t P384A[P384Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFCu};
const uint8_t P384B[P384Length] = {
    0xB3u, 0x31u, 0x2Fu, 0xA7u, 0xE2u, 0x3Eu, 0xE7u, 0xE4u,
    0x98u, 0x8Eu, 0x05u, 0x6Bu, 0xE3u, 0xF8u, 0x2Du, 0x19u,
    0x18u, 0x1Du, 0x9Cu, 0x6Eu, 0xFEu, 0x81u, 0x41u, 0x12u,
    0x03u, 0x14u, 0x08u, 0x8Fu, 0x50u, 0x13u, 0x87u, 0x5Au,
    0xC6u, 0x56u, 0x39u, 0x8Du, 0x8Au, 0x2Eu, 0xD1u, 0x9Du,
    0x2Au, 0x85u, 0xC8u, 0xEDu, 0xD3u, 0xECu, 0x2Au, 0xEFu};
const uint8_t P384Order[P384Length] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xC7u, 0x63u, 0x4Du, 0x81u, 0xF4u, 0x37u, 0x2Du, 0xDFu,
    0x58u, 0x1Au, 0x0Du, 0xB2u, 0x48u, 0xB0u, 0xA7u, 0x7Au,
    0xECu, 0xECu, 0x19u, 0x6Au, 0xCCu, 0xC5u, 0x29u, 0x73u};
const uint8_t P384Gx[P384Length] = {
    0xAAu, 0x87u, 0xCAu, 0x22u, 0xBEu, 0x8Bu, 0x05u, 0x37u,
    0x8Eu, 0xB1u, 0xC7u, 0x1Eu, 0xF3u, 0x20u, 0xADu, 0x74u,
    0x6Eu, 0x1Du, 0x3Bu, 0x62u, 0x8Bu, 0xA7u, 0x9Bu, 0x98u,
    0x59u, 0xF7u, 0x41u, 0xE0u, 0x82u, 0x54u, 0x2Au, 0x38u,
    0x55u, 0x02u, 0xF2u, 0x5Du, 0xBFu, 0x55u, 0x29u, 0x6Cu,
    0x3Au, 0x54u, 0x5Eu, 0x38u, 0x72u, 0x76u, 0x0Au, 0xB7u};
const uint8_t P384Gy[P384Length] = {
    0x36u, 0x17u, 0xDEu, 0x4Au, 0x96u, 0x26u, 0x2Cu, 0x6Fu,
    0x5Du, 0x9Eu, 0x98u, 0xBFu, 0x92u, 0x92u, 0xDCu, 0x29u,
    0xF8u, 0xF4u, 0x1Du, 0xBDu, 0x28u, 0x9Au, 0x14u, 0x7Cu,
    0xE9u, 0xDAu, 0x31u, 0x13u, 0xB5u, 0xF0u, 0xB8u, 0xC0u,
    0x0Au, 0x60u, 0xB1u, 0xCEu, 0x1Du, 0x7Eu, 0x81u, 0x9Du,
    0x7Au, 0x43u, 0x1Du, 0x7Cu, 0x90u, 0xEAu, 0x0Eu, 0x5Fu};
const uint8_t ProjectiveOne[1] = {0x01u};

constexpr EccCurveParams P256Curve = {
    P256Length, P256Prime, P256A, P256B, P256Order, P256Gx, P256Gy};
constexpr EccCurveParams P384Curve = {
    P384Length, P384Prime, P384A, P384B, P384Order, P384Gx, P384Gy};

uint16_t coordinateStorageLength(const EccCurveParams &curve) {
  return static_cast<uint16_t>(curve.length + 4u);
}

uint16_t publicKeyLength(const EccCurveParams &curve) {
  return static_cast<uint16_t>(curve.length * 2u + 1u);
}

uint16_t signatureLength(const EccCurveParams &curve) {
  return static_cast<uint16_t>(curve.length * 2u);
}

const EccCurveParams *
curveForKeyExchange(Crypto::TlsKeyExchangeAlgorithm algorithm) {
  switch (algorithm) {
  case Crypto::TlsKeyExchangeAlgorithm::EcdhP256:
    return &P256Curve;
  case Crypto::TlsKeyExchangeAlgorithm::EcdhP384:
    return &P384Curve;
  case Crypto::TlsKeyExchangeAlgorithm::X25519:
  case Crypto::TlsKeyExchangeAlgorithm::EcdhP521:
    return nullptr;
  }
  return nullptr;
}

const EccCurveParams *
curveForSignature(Crypto::TlsSignatureAlgorithm algorithm) {
  switch (algorithm) {
  case Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256:
    return &P256Curve;
  case Crypto::TlsSignatureAlgorithm::EcdsaP384Sha384:
    return &P384Curve;
  case Crypto::TlsSignatureAlgorithm::EcdsaP521Sha512:
  case Crypto::TlsSignatureAlgorithm::Ed25519:
  case Crypto::TlsSignatureAlgorithm::RsaPssRsaeSha256:
  case Crypto::TlsSignatureAlgorithm::RsaPssRsaeSha384:
    return nullptr;
  }
  return nullptr;
}

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

void copyAesKey(uint32_t destination[8], const uint32_t *source,
                uint8_t wordCount) {
  for (uint8_t index = 0; index < wordCount && index < 8; ++index)
    destination[index] = source[index];
}

void clearAesKey(uint32_t key[8]) { secureZero(key, sizeof(uint32_t) * 8); }

void aesContextCallback(aes::EventMask events, void *context) {
  auto *aesContext = static_cast<AesEcb128Context *>(context);
  if (aesContext == nullptr)
    return;

  aesContext->busy = false;
  if (aesContext->callback != nullptr)
    aesContext->callback(events, *aesContext, aesContext->callbackContext);
}

void loadWordsFromBytes(uint32_t *words, const uint8_t *bytes,
                        uint8_t wordCount) {
  for (uint8_t word = 0; word < wordCount; ++word) {
    words[word] = static_cast<uint32_t>(bytes[word * 4u]) |
                  (static_cast<uint32_t>(bytes[word * 4u + 1u]) << 8u) |
                  (static_cast<uint32_t>(bytes[word * 4u + 2u]) << 16u) |
                  (static_cast<uint32_t>(bytes[word * 4u + 3u]) << 24u);
  }
}

void loadWordsFromBytes(uint32_t words[4], const uint8_t bytes[16]) {
  loadWordsFromBytes(words, bytes, 4);
}

aes::KeySize keySizeFromWords(uint8_t keyWords) {
  switch (keyWords) {
  case 4:
    return aes::KeySize::Bits128;
  case 6:
    return aes::KeySize::Bits192;
  case 8:
    return aes::KeySize::Bits256;
  default:
    return aes::KeySize::Bits128;
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
  if (!aesEcbSetEncryptKey(context.aes, context.key, context.keyWords) ||
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

bool validCcmTagLength(size_t tagLength) {
  return tagLength == 8u || tagLength == 16u;
}

bool validCcmNonceLength(size_t nonceLength) {
  return nonceLength >= 7u && nonceLength <= 13u;
}

bool ccmLengthFits(size_t length, uint8_t q) {
  if (q >= sizeof(size_t))
    return true;
  return length < (static_cast<size_t>(1u) << (q * 8u));
}

void storeCcmEncodedLength(uint8_t *destination, uint8_t lengthBytes,
                           size_t length) {
  for (uint8_t index = 0; index < lengthBytes; ++index) {
    const uint8_t shift = static_cast<uint8_t>((lengthBytes - 1u - index) * 8u);
    destination[index] = static_cast<uint8_t>(length >> shift);
  }
}

void buildCcmB0(AesCcm128Context &context, const uint8_t *nonce) {
  const uint8_t q = static_cast<uint8_t>(15u - context.nonceLength);
  context.workBlock[0] =
      static_cast<uint8_t>((context.aadLength != 0 ? 0x40u : 0u) |
                           (((context.tagLength - 2u) / 2u) << 3u) |
                           (q - 1u));
  memcpy(&context.workBlock[1], nonce, context.nonceLength);
  storeCcmEncodedLength(&context.workBlock[1u + context.nonceLength], q,
                        context.length);
}

void buildCcmCtr(AesCcm128Context &context, uint32_t counter) {
  const uint8_t q = static_cast<uint8_t>(15u - context.nonceLength);
  context.ctr[0] = static_cast<uint8_t>(q - 1u);
  storeCcmEncodedLength(&context.ctr[1u + context.nonceLength], q, counter);
}

void xorCcmMacInput(AesCcm128Context &context) {
  for (uint8_t index = 0; index < sizeof(context.workBlock); ++index)
    context.workBlock[index] ^= context.mac[index];
  loadWordsFromBytes(context.workInput, context.workBlock);
}

bool prepareCcmAadBlock(AesCcm128Context &context) {
  secureZeroArray(context.workBlock);
  size_t blockOffset = 0;

  if (!context.aadLengthStarted) {
    if (context.aadLength >= 0xFF00u)
      return false;
    context.workBlock[0] = static_cast<uint8_t>(context.aadLength >> 8u);
    context.workBlock[1] = static_cast<uint8_t>(context.aadLength);
    blockOffset = 2u;
    context.aadLengthStarted = true;
  }

  while (blockOffset < sizeof(context.workBlock) &&
         context.aadOffset < context.aadLength) {
    context.workBlock[blockOffset++] = context.aad[context.aadOffset++];
  }

  xorCcmMacInput(context);
  return true;
}

void prepareCcmPayloadMacBlock(AesCcm128Context &context, const uint8_t *data,
                               size_t chunk) {
  secureZeroArray(context.workBlock);
  if (data != nullptr && chunk != 0)
    memcpy(context.workBlock, data, chunk);
  xorCcmMacInput(context);
}

bool submitAesCcmEcb(AesCcm128Context &context, AesCcm128Context::Step step,
                     const uint8_t input[16],
                     void (*callback)(aes::EventMask, AesEcb128Context &,
                                      void *)) {
  context.step = step;
  loadWordsFromBytes(context.workInput, input);
  if (!aesEcbSetEncryptKey(context.aes, context.key, context.keyWords) ||
      !aesEcb128SetCallback(context.aes, callback, &context)) {
    return false;
  }
  return aesEcb128CryptAsync(context.aes, context.workInput,
                             context.workOutput);
}

bool submitAesCcmMac(AesCcm128Context &context);
bool advanceAesCcm(AesCcm128Context &context);

void aesCcmEcbCallback(aes::EventMask events, AesEcb128Context &aesContext,
                       void *user) {
  (void)aesContext;
  auto *context = static_cast<AesCcm128Context *>(user);
  if (context == nullptr || !context->busy)
    return;
  if ((events & aes::EventComplete) == 0u) {
    context->busy = false;
    if (context->callback != nullptr)
      context->callback(false, *context, context->callbackContext);
    return;
  }

  uint8_t block[16] = {};
  storeBytesFromWords(block, context->workOutput);

  if (context->step == AesCcm128Context::Step::MacBlock ||
      context->step == AesCcm128Context::Step::PayloadMac) {
    memcpy(context->mac, block, sizeof(context->mac));
    secureZeroArray(block);
    if (!advanceAesCcm(*context)) {
      context->busy = false;
      if (context->callback != nullptr)
        context->callback(false, *context, context->callbackContext);
    }
    return;
  }

  if (context->step == AesCcm128Context::Step::PayloadCtr) {
    const size_t remaining = context->length - context->payloadOffset;
    const size_t chunk = remaining > sizeof(block) ? sizeof(block) : remaining;
    for (size_t index = 0; index < chunk; ++index) {
      const uint8_t in = context->input[context->payloadOffset + index];
      context->output[context->payloadOffset + index] = in ^ block[index];
    }

    if (context->encrypt) {
      prepareCcmPayloadMacBlock(
          *context, context->input + context->payloadOffset, chunk);
      context->step = AesCcm128Context::Step::PayloadMac;
      if (!submitAesCcmMac(*context)) {
        secureZeroArray(block);
        context->busy = false;
        if (context->callback != nullptr)
          context->callback(false, *context, context->callbackContext);
        return;
      }
    } else {
      prepareCcmPayloadMacBlock(
          *context, context->output + context->payloadOffset, chunk);
      context->step = AesCcm128Context::Step::PayloadMac;
      if (!submitAesCcmMac(*context)) {
        secureZero(context->output, context->length);
        secureZeroArray(block);
        context->busy = false;
        if (context->callback != nullptr)
          context->callback(false, *context, context->callbackContext);
        return;
      }
    }
    secureZeroArray(block);
    return;
  }

  if (context->step == AesCcm128Context::Step::TagMask) {
    uint8_t computedTag[16] = {};
    for (size_t index = 0; index < context->tagLength; ++index)
      computedTag[index] = context->mac[index] ^ block[index];

    bool success = true;
    if (context->encrypt) {
      memcpy(context->tagOut, computedTag, context->tagLength);
    } else {
      uint8_t diff = 0;
      for (size_t index = 0; index < context->tagLength; ++index)
        diff |= computedTag[index] ^ context->tagIn[index];
      success = diff == 0;
      if (!success && context->output != nullptr)
        secureZero(context->output, context->length);
    }

    secureZeroArray(computedTag);
    secureZeroArray(block);
    context->busy = false;
    context->step = success ? AesCcm128Context::Step::Complete
                            : AesCcm128Context::Step::Error;
    if (context->callback != nullptr)
      context->callback(success, *context, context->callbackContext);
    return;
  }

  secureZeroArray(block);
  context->busy = false;
  if (context->callback != nullptr)
    context->callback(false, *context, context->callbackContext);
}

bool submitAesCcmMac(AesCcm128Context &context) {
  if (!aesEcbSetEncryptKey(context.aes, context.key, context.keyWords) ||
      !aesEcb128SetCallback(context.aes, aesCcmEcbCallback, &context)) {
    return false;
  }
  return aesEcb128CryptAsync(context.aes, context.workInput,
                             context.workOutput);
}

bool advanceAesCcm(AesCcm128Context &context) {
  if (context.aadOffset < context.aadLength) {
    if (!prepareCcmAadBlock(context))
      return false;
    context.step = AesCcm128Context::Step::MacBlock;
    return submitAesCcmMac(context);
  }

  if (context.payloadOffset < context.length) {
    const size_t completed = context.payloadOffset;
    if (context.step == AesCcm128Context::Step::PayloadMac)
      context.payloadOffset +=
          ((context.length - context.payloadOffset) > 16u)
              ? 16u
              : (context.length - context.payloadOffset);
    if (context.payloadOffset >= context.length && completed != context.payloadOffset) {
      buildCcmCtr(context, 0u);
      return submitAesCcmEcb(context, AesCcm128Context::Step::TagMask,
                             context.ctr, aesCcmEcbCallback);
    }
    if (completed == context.payloadOffset) {
      buildCcmCtr(context, ++context.counter);
      return submitAesCcmEcb(context, AesCcm128Context::Step::PayloadCtr,
                             context.ctr, aesCcmEcbCallback);
    }
    buildCcmCtr(context, ++context.counter);
    return submitAesCcmEcb(context, AesCcm128Context::Step::PayloadCtr,
                           context.ctr, aesCcmEcbCallback);
  }

  buildCcmCtr(context, 0u);
  return submitAesCcmEcb(context, AesCcm128Context::Step::TagMask,
                         context.ctr, aesCcmEcbCallback);
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

} // namespace

void aesEcb128Init(AesEcb128Context &context) {
  clearAesKey(context.key);
  context.keyWords = 0;
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

bool aesEcbSetEncryptKey(AesEcb128Context &context, const uint32_t *key,
                         uint8_t keyWords) {
  if (key == nullptr || context.busy ||
      (keyWords != 4 && keyWords != 6 && keyWords != 8))
    return false;

  clearAesKey(context.key);
  copyAesKey(context.key, key, keyWords);
  context.keyWords = keyWords;
  context.direction = aes::Direction::Encrypt;
  context.keyConfigured = true;
  return true;
}

bool aesEcb128SetEncryptKey(AesEcb128Context &context, const uint32_t key[4]) {
  return aesEcbSetEncryptKey(context, key, 4);
}

bool aesEcb128SetDecryptKey(AesEcb128Context &context, const uint32_t key[4]) {
  if (key == nullptr || context.busy)
    return false;

  clearAesKey(context.key);
  copyAesKey(context.key, key, 4);
  context.keyWords = 4;
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
  const bool submitted = aes::startEcbAsync(
      context.direction, keySizeFromWords(context.keyWords), context.key, input,
      output);
  if (!submitted) {
    context.busy = false;
    Crypto::clearAesCallback();
  }

  return submitted;
}

void aesGcm128Init(AesGcm128Context &context) {
  aesEcb128Init(context.aes);
  clearAesKey(context.key);
  context.keyWords = 0;
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

bool aesGcmSetKey(AesGcm128Context &context, const uint8_t *key,
                  size_t keyLength) {
  if (context.busy || key == nullptr ||
      (keyLength != 16 && keyLength != 24 && keyLength != 32))
    return false;

  clearAesKey(context.key);
  context.keyWords = static_cast<uint8_t>(keyLength / 4u);
  loadWordsFromBytes(context.key, key, context.keyWords);
  context.keyConfigured = true;
  return true;
}

bool aesGcm128SetKey(AesGcm128Context &context, const uint8_t key[16]) {
  return aesGcmSetKey(context, key, 16);
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

void aesCcm128Init(AesCcm128Context &context) {
  aesEcb128Init(context.aes);
  clearAesKey(context.key);
  context.keyWords = 0;
  secureZeroArray(context.mac);
  secureZeroArray(context.ctr);
  secureZeroArray(context.workBlock);
  secureZeroArray(context.workInput);
  secureZeroArray(context.workOutput);
  context.aad = nullptr;
  context.aadLength = 0;
  context.aadOffset = 0;
  context.aadLengthStarted = false;
  context.input = nullptr;
  context.output = nullptr;
  context.length = 0;
  context.payloadOffset = 0;
  context.tagOut = nullptr;
  context.tagIn = nullptr;
  context.tagLength = 0;
  context.nonceLength = 0;
  context.counter = 0;
  context.encrypt = true;
  context.keyConfigured = false;
  context.busy = false;
  context.step = AesCcm128Context::Step::Idle;
  context.callback = nullptr;
  context.callbackContext = nullptr;
}

void aesCcm128Free(AesCcm128Context &context) {
  if (context.busy)
    Crypto::clearAesCallback();
  aesCcm128Init(context);
}

bool aesCcmSetKey(AesCcm128Context &context, const uint8_t *key,
                  size_t keyLength) {
  if (context.busy || key == nullptr ||
      (keyLength != 16 && keyLength != 24 && keyLength != 32))
    return false;

  clearAesKey(context.key);
  context.keyWords = static_cast<uint8_t>(keyLength / 4u);
  loadWordsFromBytes(context.key, key, context.keyWords);
  context.keyConfigured = true;
  return true;
}

bool aesCcm128SetKey(AesCcm128Context &context, const uint8_t key[16]) {
  return aesCcmSetKey(context, key, 16);
}

bool aesCcm128SetCallback(AesCcm128Context &context, AesCcm128Callback callback,
                          void *callbackContext) {
  if (context.busy)
    return false;

  context.callback = callback;
  context.callbackContext = callbackContext;
  return callback != nullptr;
}

bool startAesCcmOperation(AesCcm128Context &context, bool encrypt,
                          const uint8_t *nonce, size_t nonceLength,
                          const uint8_t *aad, size_t aadLength,
                          const uint8_t *input, uint8_t *output,
                          size_t length, uint8_t *tagOut, const uint8_t *tagIn,
                          size_t tagLength) {
  if (context.busy || !context.keyConfigured || context.callback == nullptr ||
      !validCcmNonceLength(nonceLength) || !validCcmTagLength(tagLength) ||
      nonce == nullptr || (aad == nullptr && aadLength != 0) ||
      (input == nullptr && length != 0) || (output == nullptr && length != 0) ||
      (encrypt && tagOut == nullptr) || (!encrypt && tagIn == nullptr)) {
    return false;
  }

  const uint8_t q = static_cast<uint8_t>(15u - nonceLength);
  if (!ccmLengthFits(length, q))
    return false;

  secureZeroArray(context.mac);
  secureZeroArray(context.ctr);
  secureZeroArray(context.workBlock);
  secureZeroArray(context.workInput);
  secureZeroArray(context.workOutput);
  context.aad = aad;
  context.aadLength = aadLength;
  context.aadOffset = 0;
  context.aadLengthStarted = false;
  context.input = input;
  context.output = output;
  context.length = length;
  context.payloadOffset = 0;
  context.tagOut = tagOut;
  context.tagIn = tagIn;
  context.tagLength = tagLength;
  context.nonceLength = static_cast<uint8_t>(nonceLength);
  context.counter = 0;
  context.encrypt = encrypt;
  context.busy = true;
  context.step = AesCcm128Context::Step::MacBlock;
  memcpy(&context.ctr[1], nonce, nonceLength);
  buildCcmB0(context, nonce);
  xorCcmMacInput(context);

  if (!submitAesCcmMac(context)) {
    context.busy = false;
    return false;
  }

  return true;
}

bool aesCcm128EncryptAsync(AesCcm128Context &context, const uint8_t *nonce,
                           size_t nonceLength, const uint8_t *aad,
                           size_t aadLength, const uint8_t *plaintext,
                           uint8_t *ciphertext, size_t length, uint8_t *tag,
                           size_t tagLength) {
  return startAesCcmOperation(context, true, nonce, nonceLength, aad, aadLength,
                              plaintext, ciphertext, length, tag, nullptr,
                              tagLength);
}

bool aesCcm128DecryptAsync(AesCcm128Context &context, const uint8_t *nonce,
                           size_t nonceLength, const uint8_t *aad,
                           size_t aadLength, const uint8_t *ciphertext,
                           uint8_t *plaintext, size_t length,
                           const uint8_t *tag, size_t tagLength) {
  return startAesCcmOperation(context, false, nonce, nonceLength, aad,
                              aadLength, ciphertext, plaintext, length,
                              nullptr, tag, tagLength);
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

MbedTlsCryptoProvider::MbedTlsCryptoProvider()
    : _directRandom(), _directRandomCallback(nullptr),
      _directRandomCallbackContext(nullptr), _directRandomBusy(false),
      _callback(nullptr), _callbackContext(nullptr), _gcmOperation(),
      _gcmCallback(nullptr), _gcmCallbackContext(nullptr), _gcmBusy(false),
      _ccmOperation(), _ccmCallback(nullptr), _ccmCallbackContext(nullptr),
      _ccmBusy(false)
#ifdef CRYPTO_HARDWARE_AVAILABLE
      ,
      _ecdhOperation(), _ecdhSharedSecret(nullptr), _ecdhPublicKey(nullptr),
      _ecdhCallback(nullptr), _ecdhCallbackContext(nullptr),
      _ecdhCoordinateLength(0), _ecdhBusy(false),
      _ecdsaSignReductionSetup(), _ecdsaSign(), _ecdsaSignResult(),
      _ecdsaSignature(nullptr), _ecdsaSignCallback(nullptr),
      _ecdsaSignCallbackContext(nullptr), _ecdsaSignCoordinateLength(0),
      _ecdsaSignStep(EcdsaSignStep::Idle),
      _ecdsaSignBusy(false),
      _ecdsaReductionSetup(), _ecdsaPublicKeyValidation(), _ecdsaVerify(),
      _ecdsaResult(),
      _ecdsaCallback(nullptr), _ecdsaCallbackContext(nullptr),
      _ecdsaStep(EcdsaVerifyStep::Idle), _ecdsaBusy(false)
#endif
{
  entropyInit(_directRandom);
  aesGcm128Init(_gcmOperation);
  aesCcm128Init(_ccmOperation);
}

MbedTlsCryptoProvider::~MbedTlsCryptoProvider() { reset(); }

bool MbedTlsCryptoProvider::beginHandshakeCrypto(
    Crypto::TlsCryptoReadyCallback callback, void *context) {
  if (callback == nullptr)
    return false;

  callback(true, context);
  return true;
}

void MbedTlsCryptoProvider::reset() {
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
  if (_ccmBusy)
    Crypto::clearAesCallback();
  aesCcm128Free(_ccmOperation);
  _ccmCallback = nullptr;
  _ccmCallbackContext = nullptr;
  _ccmBusy = false;
#ifdef CRYPTO_HARDWARE_AVAILABLE
  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy)
    Crypto::clearPukccCallback();
  clearEcdhWorkspace();
  clearEcdsaSignWorkspace();
  clearEcdsaWorkspace();
  _ecdhOperation = {};
  _ecdhSharedSecret = nullptr;
  _ecdhPublicKey = nullptr;
  _ecdhCallback = nullptr;
  _ecdhCallbackContext = nullptr;
  _ecdhCoordinateLength = 0;
  _ecdhBusy = false;
  _ecdsaSignReductionSetup = {};
  _ecdsaSign = {};
  _ecdsaSignResult = {};
  _ecdsaSignature = nullptr;
  _ecdsaSignCallback = nullptr;
  _ecdsaSignCallbackContext = nullptr;
  _ecdsaSignCoordinateLength = 0;
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
  return true;
}

#if defined(MBEDTLS_TEST_SYNC_COMPAT)
bool MbedTlsCryptoProvider::generateRandom(uint8_t *buffer, size_t length) {
  (void)buffer;
  (void)length;
  return false;
}
#endif

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
  return keyExchangeSharedSecretAsync(Crypto::TlsKeyExchangeAlgorithm::EcdhP256,
                                      privateScalar, 32, peerPublicKey, 65,
                                      sharedSecret, 32, callback, context);
}

bool MbedTlsCryptoProvider::ecdhP256PublicKeyAsync(
    const uint8_t privateScalar[32], uint8_t publicKey[65],
    Crypto::TlsEcdhP256Callback callback, void *context) {
  return keyExchangePublicKeyAsync(Crypto::TlsKeyExchangeAlgorithm::EcdhP256,
                                   privateScalar, 32, publicKey, 65, callback,
                                   context);
}

bool MbedTlsCryptoProvider::ecdsaP256SignAsync(
    const uint8_t privateKey[32], const uint8_t nonceScalar[32],
    const uint8_t hash[32], uint8_t signature[64],
    Crypto::TlsEcdsaP256SignCallback callback, void *context) {
  return signatureSignAsync(Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256,
                            privateKey, 32, nonceScalar, 32, hash, 32,
                            signature, 64, callback, context);
}

bool MbedTlsCryptoProvider::ecdsaP256VerifyAsync(
    const uint8_t publicKey[65], const uint8_t hash[32],
    const uint8_t signature[64], Crypto::TlsEcdsaP256VerifyCallback callback,
    void *context) {
  return signatureVerifyAsync(Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256,
                              publicKey, 65, hash, 32, signature, 64,
                              callback, context);
}

bool MbedTlsCryptoProvider::keyExchangeSharedSecretAsync(
    Crypto::TlsKeyExchangeAlgorithm algorithm, const uint8_t *privateScalar,
    size_t privateScalarLength, const uint8_t *peerPublicKey,
    size_t peerPublicKeyLength, uint8_t *sharedSecret,
    size_t sharedSecretLength, Crypto::TlsKeyExchangeCallback callback,
    void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)algorithm;
  (void)privateScalar;
  (void)privateScalarLength;
  (void)peerPublicKey;
  (void)peerPublicKeyLength;
  (void)sharedSecret;
  (void)sharedSecretLength;
  (void)callback;
  (void)context;
  return false;
#else
  const EccCurveParams *curve = curveForKeyExchange(algorithm);
  if (curve == nullptr || privateScalarLength != curve->length ||
      peerPublicKeyLength != publicKeyLength(*curve) ||
      sharedSecretLength != curve->length) {
    return false;
  }
  return startEcdhSharedSecretAsync(*curve, privateScalar, peerPublicKey,
                                    sharedSecret, callback, context);
#endif
}

bool MbedTlsCryptoProvider::keyExchangePublicKeyAsync(
    Crypto::TlsKeyExchangeAlgorithm algorithm, const uint8_t *privateScalar,
    size_t privateScalarLength, uint8_t *publicKey, size_t publicKeyLengthValue,
    Crypto::TlsKeyExchangeCallback callback, void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)algorithm;
  (void)privateScalar;
  (void)privateScalarLength;
  (void)publicKey;
  (void)publicKeyLengthValue;
  (void)callback;
  (void)context;
  return false;
#else
  const EccCurveParams *curve = curveForKeyExchange(algorithm);
  if (curve == nullptr || privateScalarLength != curve->length ||
      publicKeyLengthValue != publicKeyLength(*curve)) {
    return false;
  }
  return startEcdhPublicKeyAsync(*curve, privateScalar, publicKey, callback,
                                 context);
#endif
}

bool MbedTlsCryptoProvider::signatureSignAsync(
    Crypto::TlsSignatureAlgorithm algorithm, const uint8_t *privateKey,
    size_t privateKeyLength, const uint8_t *nonceScalar,
    size_t nonceScalarLength, const uint8_t *hash, size_t hashLength,
    uint8_t *signature, size_t signatureLengthValue,
    Crypto::TlsSignatureCallback callback, void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)algorithm;
  (void)privateKey;
  (void)privateKeyLength;
  (void)nonceScalar;
  (void)nonceScalarLength;
  (void)hash;
  (void)hashLength;
  (void)signature;
  (void)signatureLengthValue;
  (void)callback;
  (void)context;
  return false;
#else
  const EccCurveParams *curve = curveForSignature(algorithm);
  if (curve == nullptr || privateKeyLength != curve->length ||
      nonceScalarLength != curve->length || hashLength != curve->length ||
      signatureLengthValue != signatureLength(*curve)) {
    return false;
  }
  return startEcdsaSignAsync(*curve, privateKey, nonceScalar, hash, signature,
                             callback, context);
#endif
}

bool MbedTlsCryptoProvider::signatureVerifyAsync(
    Crypto::TlsSignatureAlgorithm algorithm, const uint8_t *publicKey,
    size_t publicKeyLengthValue, const uint8_t *hash, size_t hashLength,
    const uint8_t *signature, size_t signatureLengthValue,
    Crypto::TlsSignatureCallback callback, void *context) {
#ifndef CRYPTO_HARDWARE_AVAILABLE
  (void)algorithm;
  (void)publicKey;
  (void)publicKeyLengthValue;
  (void)hash;
  (void)hashLength;
  (void)signature;
  (void)signatureLengthValue;
  (void)callback;
  (void)context;
  return false;
#else
  const EccCurveParams *curve = curveForSignature(algorithm);
  if (curve == nullptr || publicKeyLengthValue != publicKeyLength(*curve) ||
      hashLength != curve->length ||
      signatureLengthValue != signatureLength(*curve)) {
    return false;
  }
  return startEcdsaVerifyAsync(*curve, publicKey, hash, signature, callback,
                               context);
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

bool MbedTlsCryptoProvider::aesGcm256EncryptAsync(
    const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *plaintext, uint8_t *ciphertext,
    size_t length, uint8_t tag[16], Crypto::TlsAesGcm128Callback callback,
    void *context) {
  if (_gcmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesGcmSetKey(_gcmOperation, key, 32) ||
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

bool MbedTlsCryptoProvider::aesGcm256DecryptAsync(
    const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *ciphertext, uint8_t *plaintext,
    size_t length, const uint8_t tag[16], Crypto::TlsAesGcm128Callback callback,
    void *context) {
  if (_gcmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesGcmSetKey(_gcmOperation, key, 32) ||
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

bool MbedTlsCryptoProvider::aesCcm128EncryptAsync(
    const uint8_t key[16], const uint8_t *nonce, size_t nonceLength,
    const uint8_t *aad, size_t aadLength, const uint8_t *plaintext,
    uint8_t *ciphertext, size_t length, uint8_t *tag, size_t tagLength,
    Crypto::TlsAesGcm128Callback callback, void *context) {
  if (_ccmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesCcm128SetKey(_ccmOperation, key) ||
      !Crypto::MbedTlsPort::aesCcm128SetCallback(
          _ccmOperation, MbedTlsCryptoProvider::handleCcmComplete, this)) {
    return false;
  }

  _ccmCallback = callback;
  _ccmCallbackContext = context;
  _ccmBusy = true;
  if (!Crypto::MbedTlsPort::aesCcm128EncryptAsync(
          _ccmOperation, nonce, nonceLength, aad, aadLength, plaintext,
          ciphertext, length, tag, tagLength)) {
    finishCcm(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::aesCcm128DecryptAsync(
    const uint8_t key[16], const uint8_t *nonce, size_t nonceLength,
    const uint8_t *aad, size_t aadLength, const uint8_t *ciphertext,
    uint8_t *plaintext, size_t length, const uint8_t *tag, size_t tagLength,
    Crypto::TlsAesGcm128Callback callback, void *context) {
  if (_ccmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesCcm128SetKey(_ccmOperation, key) ||
      !Crypto::MbedTlsPort::aesCcm128SetCallback(
          _ccmOperation, MbedTlsCryptoProvider::handleCcmComplete, this)) {
    return false;
  }

  _ccmCallback = callback;
  _ccmCallbackContext = context;
  _ccmBusy = true;
  if (!Crypto::MbedTlsPort::aesCcm128DecryptAsync(
          _ccmOperation, nonce, nonceLength, aad, aadLength, ciphertext,
          plaintext, length, tag, tagLength)) {
    finishCcm(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::aesCcm256EncryptAsync(
    const uint8_t key[32], const uint8_t *nonce, size_t nonceLength,
    const uint8_t *aad, size_t aadLength, const uint8_t *plaintext,
    uint8_t *ciphertext, size_t length, uint8_t *tag, size_t tagLength,
    Crypto::TlsAesGcm128Callback callback, void *context) {
  if (_ccmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesCcmSetKey(_ccmOperation, key, 32) ||
      !Crypto::MbedTlsPort::aesCcm128SetCallback(
          _ccmOperation, MbedTlsCryptoProvider::handleCcmComplete, this)) {
    return false;
  }

  _ccmCallback = callback;
  _ccmCallbackContext = context;
  _ccmBusy = true;
  if (!Crypto::MbedTlsPort::aesCcm128EncryptAsync(
          _ccmOperation, nonce, nonceLength, aad, aadLength, plaintext,
          ciphertext, length, tag, tagLength)) {
    finishCcm(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::aesCcm256DecryptAsync(
    const uint8_t key[32], const uint8_t *nonce, size_t nonceLength,
    const uint8_t *aad, size_t aadLength, const uint8_t *ciphertext,
    uint8_t *plaintext, size_t length, const uint8_t *tag, size_t tagLength,
    Crypto::TlsAesGcm128Callback callback, void *context) {
  if (_ccmBusy || key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return false;
  }

  if (!Crypto::MbedTlsPort::aesCcmSetKey(_ccmOperation, key, 32) ||
      !Crypto::MbedTlsPort::aesCcm128SetCallback(
          _ccmOperation, MbedTlsCryptoProvider::handleCcmComplete, this)) {
    return false;
  }

  _ccmCallback = callback;
  _ccmCallbackContext = context;
  _ccmBusy = true;
  if (!Crypto::MbedTlsPort::aesCcm128DecryptAsync(
          _ccmOperation, nonce, nonceLength, aad, aadLength, ciphertext,
          plaintext, length, tag, tagLength)) {
    finishCcm(false);
    return false;
  }

  return true;
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

void MbedTlsCryptoProvider::handleCcmComplete(bool success,
                                              AesCcm128Context &operation,
                                              void *user) {
  (void)operation;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr)
    return;

  provider->finishCcm(success);
}

void MbedTlsCryptoProvider::finishCcm(bool success) {
  Crypto::TlsAesGcm128Callback callback = _ccmCallback;
  void *callbackContext = _ccmCallbackContext;
  _ccmCallback = nullptr;
  _ccmCallbackContext = nullptr;
  _ccmBusy = false;
  Crypto::MbedTlsPort::aesCcm128Free(_ccmOperation);

  if (callback != nullptr)
    callback(success, callbackContext);
}

#ifdef CRYPTO_HARDWARE_AVAILABLE
bool MbedTlsCryptoProvider::startEcdhSharedSecretAsync(
    const EccCurveParams &curve, const uint8_t *privateScalar,
    const uint8_t *peerPublicKey, uint8_t *sharedSecret,
    Crypto::TlsKeyExchangeCallback callback, void *context) {
  const uint16_t coordinateLength = curve.length;
  const uint16_t coordinateStorage = coordinateStorageLength(curve);

  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || privateScalar == nullptr ||
      peerPublicKey == nullptr || sharedSecret == nullptr ||
      callback == nullptr || peerPublicKey[0] != 0x04u) {
    return false;
  }

  clearEcdhWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhModulusOffset, coordinateLength + 4u, curve.prime,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhConstantOffset, coordinateLength + 12u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhCurveAOffset, coordinateLength + 4u, curve.a,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhCurveBOffset, coordinateLength + 4u, curve.b,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset, coordinateLength * 3u + 20u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset, coordinateStorage, peerPublicKey + 1u,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + coordinateStorage, coordinateStorage,
          peerPublicKey + 1u + coordinateLength, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + coordinateStorage * 2u, coordinateStorage,
          ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhScalarOffset, coordinateLength + 4u, privateScalar,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhWorkspaceOffset, coordinateLength * 6u, curve.prime, 0u)) {
    clearEcdhWorkspace();
    return false;
  }

  _ecdhOperation = {};
  _ecdhOperation.reductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.reductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.reductionSetup.modulusLength = coordinateLength;
  _ecdhOperation.reductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);
  _ecdhOperation.reductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdhWorkspaceOffset + coordinateLength * 2u + 4u));
  _ecdhOperation.peerPointValidation.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.peerPointValidation.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.peerPointValidation.modulusLength = coordinateLength;
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
  _ecdhOperation.multiply.modulusLength = coordinateLength;
  _ecdhOperation.multiply.scalarLength = coordinateLength;
  _ecdhOperation.affine.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.affine.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.affine.modulusLength = coordinateLength;
  _ecdhOperation.affine.point = pukcc::cryptoRamNearPointer(EcdhPointOffset);
  _ecdhOperation.affine.workspace =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);

  _ecdhSharedSecret = sharedSecret;
  _ecdhPublicKey = nullptr;
  _ecdhCallback = callback;
  _ecdhCallbackContext = context;
  _ecdhCoordinateLength = coordinateLength;
  _ecdhBusy = true;
  if (!Crypto::PukccEcc::startEcdhSharedSecretAsync(
          _ecdhOperation, MbedTlsCryptoProvider::handleEcdhComplete, this)) {
    finishEcdh(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::startEcdhPublicKeyAsync(
    const EccCurveParams &curve, const uint8_t *privateScalar,
    uint8_t *publicKey, Crypto::TlsKeyExchangeCallback callback,
    void *context) {
  const uint16_t coordinateLength = curve.length;
  const uint16_t coordinateStorage = coordinateStorageLength(curve);

  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || privateScalar == nullptr ||
      publicKey == nullptr || callback == nullptr)
    return false;

  clearEcdhWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhModulusOffset, coordinateLength + 4u, curve.prime,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhConstantOffset, coordinateLength + 12u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhCurveAOffset, coordinateLength + 4u, curve.a,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset, coordinateLength * 3u + 20u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(EcdhPointOffset,
                                                  coordinateStorage, curve.gx,
                                                  coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + coordinateStorage, coordinateStorage, curve.gy,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhPointOffset + coordinateStorage * 2u, coordinateStorage,
          ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhScalarOffset, coordinateLength + 4u, privateScalar,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdhWorkspaceOffset, coordinateLength * 6u, curve.prime, 0u)) {
    clearEcdhWorkspace();
    return false;
  }

  _ecdhOperation = {};
  _ecdhOperation.reductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.reductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.reductionSetup.modulusLength = coordinateLength;
  _ecdhOperation.reductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);
  _ecdhOperation.reductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdhWorkspaceOffset + coordinateLength * 2u + 4u));
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
  _ecdhOperation.multiply.modulusLength = coordinateLength;
  _ecdhOperation.multiply.scalarLength = coordinateLength;
  _ecdhOperation.affine.modulus =
      pukcc::cryptoRamNearPointer(EcdhModulusOffset);
  _ecdhOperation.affine.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdhConstantOffset);
  _ecdhOperation.affine.modulusLength = coordinateLength;
  _ecdhOperation.affine.point = pukcc::cryptoRamNearPointer(EcdhPointOffset);
  _ecdhOperation.affine.workspace =
      pukcc::cryptoRamNearPointer(EcdhWorkspaceOffset);

  _ecdhSharedSecret = nullptr;
  _ecdhPublicKey = publicKey;
  _ecdhCallback = callback;
  _ecdhCallbackContext = context;
  _ecdhCoordinateLength = coordinateLength;
  _ecdhBusy = true;
  _ecdhOperation.step = Crypto::PukccEcc::EcdhSharedSecretStep::ReductionSetup;

  if (!Crypto::registerPukccCallback(
          MbedTlsCryptoProvider::handleEcdhPublicKeyService, this) ||
      !submitEcdhPublicKeyStep()) {
    finishEcdh(false);
    return false;
  }

  return true;
}

bool MbedTlsCryptoProvider::submitEcdhPublicKeyStep() {
  switch (_ecdhOperation.step) {
  case Crypto::PukccEcc::EcdhSharedSecretStep::ReductionSetup:
    return Crypto::PukccEcc::startReductionSetupAsync(
        _ecdhOperation.reductionSetup, _ecdhOperation.result);
  case Crypto::PukccEcc::EcdhSharedSecretStep::ScalarMultiply:
    return Crypto::PukccEcc::startEcdhMultiplyAsync(_ecdhOperation.multiply,
                                                    _ecdhOperation.result);
  case Crypto::PukccEcc::EcdhSharedSecretStep::ProjectiveToAffine:
    return Crypto::PukccEcc::startProjectiveToAffineAsync(
        _ecdhOperation.affine, _ecdhOperation.result);
  case Crypto::PukccEcc::EcdhSharedSecretStep::Idle:
  case Crypto::PukccEcc::EcdhSharedSecretStep::PeerPointValidation:
  case Crypto::PukccEcc::EcdhSharedSecretStep::Complete:
  case Crypto::PukccEcc::EcdhSharedSecretStep::Error:
    return false;
  }

  return false;
}

void MbedTlsCryptoProvider::handleEcdhPublicKeyService(pukcc::EventMask events,
                                                       uint8_t service,
                                                       uint16_t status,
                                                       void *user) {
  (void)service;
  auto *provider = static_cast<MbedTlsCryptoProvider *>(user);
  if (provider == nullptr || !provider->_ecdhBusy)
    return;

  if ((events & pukcc::EventComplete) == 0 || status != pukcc::StatusOk) {
    provider->finishEcdh(false);
    return;
  }

  switch (provider->_ecdhOperation.step) {
  case Crypto::PukccEcc::EcdhSharedSecretStep::ReductionSetup:
    provider->_ecdhOperation.step =
        Crypto::PukccEcc::EcdhSharedSecretStep::ScalarMultiply;
    break;
  case Crypto::PukccEcc::EcdhSharedSecretStep::ScalarMultiply:
    provider->_ecdhOperation.step =
        Crypto::PukccEcc::EcdhSharedSecretStep::ProjectiveToAffine;
    break;
  case Crypto::PukccEcc::EcdhSharedSecretStep::ProjectiveToAffine:
    provider->finishEcdh(true);
    return;
  case Crypto::PukccEcc::EcdhSharedSecretStep::Idle:
  case Crypto::PukccEcc::EcdhSharedSecretStep::PeerPointValidation:
  case Crypto::PukccEcc::EcdhSharedSecretStep::Complete:
  case Crypto::PukccEcc::EcdhSharedSecretStep::Error:
    provider->finishEcdh(false);
    return;
  }

  if (!provider->submitEcdhPublicKeyStep())
    provider->finishEcdh(false);
}

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
  const uint16_t coordinateLength = _ecdhCoordinateLength;
  const uint16_t coordinateStorage =
      static_cast<uint16_t>(coordinateLength + 4u);
  if (success && _ecdhPublicKey != nullptr) {
    _ecdhPublicKey[0] = 0x04u;
    completed =
        copyCryptoRamToBigEndian(EcdhPointOffset, _ecdhPublicKey + 1u,
                                 coordinateLength) &&
        copyCryptoRamToBigEndian(
            static_cast<uint16_t>(EcdhPointOffset + coordinateStorage),
            _ecdhPublicKey + 1u + coordinateLength, coordinateLength);
  } else if (success && _ecdhSharedSecret != nullptr) {
    completed = copyCryptoRamToBigEndian(EcdhPointOffset, _ecdhSharedSecret,
                                         coordinateLength);
  }

  Crypto::TlsKeyExchangeCallback callback = _ecdhCallback;
  void *callbackContext = _ecdhCallbackContext;
  _ecdhOperation = {};
  _ecdhSharedSecret = nullptr;
  _ecdhPublicKey = nullptr;
  _ecdhCallback = nullptr;
  _ecdhCallbackContext = nullptr;
  _ecdhCoordinateLength = 0;
  _ecdhBusy = false;
  Crypto::clearPukccCallback();
  clearEcdhWorkspace();

  if (callback != nullptr)
    callback(success && completed, callbackContext);
}

void MbedTlsCryptoProvider::clearEcdhWorkspace() {
  clearCryptoRamRange(EcdhModulusOffset, EcdhWorkspaceEnd - EcdhModulusOffset);
}

bool MbedTlsCryptoProvider::startEcdsaSignAsync(
    const EccCurveParams &curve, const uint8_t *privateKey,
    const uint8_t *nonceScalar, const uint8_t *hash, uint8_t *signature,
    Crypto::TlsSignatureCallback callback, void *context) {
  const uint16_t coordinateLength = curve.length;
  const uint16_t coordinateStorage = coordinateStorageLength(curve);

  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || privateKey == nullptr ||
      nonceScalar == nullptr || hash == nullptr || signature == nullptr ||
      callback == nullptr) {
    return false;
  }

  clearEcdsaSignWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignModulusOffset, coordinateLength + 4u, curve.prime,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignConstantOffset, coordinateLength + 12u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset, coordinateStorage * 3u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset, coordinateStorage, curve.gx,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset + coordinateStorage, coordinateStorage,
          curve.gy, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignBasePointOffset + coordinateStorage * 2u,
          coordinateStorage, ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignCurveAOffset, coordinateLength + 4u, curve.a,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignPrivateKeyOffset, coordinateLength + 4u, privateKey,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignScalarOffset, coordinateLength + 4u, nonceScalar,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignOrderOffset, coordinateLength + 4u, curve.order,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignHashOffset, coordinateLength + 4u, hash,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignWorkspaceOffset, coordinateLength * 8u + 44u, curve.prime,
          0u)) {
    clearEcdsaSignWorkspace();
    return false;
  }

  _ecdsaSign = {};
  _ecdsaSignReductionSetup = {};
  _ecdsaSignReductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdsaSignModulusOffset);
  _ecdsaSignReductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaSignConstantOffset);
  _ecdsaSignReductionSetup.modulusLength = coordinateLength;
  _ecdsaSignReductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdsaSignWorkspaceOffset);
  _ecdsaSignReductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdsaSignWorkspaceOffset +
                            coordinateLength * 2u + 4u));
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
  _ecdsaSign.modulusLength = coordinateLength;
  _ecdsaSign.scalarLength = coordinateLength;

  if (!Crypto::registerPukccCallback(
          MbedTlsCryptoProvider::handleEcdsaSignService, this)) {
    clearEcdsaSignWorkspace();
    return false;
  }

  _ecdsaSignResult = {};
  _ecdsaSignature = signature;
  _ecdsaSignCallback = callback;
  _ecdsaSignCallbackContext = context;
  _ecdsaSignCoordinateLength = coordinateLength;
  _ecdsaSignStep = EcdsaSignStep::ReductionSetup;
  _ecdsaSignBusy = true;
  if (!submitEcdsaSignStep()) {
    finishEcdsaSign(false);
    return false;
  }

  return true;
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
  const uint16_t coordinateLength = _ecdsaSignCoordinateLength;
  const uint16_t coordinateStorage =
      static_cast<uint16_t>(coordinateLength + 4u);
  if (success && _ecdsaSignature != nullptr) {
    completed =
        copyCryptoRamToBigEndian(EcdsaSignBasePointOffset, _ecdsaSignature,
                                 coordinateLength) &&
        copyCryptoRamToBigEndian(
            static_cast<uint16_t>(EcdsaSignBasePointOffset +
                                  coordinateStorage),
            _ecdsaSignature + coordinateLength, coordinateLength);
  }

  Crypto::TlsSignatureCallback callback = _ecdsaSignCallback;
  void *callbackContext = _ecdsaSignCallbackContext;
  _ecdsaSignReductionSetup = {};
  _ecdsaSign = {};
  _ecdsaSignResult = {};
  _ecdsaSignature = nullptr;
  _ecdsaSignCallback = nullptr;
  _ecdsaSignCallbackContext = nullptr;
  _ecdsaSignCoordinateLength = 0;
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

bool MbedTlsCryptoProvider::startEcdsaVerifyAsync(
    const EccCurveParams &curve, const uint8_t *publicKey, const uint8_t *hash,
    const uint8_t *signature, Crypto::TlsSignatureCallback callback,
    void *context) {
  const uint16_t coordinateLength = curve.length;
  const uint16_t coordinateStorage = coordinateStorageLength(curve);

  if (_ecdhBusy || _ecdsaSignBusy || _ecdsaBusy || publicKey == nullptr ||
      hash == nullptr || signature == nullptr || callback == nullptr ||
      publicKey[0] != 0x04u) {
    return false;
  }

  clearEcdsaWorkspace();
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaModulusOffset, coordinateLength + 4u, curve.prime,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaConstantOffset, coordinateLength + 12u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaOrderOffset, coordinateLength + 12u, curve.order,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset, coordinateLength + 4u, signature,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset + coordinateLength + 4u, coordinateLength + 4u,
          signature + coordinateLength, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaHashOffset, coordinateLength + 4u, hash, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset, coordinateStorage * 3u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset, coordinateStorage, curve.gx,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset + coordinateStorage, coordinateStorage,
          curve.gy, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaBasePointOffset + coordinateStorage * 2u, coordinateStorage,
          ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset, coordinateStorage * 3u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset, coordinateStorage, publicKey + 1u,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset + coordinateStorage, coordinateStorage,
          publicKey + 1u + coordinateLength, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaPublicKeyOffset + coordinateStorage * 2u, coordinateStorage,
          ProjectiveOne, sizeof(ProjectiveOne)) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaCurveAOffset, coordinateLength + 4u, curve.a,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaCurveBOffset, coordinateLength + 4u, curve.b,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaWorkspaceOffset, coordinateLength * 8u + 44u, curve.prime,
          0u)) {
    clearEcdsaWorkspace();
    return false;
  }

  _ecdsaReductionSetup = {};
  _ecdsaReductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaReductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaReductionSetup.modulusLength = coordinateLength;
  _ecdsaReductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdsaWorkspaceOffset);
  _ecdsaReductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdsaWorkspaceOffset + coordinateLength * 2u + 4u));
  _ecdsaPublicKeyValidation = {};
  _ecdsaPublicKeyValidation.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaPublicKeyValidation.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaPublicKeyValidation.modulusLength = coordinateLength;
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
  _ecdsaVerify.modulusLength = coordinateLength;
  _ecdsaVerify.scalarLength = coordinateLength;

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
  Crypto::TlsSignatureCallback callback = _ecdsaCallback;
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

#include "PukccEcdsa.h"
#include <string.h>
#ifdef CRYPTO_HARDWARE_AVAILABLE
namespace Crypto::PukccEcc {
namespace {
constexpr uint16_t P256Length = 32u;
constexpr uint16_t MaxEccPukccLength = 68u;
constexpr uint16_t MaxEccCoordinateStorageLength = MaxEccPukccLength + 4u;
constexpr uint16_t EcdsaModulusOffset = 0u;
constexpr uint16_t EcdsaModulusStorageLength = MaxEccPukccLength + 4u;
constexpr uint16_t EcdsaConstantOffset =
    EcdsaModulusOffset + EcdsaModulusStorageLength;
constexpr uint16_t EcdsaOrderOffset =
    EcdsaConstantOffset + MaxEccPukccLength + 12u;
constexpr uint16_t EcdsaSignatureOffset =
    EcdsaOrderOffset + MaxEccPukccLength + 12u;
constexpr uint16_t EcdsaHashOffset =
    EcdsaSignatureOffset + MaxEccPukccLength * 2u + 8u;
constexpr uint16_t EcdsaBasePointOffset =
    EcdsaHashOffset + MaxEccPukccLength + 4u;
constexpr uint16_t EcdsaPublicKeyOffset =
    EcdsaBasePointOffset + MaxEccCoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveAOffset =
    EcdsaPublicKeyOffset + MaxEccCoordinateStorageLength * 3u;
constexpr uint16_t EcdsaCurveBOffset =
    EcdsaCurveAOffset + MaxEccPukccLength + 4u;
constexpr uint16_t EcdsaWorkspaceOffset =
    EcdsaCurveBOffset + MaxEccPukccLength + 4u;
constexpr uint16_t EcdsaWorkspaceLength = MaxEccPukccLength * 8u + 44u;
constexpr uint16_t EcdsaWorkspaceEnd =
    EcdsaWorkspaceOffset + EcdsaWorkspaceLength;
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

const uint8_t ProjectiveOne[1] = {1u};
uint16_t coordinateStorageLength(const EccCurveParams &curve) { return curve.pukccLength + 4u; }
bool validScalar(const uint8_t *value, const EccCurveParams &curve) {
  uint8_t nonzero = 0;
  for (uint16_t i = 0; i < curve.coordinateLength; ++i) nonzero |= value[i];
  return nonzero != 0 && memcmp(value, curve.order, curve.coordinateLength) < 0;
}


}
const EccCurveParams P256Curve = {
    P256Length, P256Length, 32u, P256Prime, P256A, P256B, P256Order, P256Gx,
    P256Gy};

bool EcdsaVerifier::startEcdsaVerifyAsync(
    const EccCurveParams &curve, const uint8_t *publicKey, const uint8_t *hash,
    const uint8_t *signature, Callback callback,
    void *context) {
  const uint16_t coordinateLength = curve.coordinateLength;
  const uint16_t pukccLength = curve.pukccLength;
  const uint16_t coordinateStorage = coordinateStorageLength(curve);

  if (_ecdsaBusy || publicKey == nullptr ||
      hash == nullptr || signature == nullptr || callback == nullptr ||
      publicKey[0] != 0x04u ||
      !validScalar(signature, curve) ||
      !validScalar(signature + coordinateLength, curve) ||
      memcmp(publicKey + 1u, curve.prime, coordinateLength) >= 0 ||
      memcmp(publicKey + 1u + coordinateLength, curve.prime, coordinateLength) >= 0) {
    return false;
  }

  if (!Crypto::registerPukccCallback(EcdsaVerifier::handleEcdsaService, this))
    return false;

  if (!clearEcdsaWorkspace()) {
    Crypto::clearPukccCallback();
    return false;
  }
  if (!Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaModulusOffset, pukccLength + 4u, curve.prime,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaConstantOffset, pukccLength + 12u, curve.prime, 0u) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaOrderOffset, pukccLength + 12u, curve.order,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset, pukccLength + 4u, signature,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaSignatureOffset + pukccLength + 4u, pukccLength + 4u,
          signature + coordinateLength, coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaHashOffset, pukccLength + 4u, hash, curve.hashLength) ||
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
          EcdsaCurveAOffset, pukccLength + 4u, curve.a,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaCurveBOffset, pukccLength + 4u, curve.b,
          coordinateLength) ||
      !Crypto::PukccEcc::copyBigEndianToCryptoRam(
          EcdsaWorkspaceOffset, pukccLength * 8u + 44u, curve.prime,
          0u)) {
    clearEcdsaWorkspace();
    Crypto::clearPukccCallback();
    return false;
  }

  _ecdsaReductionSetup = {};
  _ecdsaReductionSetup.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaReductionSetup.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaReductionSetup.modulusLength = pukccLength;
  _ecdsaReductionSetup.scratchR =
      pukcc::cryptoRamNearPointer(EcdsaWorkspaceOffset);
  _ecdsaReductionSetup.scratchX = pukcc::cryptoRamNearPointer(
      static_cast<uint16_t>(EcdsaWorkspaceOffset + pukccLength * 2u + 4u));
  _ecdsaPublicKeyValidation = {};
  _ecdsaPublicKeyValidation.modulus =
      pukcc::cryptoRamNearPointer(EcdsaModulusOffset);
  _ecdsaPublicKeyValidation.reductionConstant =
      pukcc::cryptoRamNearPointer(EcdsaConstantOffset);
  _ecdsaPublicKeyValidation.modulusLength = pukccLength;
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
  _ecdsaVerify.modulusLength = pukccLength;
  _ecdsaVerify.scalarLength = pukccLength;


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

void EcdsaVerifier::handleEcdsaService(pukcc::EventMask events,
                                               uint8_t service, uint16_t status,
                                               void *user) {
  (void)service;
  auto *provider = static_cast<EcdsaVerifier *>(user);
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

bool EcdsaVerifier::submitEcdsaStep() {
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

void EcdsaVerifier::finishEcdsa(bool success) {
  const bool cleared = clearEcdsaWorkspace();
  success = success && cleared;
  Callback callback = _ecdsaCallback;
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

  if (callback != nullptr)
    callback(success, callbackContext);
}

bool EcdsaVerifier::clearEcdsaWorkspace() {
  pukcc::ServiceResult result{};
  return pukcc::fillCryptoRam(EcdsaModulusOffset,
                             EcdsaWorkspaceEnd - EcdsaModulusOffset, 0u, result);
}


void EcdsaVerifier::reset() {
  if (_ecdsaBusy) Crypto::clearPukccCallback();
  clearEcdsaWorkspace();
  _ecdsaReductionSetup = {};
  _ecdsaPublicKeyValidation = {};
  _ecdsaVerify = {};
  _ecdsaResult = {};
  _ecdsaCallback = nullptr;
  _ecdsaCallbackContext = nullptr;
  _ecdsaStep = EcdsaVerifyStep::Idle;
  _ecdsaBusy = false;
}
}
#endif

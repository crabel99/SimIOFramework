#include "PukccEcc.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccEcc {
namespace {
EcdhSharedSecretOperation *activeEcdhSharedSecret = nullptr;

bool validNearPointer(uint16_t nearPointer, uint16_t length) {
  if (nearPointer < pukcc::CryptoRamNearBase)
    return false;

  const uint16_t offset = nearPointer - pukcc::CryptoRamNearBase;
  return pukcc::validCryptoRamRange(offset, length);
}

bool validReductionSetupLayout(const ReductionSetupOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  if (modLength == 0u)
    return false;

  return validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.scratchR,
                          static_cast<uint16_t>(modLength * 2u + 4u)) &&
         validNearPointer(operation.scratchX,
                          static_cast<uint16_t>(modLength * 2u + 8u));
}

bool validEcdsaVerifyLayout(const EcdsaVerifyOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  const uint16_t scalarLength = operation.scalarLength;
  if (modLength == 0u || scalarLength == 0u)
    return false;

  return validNearPointer(operation.basePoint,
                          static_cast<uint16_t>(modLength * 3u + 12u)) &&
         validNearPointer(operation.order,
                          static_cast<uint16_t>(scalarLength + 12u)) &&
         validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(scalarLength + 12u)) &&
         validNearPointer(operation.publicKey,
                          static_cast<uint16_t>(modLength * 3u + 12u)) &&
         validNearPointer(operation.signature,
                          static_cast<uint16_t>(scalarLength * 2u + 8u)) &&
         validNearPointer(operation.curveA,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.hash,
                          static_cast<uint16_t>(scalarLength + 4u)) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 8u + 44u));
}

bool validEcdhMultiplyLayout(const EcdhMultiplyOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  const uint16_t scalarLength = operation.scalarLength;
  if (modLength == 0u || scalarLength == 0u)
    return false;

  return validNearPointer(operation.point,
                          static_cast<uint16_t>(modLength * 3u + 20u)) &&
         validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.scalar,
                          static_cast<uint16_t>(scalarLength + 4u)) &&
         validNearPointer(operation.curveA,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 6u));
}

bool validProjectiveToAffineLayout(
    const ProjectiveToAffineOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  if (modLength == 0u)
    return false;

  return validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.point,
                          static_cast<uint16_t>(modLength * 3u + 20u)) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 6u));
}

bool validPointIsOnCurveLayout(const PointIsOnCurveOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  if (modLength == 0u)
    return false;

  return validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.curveA,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.curveB,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.point,
                          static_cast<uint16_t>(modLength * 3u + 12u)) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 6u));
}

void reject(pukcc::ServiceResult &result, uint8_t service, uint16_t status) {
  result = {};
  result.service = service;
  result.status = status;
}

void finishEcdhSharedSecret(EcdhSharedSecretOperation &operation,
                            bool success, uint8_t service,
                            uint16_t status) {
  operation.result.service = service;
  operation.result.status = status;
  operation.busy = false;
  operation.step =
      success ? EcdhSharedSecretStep::Complete : EcdhSharedSecretStep::Error;
  activeEcdhSharedSecret = nullptr;
  Crypto::clearPukccCallback();

  EcdhSharedSecretCallback callback = operation.callback;
  void *callbackContext = operation.callbackContext;
  operation.callback = nullptr;
  operation.callbackContext = nullptr;
  if (callback != nullptr)
    callback(success, operation.result, operation, callbackContext);
}

bool submitEcdhSharedSecretStep(EcdhSharedSecretOperation &operation) {
  switch (operation.step) {
  case EcdhSharedSecretStep::ReductionSetup:
    return startReductionSetupAsync(operation.reductionSetup, operation.result);
  case EcdhSharedSecretStep::PeerPointValidation:
    return startPointIsOnCurveAsync(operation.peerPointValidation,
                                    operation.result);
  case EcdhSharedSecretStep::ScalarMultiply:
    return startEcdhMultiplyAsync(operation.multiply, operation.result);
  case EcdhSharedSecretStep::ProjectiveToAffine:
    return startProjectiveToAffineAsync(operation.affine, operation.result);
  case EcdhSharedSecretStep::Idle:
  case EcdhSharedSecretStep::Complete:
  case EcdhSharedSecretStep::Error:
    return false;
  }

  return false;
}

void handleEcdhSharedSecretService(pukcc::EventMask events, uint8_t service,
                                   uint16_t status, void *context) {
  (void)context;
  EcdhSharedSecretOperation *operation = activeEcdhSharedSecret;
  if (operation == nullptr || !operation->busy)
    return;

  if ((events & pukcc::EventComplete) == 0 || status != pukcc::StatusOk) {
    finishEcdhSharedSecret(*operation, false, service, status);
    return;
  }

  switch (operation->step) {
  case EcdhSharedSecretStep::ReductionSetup:
    operation->step = EcdhSharedSecretStep::PeerPointValidation;
    break;
  case EcdhSharedSecretStep::PeerPointValidation:
    operation->step = EcdhSharedSecretStep::ScalarMultiply;
    break;
  case EcdhSharedSecretStep::ScalarMultiply:
    operation->step = EcdhSharedSecretStep::ProjectiveToAffine;
    break;
  case EcdhSharedSecretStep::ProjectiveToAffine:
    finishEcdhSharedSecret(*operation, true, service, status);
    return;
  case EcdhSharedSecretStep::Idle:
  case EcdhSharedSecretStep::Complete:
  case EcdhSharedSecretStep::Error:
    finishEcdhSharedSecret(*operation, false, service,
                           pukcc::StatusComputationNotStarted);
    return;
  }

  if (!submitEcdhSharedSecretStep(*operation)) {
    finishEcdhSharedSecret(*operation, false, operation->result.service,
                           operation->result.status);
  }
}
} // namespace

static_assert(sizeof(EcdsaVerifyOperation) == 40,
              "ECDSA verify parameter block must match the PUKCC ROM ABI");
static_assert(sizeof(EcdhMultiplyOperation) == 32,
              "ECDH multiply parameter block must match the PUKCC ROM ABI");
static_assert(
    sizeof(ProjectiveToAffineOperation) == 28,
    "Projective-to-affine parameter block must match the PUKCC ROM ABI");
static_assert(sizeof(PointIsOnCurveOperation) == 36,
              "Point-is-on-curve parameter block must match the PUKCC ROM ABI");
static_assert(sizeof(ReductionSetupOperation) == 32,
              "RedMod parameter block must match the PUKCC ROM ABI");

bool copyBigEndianToCryptoRam(uint16_t offset, uint16_t destinationLength,
                              const uint8_t *source, uint16_t sourceLength) {
  if (source == nullptr || sourceLength > destinationLength ||
      !pukcc::validCryptoRamRange(offset, destinationLength))
    return false;
  pukcc::enableClock();
  if (!pukcc::ready())
    return false;

  volatile uint32_t *destination =
      reinterpret_cast<volatile uint32_t *>(pukcc::cryptoRam(offset));
  const uint16_t wordCount = destinationLength / sizeof(uint32_t);
  for (uint16_t index = 0; index < wordCount; ++index)
    destination[index] = 0;

  const uint16_t copyLength =
      sourceLength < destinationLength ? sourceLength : destinationLength;
  for (uint16_t index = 0; index < copyLength; ++index) {
    const uint16_t sourceIndex = copyLength - 1u - index;
    const uint16_t wordIndex = index / sizeof(uint32_t);
    const uint16_t byteShift = (index % sizeof(uint32_t)) * 8u;
    uint32_t word = destination[wordIndex];
    word &= ~(0xFFu << byteShift);
    word |= static_cast<uint32_t>(source[sourceIndex]) << byteShift;
    destination[wordIndex] = word;
  }

  return true;
}

bool startReductionSetupAsync(ReductionSetupOperation &operation,
                              pukcc::ServiceResult &result) {
  if (!validReductionSetupLayout(operation)) {
    reject(result, pukcc::RedModServiceId, pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  operation.header.option = RedModSetupOption;
  return Crypto::pukccServiceAsync(pukcc::RedModServiceId, operation.header,
                                  result);
}

bool startEcdsaVerifyAsync(EcdsaVerifyOperation &operation,
                           pukcc::ServiceResult &result) {
  if (!validEcdsaVerifyLayout(operation)) {
    reject(result, pukcc::ZpEcDsaVerifyFastServiceId,
           pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  return Crypto::pukccServiceAsync(pukcc::ZpEcDsaVerifyFastServiceId,
                                  operation.header, result);
}

bool startEcdhMultiplyAsync(EcdhMultiplyOperation &operation,
                            pukcc::ServiceResult &result) {
  if (!validEcdhMultiplyLayout(operation)) {
    reject(result, pukcc::ZpEccMulFastServiceId,
           pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  return Crypto::pukccServiceAsync(pukcc::ZpEccMulFastServiceId,
                                  operation.header, result);
}

bool startProjectiveToAffineAsync(ProjectiveToAffineOperation &operation,
                                  pukcc::ServiceResult &result) {
  if (!validProjectiveToAffineLayout(operation)) {
    reject(result, pukcc::ZpEcConvProjToAffineServiceId,
           pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  return Crypto::pukccServiceAsync(pukcc::ZpEcConvProjToAffineServiceId,
                                   operation.header, result);
}

bool startPointIsOnCurveAsync(PointIsOnCurveOperation &operation,
                              pukcc::ServiceResult &result) {
  if (!validPointIsOnCurveLayout(operation)) {
    reject(result, pukcc::ZpEcPointIsOnCurveServiceId,
           pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  return Crypto::pukccServiceAsync(pukcc::ZpEcPointIsOnCurveServiceId,
                                  operation.header, result);
}

bool startEcdhSharedSecretAsync(EcdhSharedSecretOperation &operation,
                                EcdhSharedSecretCallback callback,
                                void *callbackContext) {
  if (callback == nullptr || operation.busy || activeEcdhSharedSecret != nullptr)
    return false;

  if (!validReductionSetupLayout(operation.reductionSetup) ||
      !validPointIsOnCurveLayout(operation.peerPointValidation) ||
      !validEcdhMultiplyLayout(operation.multiply) ||
      !validProjectiveToAffineLayout(operation.affine)) {
    reject(operation.result, pukcc::ZpEccMulFastServiceId,
           pukcc::StatusParameterNotInPukccRam);
    operation.step = EcdhSharedSecretStep::Error;
    return false;
  }

  if (!Crypto::registerPukccCallback(handleEcdhSharedSecretService,
                                     &operation)) {
    return false;
  }

  operation.result = {};
  operation.callback = callback;
  operation.callbackContext = callbackContext;
  operation.step = EcdhSharedSecretStep::ReductionSetup;
  operation.busy = true;
  activeEcdhSharedSecret = &operation;

  if (!submitEcdhSharedSecretStep(operation)) {
    activeEcdhSharedSecret = nullptr;
    operation.busy = false;
    operation.step = EcdhSharedSecretStep::Error;
    Crypto::clearPukccCallback();
    return false;
  }

  return true;
}

} // namespace Crypto::PukccEcc

#endif /* CRYPTO_HARDWARE_AVAILABLE */

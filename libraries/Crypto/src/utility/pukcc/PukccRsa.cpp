#include "PukccRsa.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccRsa {
namespace {
PublicExpModOperation *activePublicExpMod = nullptr;

bool validNearPointer(uint16_t nearPointer, uint16_t length) {
  if (nearPointer < pukcc::CryptoRamNearBase)
    return false;

  const uint16_t offset = nearPointer - pukcc::CryptoRamNearBase;
  return pukcc::validCryptoRamRange(offset, length);
}

bool validExpModLayout(const ExpModOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  if (modLength == 0u || operation.exponent == nullptr ||
      operation.exponentLength == 0u)
    return false;

  return validNearPointer(operation.message,
                          static_cast<uint16_t>(modLength + 16u)) &&
         validNearPointer(operation.modulus,
                          static_cast<uint16_t>(modLength + 4u)) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 8u)) &&
         validNearPointer(operation.precomp,
                          static_cast<uint16_t>(3u * (modLength + 4u) + 8u));
}

void reject(pukcc::ServiceResult &result, uint8_t service, uint16_t status) {
  result = {};
  result.service = service;
  result.status = status;
}

void finishPublicExpMod(PublicExpModOperation &operation, bool success,
                        uint8_t service, uint16_t status) {
  operation.result.service = service;
  operation.result.status = status;
  operation.busy = false;
  operation.step =
      success ? PublicExpModStep::Complete : PublicExpModStep::Error;
  activePublicExpMod = nullptr;
  Crypto::clearPukccCallback();

  PublicExpModCallback callback = operation.callback;
  void *callbackContext = operation.callbackContext;
  operation.callback = nullptr;
  operation.callbackContext = nullptr;
  if (callback != nullptr)
    callback(success, operation.result, operation, callbackContext);
}

bool submitPublicExpModStep(PublicExpModOperation &operation) {
  switch (operation.step) {
  case PublicExpModStep::ReductionSetup:
    return PukccEcc::startReductionSetupAsync(operation.reductionSetup,
                                             operation.result);
  case PublicExpModStep::Exponentiation:
    if (operation.message != nullptr) {
      const uint16_t messageOffset =
          operation.exponentiation.message - pukcc::CryptoRamNearBase;
      if (!PukccEcc::copyBigEndianToCryptoRam(
              messageOffset, operation.exponentiation.modulusLength,
              operation.message, operation.messageLength)) {
        reject(operation.result, pukcc::ExpModServiceId,
               pukcc::StatusParameterNotInPukccRam);
        return false;
      }
    }
    return startExpModAsync(operation.exponentiation, operation.mode,
                            operation.windowSize, operation.result);
  case PublicExpModStep::Idle:
  case PublicExpModStep::Complete:
  case PublicExpModStep::Error:
    return false;
  }

  return false;
}

void handlePublicExpModService(pukcc::EventMask events, uint8_t service,
                               uint16_t status, void *context) {
  (void)context;
  PublicExpModOperation *operation = activePublicExpMod;
  if (operation == nullptr || !operation->busy)
    return;

  if ((events & pukcc::EventComplete) == 0 || status != pukcc::StatusOk) {
    finishPublicExpMod(*operation, false, service, status);
    return;
  }

  switch (operation->step) {
  case PublicExpModStep::ReductionSetup:
    operation->step = PublicExpModStep::Exponentiation;
    break;
  case PublicExpModStep::Exponentiation:
    finishPublicExpMod(*operation, true, service, status);
    return;
  case PublicExpModStep::Idle:
  case PublicExpModStep::Complete:
  case PublicExpModStep::Error:
    finishPublicExpMod(*operation, false, service,
                       pukcc::StatusComputationNotStarted);
    return;
  }

  if (!submitPublicExpModStep(*operation)) {
    finishPublicExpMod(*operation, false, operation->result.service,
                       operation->result.status);
  }
}
} // namespace

static_assert(sizeof(ExpModOperation) == 36,
              "ExpMod parameter block must match the PUKCC ROM ABI");

bool startExpModAsync(ExpModOperation &operation, ExpModMode mode,
                      ExpModWindowSize windowSize,
                      pukcc::ServiceResult &result) {
  if (!validExpModLayout(operation)) {
    reject(result, pukcc::ExpModServiceId, pukcc::StatusParameterNotInPukccRam);
    return false;
  }

  operation.header = {};
  operation.header.option = static_cast<uint16_t>(mode) |
                            static_cast<uint16_t>(windowSize) |
                            ExpModExponentInPukccRamOption;
  return Crypto::pukccServiceAsync(pukcc::ExpModServiceId, operation.header,
                                  result);
}

bool startExpModAsync(ExpModOperation &operation, pukcc::ServiceResult &result) {
  return startExpModAsync(operation, ExpModMode::Fast, ExpModWindowSize::Bits1,
                          result);
}

bool startPublicExpModAsync(PublicExpModOperation &operation,
                            PublicExpModCallback callback,
                            void *callbackContext) {
  if (callback == nullptr || operation.busy || activePublicExpMod != nullptr)
    return false;

  if (!validExpModLayout(operation.exponentiation)) {
    reject(operation.result, pukcc::ExpModServiceId,
           pukcc::StatusParameterNotInPukccRam);
    operation.step = PublicExpModStep::Error;
    return false;
  }

  if (!Crypto::registerPukccCallback(handlePublicExpModService, &operation))
    return false;

  operation.result = {};
  operation.callback = callback;
  operation.callbackContext = callbackContext;
  operation.step = PublicExpModStep::ReductionSetup;
  operation.busy = true;
  activePublicExpMod = &operation;

  if (!submitPublicExpModStep(operation)) {
    activePublicExpMod = nullptr;
    operation.busy = false;
    operation.step = PublicExpModStep::Error;
    Crypto::clearPukccCallback();
    return false;
  }

  return true;
}

} // namespace Crypto::PukccRsa

#endif /* CRYPTO_HARDWARE_AVAILABLE */

#include "PukccEcc.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccEcc {
namespace {
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

  return validNearPointer(operation.modulus, modLength) &&
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
                          static_cast<uint16_t>(modLength * 2u)) &&
         validNearPointer(operation.order, scalarLength) &&
         validNearPointer(operation.modulus, modLength) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.publicKey,
                          static_cast<uint16_t>(modLength * 2u)) &&
         validNearPointer(operation.signature,
                          static_cast<uint16_t>(scalarLength * 2u)) &&
         validNearPointer(operation.curveA, modLength) &&
         validNearPointer(operation.hash, scalarLength) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 6u));
}

bool validEcdhMultiplyLayout(const EcdhMultiplyOperation &operation) {
  const uint16_t modLength = operation.modulusLength;
  const uint16_t scalarLength = operation.scalarLength;
  if (modLength == 0u || scalarLength == 0u)
    return false;

  return validNearPointer(operation.point,
                          static_cast<uint16_t>(modLength * 2u)) &&
         validNearPointer(operation.modulus, modLength) &&
         validNearPointer(operation.reductionConstant,
                          static_cast<uint16_t>(modLength + 12u)) &&
         validNearPointer(operation.scalar, scalarLength) &&
         validNearPointer(operation.curveA, modLength) &&
         validNearPointer(operation.workspace,
                          static_cast<uint16_t>(modLength * 6u));
}

void reject(pukcc::ServiceResult &result, uint8_t service, uint16_t status) {
  result = {};
  result.service = service;
  result.status = status;
}
} // namespace

static_assert(sizeof(EcdsaVerifyOperation) == 40,
              "ECDSA verify parameter block must match the PUKCC ROM ABI");
static_assert(sizeof(EcdhMultiplyOperation) == 32,
              "ECDH multiply parameter block must match the PUKCC ROM ABI");
static_assert(sizeof(ReductionSetupOperation) == 32,
              "RedMod parameter block must match the PUKCC ROM ABI");

bool copyBigEndianToCryptoRam(uint16_t offset, uint16_t destinationLength,
                              const uint8_t *source, uint16_t sourceLength) {
  if (source == nullptr || !pukcc::validCryptoRamRange(offset, destinationLength))
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

} // namespace Crypto::PukccEcc

#endif /* CRYPTO_HARDWARE_AVAILABLE */

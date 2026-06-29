#pragma once

#include <Crypto.h>

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccEcc {

static constexpr uint16_t RedModSetupOption = 0x0100u;

/**
 * @brief PUKCC Crypto RAM near-pointer boundary for ECC services.
 *
 * These operation objects are service-specific PUKCL parameter blocks. Callers
 * own curve/key/signature layout in PUKCC Crypto RAM and pass near pointers
 * into these objects. The objects must remain alive until the PUKCC callback
 * fires because the ROM service reads the fields from PendSV context.
 */
struct ReductionSetupOperation {
  pukcc::ServiceParamHeader header;
  uint16_t modulus;
  uint16_t reductionConstant;
  uint16_t modulusLength;
  uint16_t scratchR;
  uint16_t padding0;
  uint16_t padding1;
  uint16_t scratchX;
};

struct EcdsaVerifyOperation {
  pukcc::ServiceParamHeader header;
  uint16_t basePoint;
  uint16_t order;
  uint16_t modulus;
  uint16_t reductionConstant;
  uint16_t publicKey;
  uint16_t signature;
  uint16_t curveA;
  uint16_t hash;
  uint16_t workspace;
  uint16_t modulusLength;
  uint16_t scalarLength;
  uint16_t padding;
};

struct EcdhMultiplyOperation {
  pukcc::ServiceParamHeader header;
  uint16_t point;
  uint16_t modulus;
  uint16_t reductionConstant;
  uint16_t scalar;
  uint16_t curveA;
  uint16_t workspace;
  uint16_t modulusLength;
  uint16_t scalarLength;
};

bool copyBigEndianToCryptoRam(uint16_t offset, uint16_t destinationLength,
                              const uint8_t *source, uint16_t sourceLength);
bool startReductionSetupAsync(ReductionSetupOperation &operation,
                              pukcc::ServiceResult &result);
bool startEcdsaVerifyAsync(EcdsaVerifyOperation &operation,
                           pukcc::ServiceResult &result);
bool startEcdhMultiplyAsync(EcdhMultiplyOperation &operation,
                            pukcc::ServiceResult &result);

} // namespace Crypto::PukccEcc

#endif /* CRYPTO_HARDWARE_AVAILABLE */

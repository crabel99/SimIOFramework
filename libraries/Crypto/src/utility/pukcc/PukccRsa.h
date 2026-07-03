#pragma once

#include "PukccEcc.h"

#include <Crypto.h>

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccRsa {

static constexpr uint16_t ExpModFastRsaOption = 0x0004u;
static constexpr uint16_t ExpModRegularRsaOption = 0x0001u;
static constexpr uint16_t ExpModExponentInPukccRamOption = 0x0002u;
static constexpr uint16_t ExpModWindowSize1Option = 0x0000u;

struct ExpModOperation {
  pukcc::ServiceParamHeader header;
  uint16_t message;
  uint16_t modulus;
  uint16_t reductionConstant;
  uint16_t precomp;
  const uint8_t *exponent;
  uint16_t modulusLength;
  uint16_t exponentLength;
  uint8_t blinding;
  uint8_t padding0;
  uint16_t padding1;
};

struct PublicExpModOperation;

using PublicExpModCallback =
    void (*)(bool success, pukcc::ServiceResult &result,
             PublicExpModOperation &operation, void *context);

enum class PublicExpModStep : uint8_t {
  Idle,
  ReductionSetup,
  Exponentiation,
  Complete,
  Error,
};

struct PublicExpModOperation {
  PukccEcc::ReductionSetupOperation reductionSetup;
  ExpModOperation exponentiation;
  const uint8_t *message = nullptr;
  uint16_t messageLength = 0;
  pukcc::ServiceResult result = {};
  PublicExpModCallback callback = nullptr;
  void *callbackContext = nullptr;
  PublicExpModStep step = PublicExpModStep::Idle;
  bool busy = false;
};

bool startExpModAsync(ExpModOperation &operation, pukcc::ServiceResult &result);
bool startPublicExpModAsync(PublicExpModOperation &operation,
                            PublicExpModCallback callback,
                            void *callbackContext = nullptr);

} // namespace Crypto::PukccRsa

#endif /* CRYPTO_HARDWARE_AVAILABLE */

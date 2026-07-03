#pragma once

#include "PukccEcc.h"

#include <Crypto.h>

#ifdef CRYPTO_HARDWARE_AVAILABLE

namespace Crypto::PukccRsa {

static constexpr uint16_t ExpModFastRsaOption = 0x0004u;
static constexpr uint16_t ExpModRegularRsaOption = 0x0001u;
static constexpr uint16_t ExpModExponentInPukccRamOption = 0x0002u;
static constexpr uint16_t ExpModWindowSize1Option = 0x0000u;
static constexpr uint16_t ExpModWindowSize2Option = 0x0008u;
static constexpr uint16_t ExpModWindowSize3Option = 0x0010u;
static constexpr uint16_t ExpModWindowSize4Option = 0x0018u;

enum class ExpModMode : uint16_t {
  Fast = ExpModFastRsaOption,
  Regular = ExpModRegularRsaOption,
};

enum class ExpModWindowSize : uint16_t {
  Bits1 = ExpModWindowSize1Option,
  Bits2 = ExpModWindowSize2Option,
  Bits3 = ExpModWindowSize3Option,
  Bits4 = ExpModWindowSize4Option,
};

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
  ExpModMode mode = ExpModMode::Fast;
  ExpModWindowSize windowSize = ExpModWindowSize::Bits1;
  bool busy = false;
};

bool startExpModAsync(ExpModOperation &operation, pukcc::ServiceResult &result);
bool startExpModAsync(ExpModOperation &operation, ExpModMode mode,
                      ExpModWindowSize windowSize,
                      pukcc::ServiceResult &result);
bool startPublicExpModAsync(PublicExpModOperation &operation,
                            PublicExpModCallback callback,
                            void *callbackContext = nullptr);

} // namespace Crypto::PukccRsa

#endif /* CRYPTO_HARDWARE_AVAILABLE */

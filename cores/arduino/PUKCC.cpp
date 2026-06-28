#include "PUKCC.h"

#if PUKCC_AVAILABLE

namespace {
inline volatile uint32_t &statusRegister() {
  return *reinterpret_cast<volatile uint32_t *>(pukcc::StatusRegisterAddress);
}

struct PukclHeader {
  uint8_t service;
  uint8_t subService;
  uint16_t option;
  uint32_t specific;
  uint16_t status;
  uint16_t reserved16;
  uint32_t reserved32;
};

struct PukclSelfTest {
  uint32_t libraryVersion;
  uint32_t hardwareVersion;
  uint32_t check1;
  uint32_t check2;
  uint8_t step;
};

struct PukclSelfTestParam {
  PukclHeader header;
  PukclSelfTest selfTest;
};

struct PukclFill {
  uint16_t reserved0;
  uint16_t reserved1;
  uint16_t reserved2;
  uint16_t reserved3;
  uint16_t reserved4;
  uint16_t reserved5;
  uint16_t rBase;
  uint16_t rLength;
  uint32_t fillValue;
};

struct PukclFillParam {
  PukclHeader header;
  PukclFill fill;
};

static_assert(sizeof(PukclHeader) == 16,
              "PUKCL header layout must match the ROM ABI");
static_assert(sizeof(PukclFill) == 20,
              "PUKCL Fill layout must match the ROM ABI");

using PukclFunction = void (*)(PukclSelfTestParam *);
using PukclHeaderFunction = void (*)(PukclHeader *);
using PukclFillFunction = void (*)(PukclFillParam *);

inline PukclFunction selfTestFunction() {
  return reinterpret_cast<PukclFunction>(pukcc::SelfTestFunctionAddress);
}

inline PukclHeaderFunction clearFlagsFunction() {
  return reinterpret_cast<PukclHeaderFunction>(pukcc::ClearFlagsFunctionAddress);
}

inline PukclFillFunction fillFunction() {
  return reinterpret_cast<PukclFillFunction>(pukcc::FillFunctionAddress);
}
} // namespace

int pukcc::irqNumber() { return static_cast<int>(PUKCC_IRQn); }

bool pukcc::begin(uint32_t loopBudget) {
  enableClock();
  return waitForRamClear(loopBudget);
}

void pukcc::end() { disableClock(); }

void pukcc::enableClock() {
#if defined(MCLK_AHBMASK_PUKCC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_AHBMASK |= MCLK_AHBMASK_PUKCC_Msk;
#else
  MCLK->AHBMASK.reg |= MCLK_AHBMASK_PUKCC_Msk;
#endif
#endif
}

void pukcc::disableClock() {
#if defined(MCLK_AHBMASK_PUKCC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_AHBMASK &= ~MCLK_AHBMASK_PUKCC_Msk;
#else
  MCLK->AHBMASK.reg &= ~MCLK_AHBMASK_PUKCC_Msk;
#endif
#endif
}

uint32_t pukcc::status() { return statusRegister(); }

bool pukcc::ramClearBusy() {
  return (status() & ClearRamBusyMask) != 0u;
}

bool pukcc::waitForRamClear(uint32_t loopBudget) {
  while (ramClearBusy() && (loopBudget > 0u)) {
    --loopBudget;
  }
  return !ramClearBusy();
}

bool pukcc::ready() { return !ramClearBusy(); }

bool pukcc::selfTest(SelfTestResult &result, uint32_t loopBudget) {
  result = {};
  if (!begin(loopBudget)) {
    result.status = StatusComputationNotStarted;
    return false;
  }

  PukclSelfTestParam param = {};
  param.header.service = SelfTestServiceId;
  param.header.status = StatusComputationNotStarted;

  selfTestFunction()(&param);

  result.status = param.header.status;
  result.libraryVersion = param.selfTest.libraryVersion;
  result.hardwareVersion = param.selfTest.hardwareVersion;
  result.check1 = param.selfTest.check1;
  result.check2 = param.selfTest.check2;
  result.step = param.selfTest.step;

  return result.status == StatusOk && result.check1 == SelfTestExpectedCheck1 &&
         result.check2 == SelfTestExpectedCheck2 &&
         result.step == SelfTestExpectedStep;
}

bool pukcc::clearFlags(uint32_t initialFlags, ServiceResult &result) {
  result = {};
  if (!begin()) {
    result.status = StatusComputationNotStarted;
    return false;
  }

  PukclHeader header = {};
  header.service = ClearFlagsServiceId;
  header.specific = initialFlags;
  header.status = StatusComputationNotStarted;

  clearFlagsFunction()(&header);

  result.service = header.service;
  result.status = header.status;
  result.specific = header.specific;
  return result.status == StatusOk;
}

volatile uint8_t *pukcc::cryptoRam(uint16_t offset) {
  return reinterpret_cast<volatile uint8_t *>(cryptoRamBaseAddress() + offset);
}

bool pukcc::validCryptoRamRange(uint16_t offset, uint16_t length) {
  if ((offset & 0x3u) != 0u || (length & 0x3u) != 0u)
    return false;
  if (length < 4u || length > CryptoRamUsableSize)
    return false;
  return offset <= CryptoRamUsableSize &&
         static_cast<uint32_t>(offset) + length <= CryptoRamUsableSize;
}

uint16_t pukcc::cryptoRamNearPointer(uint16_t offset) {
  return CryptoRamNearBase + offset;
}

bool pukcc::fillCryptoRam(uint16_t offset, uint16_t length,
                          uint32_t fillValue, ServiceResult &result) {
  result = {};
  result.service = FillServiceId;

  if ((offset & 0x3u) != 0u) {
    result.status = StatusParameterBadAlignment;
    return false;
  }
  if ((length & 0x3u) != 0u || length < 4u || length > CryptoRamUsableSize) {
    result.status = StatusParameterWrongLength;
    return false;
  }
  if (!validCryptoRamRange(offset, length)) {
    result.status = StatusParameterNotInPukccRam;
    return false;
  }
  if (!begin()) {
    result.status = StatusComputationNotStarted;
    return false;
  }

  PukclFillParam param = {};
  param.header.service = FillServiceId;
  param.header.status = StatusComputationNotStarted;
  param.fill.rBase = cryptoRamNearPointer(offset);
  param.fill.rLength = length;
  param.fill.fillValue = fillValue;

  fillFunction()(&param);

  result.service = param.header.service;
  result.status = param.header.status;
  result.specific = param.header.specific;
  return result.status == StatusOk;
}

#endif /* PUKCC_AVAILABLE */

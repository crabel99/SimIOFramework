#include "PUKCC.h"

#if PUKCC_AVAILABLE

namespace {
inline volatile uint32_t &statusRegister() {
  return *reinterpret_cast<volatile uint32_t *>(pukcc::StatusRegisterAddress);
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
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

enum class PendingOperation : uint8_t {
  None,
  SelfTest,
  ClearFlags,
  Fill,
};

struct AsyncState {
  pukcc::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  pukcc::SelfTestResult *selfTestResult = nullptr;
  pukcc::ServiceResult *serviceResult = nullptr;
  uint32_t initialFlags = 0;
  uint16_t offset = 0;
  uint16_t length = 0;
  uint32_t fillValue = 0;
  PendingOperation operation = PendingOperation::None;
  bool serviceRegistered = false;
  bool busy = false;
};

AsyncState asyncState;

void completeAsync(uint8_t serviceId, uint16_t status) {
  pukcc::EventCallback callback = nullptr;
  void *callbackContext = nullptr;

  const uint32_t primask = enterCritical();
  callback = asyncState.callback;
  callbackContext = asyncState.callbackContext;
  asyncState.operation = PendingOperation::None;
  asyncState.selfTestResult = nullptr;
  asyncState.serviceResult = nullptr;
  asyncState.busy = false;
  exitCritical(primask);

  pukcc::EventMask events = pukcc::statusIsOk(status) ? pukcc::EventComplete
                                                       : pukcc::EventError;
  if (callback != nullptr)
    callback(events, serviceId, status, callbackContext);
}

void pukccPendSvService(uint8_t serviceId, void *context) {
  (void)serviceId;
  (void)context;

  PendingOperation operation = PendingOperation::None;
  pukcc::SelfTestResult *selfTestResult = nullptr;
  pukcc::ServiceResult *serviceResult = nullptr;
  uint32_t initialFlags = 0;
  uint16_t offset = 0;
  uint16_t length = 0;
  uint32_t fillValue = 0;

  uint32_t primask = enterCritical();
  operation = asyncState.operation;
  selfTestResult = asyncState.selfTestResult;
  serviceResult = asyncState.serviceResult;
  initialFlags = asyncState.initialFlags;
  offset = asyncState.offset;
  length = asyncState.length;
  fillValue = asyncState.fillValue;
  exitCritical(primask);

  if (operation == PendingOperation::None)
    return;

  pukcc::enableClock();
  if (pukcc::ramClearBusy()) {
    PendSV::instance().setPending(pukcc::pendSvServiceId());
    return;
  }

  switch (operation) {
  case PendingOperation::SelfTest: {
    if (selfTestResult == nullptr) {
      completeAsync(pukcc::SelfTestServiceId,
                    pukcc::StatusComputationNotStarted);
      return;
    }

    PukclSelfTestParam param = {};
    param.header.service = pukcc::SelfTestServiceId;
    param.header.status = pukcc::StatusComputationNotStarted;
    selfTestFunction()(&param);

    selfTestResult->status = param.header.status;
    selfTestResult->libraryVersion = param.selfTest.libraryVersion;
    selfTestResult->hardwareVersion = param.selfTest.hardwareVersion;
    selfTestResult->check1 = param.selfTest.check1;
    selfTestResult->check2 = param.selfTest.check2;
    selfTestResult->step = param.selfTest.step;
    completeAsync(pukcc::SelfTestServiceId, selfTestResult->status);
    return;
  }
  case PendingOperation::ClearFlags: {
    if (serviceResult == nullptr) {
      completeAsync(pukcc::ClearFlagsServiceId,
                    pukcc::StatusComputationNotStarted);
      return;
    }

    PukclHeader header = {};
    header.service = pukcc::ClearFlagsServiceId;
    header.specific = initialFlags;
    header.status = pukcc::StatusComputationNotStarted;
    clearFlagsFunction()(&header);

    serviceResult->service = header.service;
    serviceResult->status = header.status;
    serviceResult->specific = header.specific;
    completeAsync(pukcc::ClearFlagsServiceId, serviceResult->status);
    return;
  }
  case PendingOperation::Fill: {
    if (serviceResult == nullptr) {
      completeAsync(pukcc::FillServiceId, pukcc::StatusComputationNotStarted);
      return;
    }

    PukclFillParam param = {};
    param.header.service = pukcc::FillServiceId;
    param.header.status = pukcc::StatusComputationNotStarted;
    param.fill.rBase = pukcc::cryptoRamNearPointer(offset);
    param.fill.rLength = length;
    param.fill.fillValue = fillValue;
    fillFunction()(&param);

    serviceResult->service = param.header.service;
    serviceResult->status = param.header.status;
    serviceResult->specific = param.header.specific;
    completeAsync(pukcc::FillServiceId, serviceResult->status);
    return;
  }
  case PendingOperation::None:
    return;
  }
}

bool ensurePendSvServiceRegistered() {
  if (asyncState.serviceRegistered)
    return true;

  const bool registered = PendSV::instance().registerService(
      pukcc::pendSvServiceId(), pukccPendSvService);
  if (registered)
    asyncState.serviceRegistered = true;
  return registered;
}
} // namespace

int pukcc::irqNumber() { return static_cast<int>(PUKCC_IRQn); }

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

bool pukcc::ready() { return !ramClearBusy(); }

pukcc::StatusSeverity pukcc::statusSeverity(uint16_t serviceStatus) {
  if (serviceStatus == StatusOk)
    return StatusSeverity::Ok;

  switch (serviceStatus & StatusSeverityMask) {
  case 0x4000u:
    return StatusSeverity::Information;
  case 0x8000u:
    return StatusSeverity::Warning;
  case 0xC000u:
    return StatusSeverity::Severe;
  default:
    return StatusSeverity::Ok;
  }
}

uint16_t pukcc::statusReason(uint16_t serviceStatus) {
  return serviceStatus & StatusReasonMask;
}

bool pukcc::statusIsOk(uint16_t serviceStatus) {
  return serviceStatus == StatusOk;
}

bool pukcc::statusIsInformation(uint16_t serviceStatus) {
  return statusSeverity(serviceStatus) == StatusSeverity::Information;
}

bool pukcc::statusIsWarning(uint16_t serviceStatus) {
  return statusSeverity(serviceStatus) == StatusSeverity::Warning;
}

bool pukcc::statusIsSevere(uint16_t serviceStatus) {
  return statusSeverity(serviceStatus) == StatusSeverity::Severe;
}

uintptr_t pukcc::serviceFunctionAddress(uint8_t serviceId) {
  switch (serviceId) {
  case ClearFlagsServiceId:
    return ClearFlagsFunctionAddress;
  case SelfTestServiceId:
    return SelfTestFunctionAddress;
  case RngServiceId:
    return RngFunctionAddress;
  case ExpModServiceId:
    return ExpModFunctionAddress;
  case ZpEcDsaGenerateServiceId:
    return ZpEcDsaGenerateFunctionAddress;
  case ZpEcDsaVerifyServiceId:
    return ZpEcDsaVerifyFunctionAddress;
  case FillServiceId:
    return FillFunctionAddress;
  default:
    return 0u;
  }
}

bool pukcc::serviceHasKnownEntry(uint8_t serviceId) {
  return serviceFunctionAddress(serviceId) != 0u;
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

bool pukcc::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  asyncState.callback = callback;
  asyncState.callbackContext = context;
  exitCritical(primask);
  return true;
}

void pukcc::clearEventCallback() {
  const uint32_t primask = enterCritical();
  asyncState.callback = nullptr;
  asyncState.callbackContext = nullptr;
  asyncState.selfTestResult = nullptr;
  asyncState.serviceResult = nullptr;
  asyncState.operation = PendingOperation::None;
  asyncState.busy = false;
  exitCritical(primask);
  PendSV::instance().clearService(pendSvServiceId());
  asyncState.serviceRegistered = false;
}

bool pukcc::selfTestAsync(SelfTestResult &result) {
  if (!ensurePendSvServiceRegistered())
    return false;

  result = {};
  const uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.selfTestResult = &result;
  asyncState.serviceResult = nullptr;
  asyncState.operation = PendingOperation::SelfTest;
  asyncState.busy = true;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
  return true;
}

bool pukcc::clearFlagsAsync(uint32_t initialFlags, ServiceResult &result) {
  if (!ensurePendSvServiceRegistered())
    return false;

  result = {};
  result.service = ClearFlagsServiceId;
  const uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.selfTestResult = nullptr;
  asyncState.serviceResult = &result;
  asyncState.initialFlags = initialFlags;
  asyncState.operation = PendingOperation::ClearFlags;
  asyncState.busy = true;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
  return true;
}

bool pukcc::fillCryptoRamAsync(uint16_t offset, uint16_t length,
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
  if (!ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.selfTestResult = nullptr;
  asyncState.serviceResult = &result;
  asyncState.offset = offset;
  asyncState.length = length;
  asyncState.fillValue = fillValue;
  asyncState.operation = PendingOperation::Fill;
  asyncState.busy = true;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
  return true;
}

bool pukcc::asyncBusy() {
  const uint32_t primask = enterCritical();
  const bool busy = asyncState.busy;
  exitCritical(primask);
  return busy;
}

void pukcc::handleInterrupt() {
  PendSV::instance().setPending(pendSvServiceId());
}

extern "C" void PUKCC_Handler(void) {
  pukcc::handleInterrupt();
}

#endif /* PUKCC_AVAILABLE */

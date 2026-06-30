#include "RTC.h"

#if RTC_AVAILABLE

namespace {
#if defined(RTC_REGS) && defined(RTC_MODE0_CTRLA_ENABLE_Msk)
#define SIMIO_RTC_NEW_CTRLA_REGS 1
inline rtc_registers_t *regs() { return RTC_REGS; }
#elif defined(RTC_MODE0_CTRLA_ENABLE)
#define SIMIO_RTC_OLD_CTRLA_REGS 1
inline Rtc *regs() { return reinterpret_cast<Rtc *>(RTC_PERIPH); }
#elif defined(RTC_MODE0_CTRL_ENABLE)
#define SIMIO_RTC_CTRL_REGS 1
inline Rtc *regs() { return reinterpret_cast<Rtc *>(RTC_PERIPH); }
#else
#error "Unsupported RTC CMSIS register layout"
#endif

#if defined(RTC_MODE0_CTRLA_ENABLE_Msk)
constexpr uint16_t kCtrlEnable = RTC_MODE0_CTRLA_ENABLE_Msk;
constexpr uint16_t kCtrlModeCount32 = RTC_MODE0_CTRLA_MODE_COUNT32;
constexpr uint16_t kCtrlPrescalerDiv1024 = RTC_MODE0_CTRLA_PRESCALER_DIV1024;
constexpr uint16_t kCtrlCountSync = RTC_MODE0_CTRLA_COUNTSYNC_Msk;
constexpr uint32_t kSyncEnable = RTC_MODE0_SYNCBUSY_ENABLE_Msk;
constexpr uint32_t kSyncCount = RTC_MODE0_SYNCBUSY_COUNT_Msk;
constexpr uint32_t kSyncComp0 = RTC_MODE0_SYNCBUSY_COMP0_Msk;
constexpr uint32_t kSyncCountSync = RTC_MODE0_SYNCBUSY_COUNTSYNC_Msk;
#elif defined(RTC_MODE0_CTRLA_ENABLE)
constexpr uint16_t kCtrlEnable = RTC_MODE0_CTRLA_ENABLE;
constexpr uint16_t kCtrlModeCount32 = RTC_MODE0_CTRLA_MODE_COUNT32;
constexpr uint16_t kCtrlPrescalerDiv1024 = RTC_MODE0_CTRLA_PRESCALER_DIV1024;
constexpr uint16_t kCtrlCountSync = RTC_MODE0_CTRLA_COUNTSYNC;
constexpr uint32_t kSyncEnable = RTC_MODE0_SYNCBUSY_ENABLE;
constexpr uint32_t kSyncCount = RTC_MODE0_SYNCBUSY_COUNT;
constexpr uint32_t kSyncComp0 = RTC_MODE0_SYNCBUSY_COMP0;
constexpr uint32_t kSyncCountSync = RTC_MODE0_SYNCBUSY_COUNTSYNC;
#endif

uint16_t controlReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE0.RTC_CTRLA;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  return regs()->MODE0.CTRLA.reg;
#else
  return regs()->MODE0.CTRL.reg;
#endif
}

void writeControl(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_CTRLA = value;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  regs()->MODE0.CTRLA.reg = value;
#else
  regs()->MODE0.CTRL.reg = value;
#endif
}

void setControlBits(uint16_t mask) { writeControl(controlReg() | mask); }

void clearControlBits(uint16_t mask) { writeControl(controlReg() & ~mask); }

uint32_t syncBusyReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE0.RTC_SYNCBUSY;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  return regs()->MODE0.SYNCBUSY.reg;
#else
  return regs()->MODE0.STATUS.bit.SYNCBUSY;
#endif
}

uint32_t countReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE0.RTC_COUNT;
#else
  return regs()->MODE0.COUNT.reg;
#endif
}

void writeCount(uint32_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_COUNT = value;
#else
  regs()->MODE0.COUNT.reg = value;
#endif
}

void writeCompare0(uint32_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_COMP[0] = value;
#else
  regs()->MODE0.COMP[0].reg = value;
#endif
}

uint16_t interruptFlagReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE0.RTC_INTFLAG;
#else
  return regs()->MODE0.INTFLAG.reg;
#endif
}

void writeInterruptFlag(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_INTFLAG = value;
#else
  regs()->MODE0.INTFLAG.reg = value;
#endif
}

void writeInterruptEnableSet(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_INTENSET = value;
#else
  regs()->MODE0.INTENSET.reg = value;
#endif
}

void writeInterruptEnableClear(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE0.RTC_INTENCLR = value;
#else
  regs()->MODE0.INTENCLR.reg = value;
#endif
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) { __set_PRIMASK(primask); }

struct RtcState {
  rtc::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint8_t pendingEvents = rtc::EventNone;
  uint64_t pendingUnixTime = 0;
  uint64_t unixTime = 0;
  bool serviceRegistered = false;
  rtc::TimeState timeState = rtc::TimeState::Unset;
  rtc::Error lastError = rtc::Error::None;
};

RtcState rtcState;

bool waitSync(uint32_t mask) {
  for (uint32_t attempt = 0; attempt < 100000u; ++attempt) {
#if defined(SIMIO_RTC_CTRL_REGS)
    (void)mask;
    if (syncBusyReg() == 0)
      return true;
#else
    if ((syncBusyReg() & mask) == 0)
      return true;
#endif
  }
  return false;
}

void queueEvent(uint8_t events, uint64_t unixTime) {
  const uint32_t primask = enterCritical();
  rtcState.pendingEvents |= events;
  rtcState.pendingUnixTime = unixTime;
  exitCritical(primask);
  PendSV::instance().setPending(rtc::pendSvServiceId());
}

void rtcPendSvService(uint8_t serviceId, void *context) {
  (void)serviceId;
  (void)context;

  rtc::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint8_t events = rtc::EventNone;
  uint64_t unixTime = 0;

  const uint32_t primask = enterCritical();
  callback = rtcState.callback;
  callbackContext = rtcState.callbackContext;
  events = rtcState.pendingEvents;
  unixTime = rtcState.pendingUnixTime;
  rtcState.pendingEvents = rtc::EventNone;
  exitCritical(primask);

  if (callback != nullptr && events != rtc::EventNone)
    callback(events, unixTime, callbackContext);
}

bool ensurePendSvServiceRegistered() {
  if (rtcState.serviceRegistered)
    return true;

  const bool registered =
      PendSV::instance().registerService(rtc::pendSvServiceId(),
                                         rtcPendSvService);
  if (registered)
    rtcState.serviceRegistered = true;
  return registered;
}

bool configureGenericClock() {
#if defined(SIMIO_RTC_CTRL_REGS)
  GCLK->CLKCTRL.reg =
      static_cast<uint16_t>(GCLK_CLKCTRL_ID_RTC | GCLK_CLKCTRL_GEN_GCLK1 |
                            GCLK_CLKCTRL_CLKEN);
  while (GCLK->STATUS.bit.SYNCBUSY != 0) {
  }
  return true;
#elif defined(GCLK_REGS) && defined(GCLK_PCHCTRL_CHEN_Msk) && defined(ID_RTC)
  GCLK_REGS->GCLK_PCHCTRL[ID_RTC] =
      GCLK_PCHCTRL_GEN_GCLK3 | GCLK_PCHCTRL_CHEN_Msk;
  for (uint32_t attempt = 0; attempt < 100000u; ++attempt) {
    if ((GCLK_REGS->GCLK_PCHCTRL[ID_RTC] & GCLK_PCHCTRL_CHEN_Msk) != 0u)
      return true;
  }
  return false;
#elif defined(GCLK) && defined(GCLK_PCHCTRL_CHEN) && defined(ID_RTC)
  GCLK->PCHCTRL[ID_RTC].reg = GCLK_PCHCTRL_GEN_GCLK3 | GCLK_PCHCTRL_CHEN;
  for (uint32_t attempt = 0; attempt < 100000u; ++attempt) {
    if ((GCLK->PCHCTRL[ID_RTC].reg & GCLK_PCHCTRL_CHEN) != 0u)
      return true;
  }
  return false;
#else
  return false;
#endif
}
} // namespace

int rtc::irqNumber() { return static_cast<int>(RTC_IRQn); }

bool rtc::available() { return true; }

void rtc::enableClock() {
#if defined(SIMIO_RTC_CTRL_REGS)
  PM->APBAMASK.reg |= PM_APBAMASK_RTC;
#elif defined(MCLK_REGS) && defined(MCLK_APBAMASK_RTC_Msk)
  MCLK_REGS->MCLK_APBAMASK |= MCLK_APBAMASK_RTC_Msk;
#elif defined(MCLK_APBAMASK_RTC)
  MCLK->APBAMASK.reg |= MCLK_APBAMASK_RTC;
#endif
}

void rtc::disableClock() {
#if defined(SIMIO_RTC_CTRL_REGS)
  PM->APBAMASK.reg &= ~PM_APBAMASK_RTC;
#elif defined(MCLK_REGS) && defined(MCLK_APBAMASK_RTC_Msk)
  MCLK_REGS->MCLK_APBAMASK &= ~MCLK_APBAMASK_RTC_Msk;
#elif defined(MCLK_APBAMASK_RTC)
  MCLK->APBAMASK.reg &= ~MCLK_APBAMASK_RTC;
#endif
}

bool rtc::begin(bool runStandby) {
  (void)runStandby;
  if (!ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::PendSvRegistrationFailed;
    return false;
  }

  enableClock();
  if (!configureGenericClock()) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  disableInterrupts(Compare0Interrupt);
  clearInterruptFlags(Compare0Interrupt);

#if defined(SIMIO_RTC_CTRL_REGS)
  if ((controlReg() & RTC_MODE0_CTRL_ENABLE) == 0u) {
    writeControl(RTC_MODE0_CTRL_MODE_COUNT32 | RTC_MODE0_CTRL_PRESCALER_DIV1024);
    if (!waitSync(0)) {
      rtcState.lastError = Error::CountSyncTimeout;
      return false;
    }
    regs()->MODE0.READREQ.reg = RTC_READREQ_RCONT | RTC_READREQ_ADDR(0x10);
    writeCount(0);
    if (!waitSync(0)) {
      rtcState.lastError = Error::CountWriteTimeout;
      return false;
    }
    setControlBits(RTC_MODE0_CTRL_ENABLE);
    if (!waitSync(0)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }
#else
  if ((controlReg() & kCtrlEnable) == 0u) {
    writeControl(kCtrlModeCount32 | kCtrlPrescalerDiv1024 | kCtrlCountSync);
    if (!waitSync(kSyncCountSync)) {
      rtcState.lastError = Error::CountSyncTimeout;
      return false;
    }
    writeCount(0);
    if (!waitSync(kSyncCount)) {
      rtcState.lastError = Error::CountWriteTimeout;
      return false;
    }
    setControlBits(kCtrlEnable);
    if (!waitSync(kSyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }
#endif

  if (!scheduleSecondTick()) {
    rtcState.lastError = Error::ScheduleFailed;
    return false;
  }
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  enableInterrupts(Compare0Interrupt);
  rtcState.lastError = Error::None;
  return true;
}

void rtc::end() {
  disableInterrupts(Compare0Interrupt);
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
#if defined(SIMIO_RTC_CTRL_REGS)
  clearControlBits(RTC_MODE0_CTRL_ENABLE);
  waitSync(0);
#else
  clearControlBits(kCtrlEnable);
  waitSync(kSyncEnable);
#endif
}

bool rtc::enabled() {
#if defined(SIMIO_RTC_CTRL_REGS)
  return (controlReg() & RTC_MODE0_CTRL_ENABLE) != 0u;
#else
  return (controlReg() & kCtrlEnable) != 0u;
#endif
}

bool rtc::setUnixTime(uint64_t unixTime, TimeState state) {
  if (unixTime == 0) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }
  if (!begin())
    return false;

  const uint32_t primask = enterCritical();
  if (rtcState.timeState == TimeState::Trusted && state != TimeState::Trusted) {
    rtcState.lastError = Error::TrustedAuthorityRejected;
    exitCritical(primask);
    return false;
  }

  rtcState.unixTime = unixTime;
  rtcState.timeState = state == TimeState::Unset ? TimeState::Manual : state;
  rtcState.lastError = Error::None;
  exitCritical(primask);

  if (!scheduleSecondTick()) {
    rtcState.lastError = Error::ScheduleFailed;
    return false;
  }

  queueEvent(EventTimeSet, unixTime);
  return true;
}

bool rtc::unixTime(uint64_t &unixTimeOut) {
  const uint32_t primask = enterCritical();
  const bool configured = rtcState.timeState != TimeState::Unset;
  unixTimeOut = rtcState.unixTime;
  exitCritical(primask);
  return configured;
}

bool rtc::trustedUnixTime(uint64_t &unixTimeOut) {
  const uint32_t primask = enterCritical();
  const bool configured = rtcState.timeState == TimeState::Trusted;
  unixTimeOut = rtcState.unixTime;
  exitCritical(primask);
  return configured;
}

bool rtc::trusted() {
  const uint32_t primask = enterCritical();
  const bool result = rtcState.timeState == TimeState::Trusted;
  exitCritical(primask);
  return result;
}

rtc::TimeState rtc::timeState() {
  const uint32_t primask = enterCritical();
  const TimeState result = rtcState.timeState;
  exitCritical(primask);
  return result;
}

rtc::Error rtc::lastError() {
  const uint32_t primask = enterCritical();
  const Error result = rtcState.lastError;
  exitCritical(primask);
  return result;
}

void rtc::clearTime() {
  const uint32_t primask = enterCritical();
  rtcState.unixTime = 0;
  rtcState.timeState = TimeState::Unset;
  rtcState.lastError = Error::None;
  exitCritical(primask);
}

void rtc::clearTrusted() {
  const uint32_t primask = enterCritical();
  if (rtcState.timeState == TimeState::Trusted)
    rtcState.timeState = TimeState::Manual;
  exitCritical(primask);
}

uint32_t rtc::counter() {
#if defined(SIMIO_RTC_CTRL_REGS)
  regs()->MODE0.READREQ.reg = RTC_READREQ_RREQ | RTC_READREQ_ADDR(0x10);
  waitSync(0);
#else
  setControlBits(kCtrlCountSync);
  waitSync(kSyncCountSync);
#endif
  return countReg();
}

bool rtc::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  rtcState.callback = callback;
  rtcState.callbackContext = context;
  rtcState.pendingEvents = EventNone;
  exitCritical(primask);
  return true;
}

void rtc::clearEventCallback() {
  const uint32_t primask = enterCritical();
  rtcState.callback = nullptr;
  rtcState.callbackContext = nullptr;
  rtcState.pendingEvents = EventNone;
  exitCritical(primask);
  PendSV::instance().clearService(pendSvServiceId());
  rtcState.serviceRegistered = false;
}

uint16_t rtc::interruptFlags() {
  return interruptFlagReg();
}

void rtc::clearInterruptFlags(uint16_t flags) {
  writeInterruptFlag(flags);
}

void rtc::enableInterrupts(uint16_t mask) { writeInterruptEnableSet(mask); }

void rtc::disableInterrupts(uint16_t mask) { writeInterruptEnableClear(mask); }

bool rtc::scheduleSecondTick() {
  if (!enabled())
    return false;

  const uint32_t next = counter() + TicksPerSecond;
  writeCompare0(next);
#if defined(SIMIO_RTC_CTRL_REGS)
  return waitSync(0);
#else
  return waitSync(kSyncComp0);
#endif
}

void rtc::handleInterrupt() {
  const uint16_t flags = interruptFlags();
  const uint16_t handled = flags & Compare0Interrupt;
  if (handled == 0u)
    return;

  clearInterruptFlags(handled);
  scheduleSecondTick();

  uint64_t unixTime = 0;
  bool configured = false;
  const uint32_t primask = enterCritical();
  if (rtcState.timeState != TimeState::Unset) {
    ++rtcState.unixTime;
    unixTime = rtcState.unixTime;
    configured = true;
  }
  exitCritical(primask);

  if (configured)
    queueEvent(EventSecond, unixTime);
}

extern "C" void RTC_Handler(void) { rtc::handleInterrupt(); }

#endif /* RTC_AVAILABLE */

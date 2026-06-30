#include "RTC.h"

#if RTC_AVAILABLE

namespace {
#if defined(RTC_REGS) && defined(RTC_MODE2_CTRLA_ENABLE_Msk)
#define SIMIO_RTC_NEW_CTRLA_REGS 1
inline rtc_registers_t *regs() { return RTC_REGS; }
#elif defined(RTC_MODE2_CTRLA_ENABLE)
#define SIMIO_RTC_OLD_CTRLA_REGS 1
inline Rtc *regs() { return reinterpret_cast<Rtc *>(RTC_PERIPH); }
#elif defined(RTC_MODE2_CTRL_ENABLE)
#define SIMIO_RTC_CTRL_REGS 1
inline Rtc *regs() { return reinterpret_cast<Rtc *>(RTC_PERIPH); }
#else
#error "Unsupported RTC CMSIS register layout"
#endif

#if defined(RTC_MODE2_CTRLA_ENABLE_Msk)
constexpr uint16_t kCtrlEnable = RTC_MODE2_CTRLA_ENABLE_Msk;
constexpr uint8_t kCtrlModePosition = RTC_MODE2_CTRLA_MODE_Pos;
constexpr uint16_t kCtrlPrescalerDiv1024 =
    RTC_MODE2_CTRLA_PRESCALER_DIV1024;
constexpr uint32_t kSyncEnable = RTC_MODE2_SYNCBUSY_ENABLE_Msk;
constexpr uint32_t kSyncClock = RTC_MODE2_SYNCBUSY_CLOCK_Msk;
#elif defined(RTC_MODE2_CTRLA_ENABLE)
constexpr uint16_t kCtrlEnable = RTC_MODE2_CTRLA_ENABLE;
constexpr uint8_t kCtrlModePosition = RTC_MODE2_CTRLA_MODE_Pos;
constexpr uint16_t kCtrlPrescalerDiv1024 =
    RTC_MODE2_CTRLA_PRESCALER_DIV1024;
constexpr uint32_t kSyncEnable = RTC_MODE2_SYNCBUSY_ENABLE;
constexpr uint32_t kSyncClock = RTC_MODE2_SYNCBUSY_CLOCK;
#else
constexpr uint16_t kCtrlEnable = RTC_MODE2_CTRL_ENABLE;
constexpr uint8_t kCtrlModePosition = RTC_MODE2_CTRL_MODE_Pos;
constexpr uint16_t kCtrlPrescalerDiv1024 = RTC_MODE2_CTRL_PRESCALER_DIV1024;
constexpr uint32_t kSyncEnable = 0;
constexpr uint32_t kSyncClock = 0;
#endif

constexpr uint16_t controlModeBits(rtc::OperatingMode mode) {
  return static_cast<uint16_t>(static_cast<uint16_t>(mode)
                              << kCtrlModePosition);
}

constexpr uint16_t kCtrlModeClock =
    controlModeBits(rtc::OperatingMode::Clock);

#if defined(RTC_MODE2_INTFLAG_PER0_Msk)
constexpr uint16_t kPeriodic0Interrupt = RTC_MODE2_INTFLAG_PER0_Msk;
#elif defined(RTC_MODE2_INTFLAG_PER0)
constexpr uint16_t kPeriodic0Interrupt = RTC_MODE2_INTFLAG_PER0;
#else
constexpr uint16_t kPeriodic0Interrupt = 0;
#endif

#if defined(RTC_MODE2_INTFLAG_PER_Msk)
constexpr uint16_t kPeriodicInterruptMask = RTC_MODE2_INTFLAG_PER_Msk;
#else
constexpr uint16_t kPeriodicInterruptMask = 0;
#endif

#if defined(RTC_MODE2_INTFLAG_ALARM0_Msk)
constexpr uint16_t kAlarm0Interrupt = RTC_MODE2_INTFLAG_ALARM0_Msk;
#elif defined(RTC_MODE2_INTFLAG_ALARM0)
constexpr uint16_t kAlarm0Interrupt = RTC_MODE2_INTFLAG_ALARM0;
#else
constexpr uint16_t kAlarm0Interrupt = 0;
#endif

#if defined(RTC_MODE2_INTFLAG_ALARM1_Msk)
constexpr uint16_t kAlarm1Interrupt = RTC_MODE2_INTFLAG_ALARM1_Msk;
#elif defined(RTC_MODE2_INTFLAG_ALARM1)
constexpr uint16_t kAlarm1Interrupt = RTC_MODE2_INTFLAG_ALARM1;
#else
constexpr uint16_t kAlarm1Interrupt = 0;
#endif

#if defined(RTC_MODE2_INTFLAG_OVF_Msk)
constexpr uint16_t kOverflowInterrupt = RTC_MODE2_INTFLAG_OVF_Msk;
#elif defined(RTC_MODE2_INTFLAG_OVF)
constexpr uint16_t kOverflowInterrupt = RTC_MODE2_INTFLAG_OVF;
#else
constexpr uint16_t kOverflowInterrupt = 0;
#endif

constexpr uint16_t kBaseInterruptMask =
    kPeriodic0Interrupt | kAlarm0Interrupt | kAlarm1Interrupt |
    kOverflowInterrupt;

uint16_t controlReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE2.RTC_CTRLA;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  return regs()->MODE2.CTRLA.reg;
#else
  return regs()->MODE2.CTRL.reg;
#endif
}

void writeControl(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE2.RTC_CTRLA = value;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  regs()->MODE2.CTRLA.reg = value;
#else
  regs()->MODE2.CTRL.reg = value;
#endif
}

void setControlBits(uint16_t mask) { writeControl(controlReg() | mask); }

void clearControlBits(uint16_t mask) { writeControl(controlReg() & ~mask); }

uint32_t syncBusyReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE2.RTC_SYNCBUSY;
#elif defined(SIMIO_RTC_OLD_CTRLA_REGS)
  return regs()->MODE2.SYNCBUSY.reg;
#else
  return regs()->MODE2.STATUS.bit.SYNCBUSY;
#endif
}

uint32_t clockReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE2.RTC_CLOCK;
#else
  return regs()->MODE2.CLOCK.reg;
#endif
}

void writeClock(uint32_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE2.RTC_CLOCK = value;
#else
  regs()->MODE2.CLOCK.reg = value;
#endif
}

uint16_t interruptFlagReg() {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  return regs()->MODE2.RTC_INTFLAG;
#else
  return regs()->MODE2.INTFLAG.reg;
#endif
}

void writeInterruptFlag(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE2.RTC_INTFLAG = value;
#else
  regs()->MODE2.INTFLAG.reg = value;
#endif
}

void writeInterruptEnableSet(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE2.RTC_INTENSET = value;
#else
  regs()->MODE2.INTENSET.reg = value;
#endif
}

void writeInterruptEnableClear(uint16_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  regs()->MODE2.RTC_INTENCLR = value;
#else
  regs()->MODE2.INTENCLR.reg = value;
#endif
}

bool alarmSupported(uint8_t index) {
  return index == 0 || (index == 1 && kAlarm1Interrupt != 0);
}

void writeAlarm(uint8_t index, uint32_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  if (index == 0)
    regs()->MODE2.RTC_ALARM0 = value;
  else
    regs()->MODE2.RTC_ALARM1 = value;
#else
  regs()->MODE2.Alarm[index].ALARM.reg = value;
#endif
}

void writeAlarmMask(uint8_t index, uint8_t value) {
#if defined(SIMIO_RTC_NEW_CTRLA_REGS)
  if (index == 0)
    regs()->MODE2.RTC_MASK0 = value;
  else
    regs()->MODE2.RTC_MASK1 = value;
#else
  regs()->MODE2.Alarm[index].MASK.reg = value;
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
  rtc::EventMask pendingEvents = rtc::EventNone;
  uint64_t pendingUnixTime = 0;
  uint64_t unixTime = 0;
  bool serviceRegistered = false;
  rtc::TimeState timeState = rtc::TimeState::Unset;
  rtc::Error lastError = rtc::Error::None;
};

RtcState rtcState;

static_assert((rtc::Mode2ReferenceYear % 4u) == 0u,
              "RTC Mode2 reference year must be a leap year");
static_assert(rtc::Mode2ReferenceYear == 2000u,
              "RTC Mode2 Unix conversion is bounded to 2000-2063");

bool mode2YearIsLeap(uint8_t yearOffset) {
  return (yearOffset & 0x03u) == 0u;
}

uint8_t mode2DaysInMonth(uint8_t yearOffset, uint8_t month) {
  static constexpr uint8_t kDaysByMonth[] = {
      31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u};
  if (month == 0u || month > 12u)
    return 0u;
  if (month == 2u && mode2YearIsLeap(yearOffset))
    return 29u;
  return kDaysByMonth[month - 1u];
}

int64_t daysFromCivil(uint16_t year, uint8_t month, uint8_t day) {
  int32_t adjustedYear = static_cast<int32_t>(year);
  const uint32_t monthValue = month;
  adjustedYear -= monthValue <= 2u ? 1 : 0;
  const int32_t era =
      (adjustedYear >= 0 ? adjustedYear : adjustedYear - 399) / 400;
  const uint32_t yearOfEra =
      static_cast<uint32_t>(adjustedYear - era * 400);
  const uint32_t dayOfYear =
      (153u * (monthValue > 2u ? monthValue - 3u : monthValue + 9u) + 2u) /
          5u +
      day - 1u;
  const uint32_t dayOfEra =
      yearOfEra * 365u + yearOfEra / 4u - yearOfEra / 100u + dayOfYear;
  return static_cast<int64_t>(era) * 146097 + dayOfEra - 719468;
}

void civilFromDays(uint64_t daysSinceEpoch, uint16_t &year, uint8_t &month,
                   uint8_t &day) {
  const int64_t z = static_cast<int64_t>(daysSinceEpoch) + 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const uint32_t dayOfEra = static_cast<uint32_t>(z - era * 146097);
  const uint32_t yearOfEra =
      (dayOfEra - dayOfEra / 1460u + dayOfEra / 36524u -
       dayOfEra / 146096u) /
      365u;
  const int64_t yearValue = static_cast<int64_t>(yearOfEra) + era * 400;
  const uint32_t dayOfYear =
      dayOfEra - (365u * yearOfEra + yearOfEra / 4u - yearOfEra / 100u);
  const uint32_t monthPrime = (5u * dayOfYear + 2u) / 153u;

  day = static_cast<uint8_t>(dayOfYear - (153u * monthPrime + 2u) / 5u + 1u);
  month = static_cast<uint8_t>(monthPrime < 10u ? monthPrime + 3u
                                                : monthPrime - 9u);
  year = static_cast<uint16_t>(yearValue + (month <= 2u ? 1 : 0));
}

uint16_t mode2Year(const rtc::Mode2Time &mode2Time) {
  return static_cast<uint16_t>(rtc::Mode2ReferenceYear + mode2Time.year);
}

bool mode2TimeIsValid(const rtc::Mode2Time &mode2Time) {
  if (mode2Time.year >= rtc::Mode2YearCount || mode2Time.hour > 23u ||
      mode2Time.minute > 59u || mode2Time.second > 59u)
    return false;

  const uint8_t monthDays = mode2DaysInMonth(mode2Time.year, mode2Time.month);
  return monthDays != 0u && mode2Time.day >= 1u && mode2Time.day <= monthDays;
}

uint32_t packMode2Time(const rtc::Mode2Time &time) {
  return (static_cast<uint32_t>(time.second) << 0) |
         (static_cast<uint32_t>(time.minute) << 6) |
         (static_cast<uint32_t>(time.hour) << 12) |
         (static_cast<uint32_t>(time.day) << 17) |
         (static_cast<uint32_t>(time.month) << 22) |
         (static_cast<uint32_t>(time.year) << 26);
}

rtc::Mode2Time unpackMode2Time(uint32_t value) {
  return rtc::Mode2Time{
      static_cast<uint8_t>((value >> 26) & 0x3Fu),
      static_cast<uint8_t>((value >> 22) & 0x0Fu),
      static_cast<uint8_t>((value >> 17) & 0x1Fu),
      static_cast<uint8_t>((value >> 12) & 0x1Fu),
      static_cast<uint8_t>((value >> 6) & 0x3Fu),
      static_cast<uint8_t>(value & 0x3Fu),
  };
}

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

void queueEvent(rtc::EventMask events, uint64_t unixTime) {
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
  rtc::EventMask events = rtc::EventNone;
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

void processInterruptFlags(uint16_t flags, bool clearHardwareFlags) {
  const uint16_t handled =
      flags & (kBaseInterruptMask | kPeriodicInterruptMask);
  if (handled == 0u)
    return;

  if (clearHardwareFlags)
    rtc::clearInterruptFlags(handled);

  uint64_t unixTimeValue = 0;
  rtc::EventMask events = rtc::EventNone;
  if ((handled & kPeriodic0Interrupt) != 0)
    events |= rtc::EventSecond;
  if ((handled & (kPeriodicInterruptMask & ~kPeriodic0Interrupt)) != 0)
    events |= rtc::EventDebounce;
  if ((handled & kAlarm0Interrupt) != 0)
    events |= rtc::EventAlarm0;
  if ((handled & kAlarm1Interrupt) != 0)
    events |= rtc::EventAlarm1;
  const bool overflow = (handled & kOverflowInterrupt) != 0;
  if (overflow)
    events |= rtc::EventOverflow;

  if (overflow) {
    const uint32_t primask = enterCritical();
    rtcState.unixTime = 0;
    rtcState.timeState = rtc::TimeState::Unset;
    exitCritical(primask);
  } else if (rtcState.timeState != rtc::TimeState::Unset) {
    rtc::Mode2Time mode2Time = unpackMode2Time(clockReg());
    if (rtc::mode2ToUnixTime(mode2Time, unixTimeValue)) {
      const uint32_t primask = enterCritical();
      rtcState.unixTime = unixTimeValue;
      exitCritical(primask);
    }
  }

  queueEvent(events, unixTimeValue);
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

bool configureRtcClock() {
#if defined(SIMIO_RTC_CTRL_REGS)
  GCLK->GENDIV.reg = GCLK_GENDIV_ID(2u) | GCLK_GENDIV_DIV(32u);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  GCLK->GENCTRL.reg =
      GCLK_GENCTRL_ID(2u) |
#if defined(CRYSTALLESS)
      GCLK_GENCTRL_SRC_OSC32K |
#else
      GCLK_GENCTRL_SRC_XOSC32K |
#endif
      GCLK_GENCTRL_GENEN;
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  GCLK->CLKCTRL.reg =
      static_cast<uint16_t>(GCLK_CLKCTRL_ID_RTC | GCLK_CLKCTRL_GEN_GCLK2 |
                            GCLK_CLKCTRL_CLKEN);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  return true;
#elif defined(OSC32KCTRL_RTCCTRL_RTCSEL_XOSC1K)
#if defined(__SAME51__) || defined(__SAME53__) || defined(__SAME54__)
#if defined(OSC32KCTRL_REGS)
  OSC32KCTRL_REGS->OSC32KCTRL_RTCCTRL =
#else
  OSC32KCTRL->OSC32KCTRL_RTCCTRL =
#endif
#if defined(CRYSTALLESS)
      OSC32KCTRL_RTCCTRL_RTCSEL_ULP1K;
#else
      OSC32KCTRL_RTCCTRL_RTCSEL_XOSC1K;
#endif
#else
#if defined(CRYSTALLESS)
  OSC32KCTRL->RTCCTRL.reg = OSC32KCTRL_RTCCTRL_RTCSEL_ULP1K;
#else
  OSC32KCTRL->RTCCTRL.reg = OSC32KCTRL_RTCCTRL_RTCSEL_XOSC1K;
#endif
#endif
  return true;
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
  if (!configureRtcClock()) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  disableInterrupts(kBaseInterruptMask | kPeriodicInterruptMask);
  clearInterruptFlags(kBaseInterruptMask | kPeriodicInterruptMask);

  if ((controlReg() & kCtrlEnable) == 0u) {
    writeControl(kCtrlModeClock | kCtrlPrescalerDiv1024);
    writeClock(packMode2Time(Mode2Time{0, 1, 1, 0, 0, 0}));
    if (!waitSync(kSyncClock)) {
      rtcState.lastError = Error::ClockWriteTimeout;
      return false;
    }
    setControlBits(kCtrlEnable);
    if (!waitSync(kSyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  enableInterrupts(kPeriodic0Interrupt | kOverflowInterrupt);
  rtcState.lastError = Error::None;
  return true;
}

void rtc::end() {
  disableInterrupts(kBaseInterruptMask | kPeriodicInterruptMask);
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
  clearControlBits(kCtrlEnable);
  waitSync(kSyncEnable);
}

bool rtc::enabled() { return (controlReg() & kCtrlEnable) != 0u; }

bool rtc::setUnixTime(uint64_t unixTimeValue, TimeState state) {
  if (unixTimeValue == 0) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }
  if (!begin())
    return false;

  Mode2Time mode2Time = {};
  if (!unixTimeToMode2(unixTimeValue, mode2Time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }

  const uint32_t primask = enterCritical();
  if (rtcState.timeState == TimeState::Trusted && state != TimeState::Trusted) {
    rtcState.lastError = Error::TrustedAuthorityRejected;
    exitCritical(primask);
    return false;
  }

  rtcState.unixTime = unixTimeValue;
  rtcState.timeState = state == TimeState::Unset ? TimeState::Manual : state;
  rtcState.lastError = Error::None;
  exitCritical(primask);

  writeClock(packMode2Time(mode2Time));
  if (!waitSync(kSyncClock)) {
    rtcState.lastError = Error::ClockWriteTimeout;
    return false;
  }

  queueEvent(EventTimeSet, unixTimeValue);
  return true;
}

bool rtc::unixTime(uint64_t &unixTimeOut) {
  const uint32_t primask = enterCritical();
  const bool configured = rtcState.timeState != TimeState::Unset;
  exitCritical(primask);
  if (!configured)
    return false;

  Mode2Time mode2Time = unpackMode2Time(clockReg());
  if (!mode2ToUnixTime(mode2Time, unixTimeOut))
    return false;

  const uint32_t updateMask = enterCritical();
  if (rtcState.unixTime != 0 && unixTimeOut < rtcState.unixTime) {
    rtcState.unixTime = 0;
    rtcState.timeState = TimeState::Unset;
    exitCritical(updateMask);
    queueEvent(EventOverflow, 0);
    return false;
  }
  rtcState.unixTime = unixTimeOut;
  exitCritical(updateMask);
  return true;
}

bool rtc::trustedUnixTime(uint64_t &unixTimeOut) {
  const uint32_t primask = enterCritical();
  const bool configured = rtcState.timeState == TimeState::Trusted;
  exitCritical(primask);
  return configured && unixTime(unixTimeOut);
}

bool rtc::unixTimeToMode2(uint64_t unixTimeValue, Mode2Time &mode2Time) {
  static constexpr uint32_t kSecondsPerDay = 86400u;
  if (unixTimeValue == 0u)
    return false;

  uint64_t days = unixTimeValue / kSecondsPerDay;
  uint32_t secondsOfDay = static_cast<uint32_t>(unixTimeValue % kSecondsPerDay);

  const int64_t mode2StartDay = daysFromCivil(Mode2ReferenceYear, 1u, 1u);
  const int64_t mode2EndDay = daysFromCivil(
      static_cast<uint16_t>(Mode2ReferenceYear + Mode2YearCount), 1u, 1u);
  const uint64_t mode2StartDayCount = static_cast<uint64_t>(mode2StartDay);
  const uint64_t mode2EndDayCount = static_cast<uint64_t>(mode2EndDay);
  if (days < mode2StartDayCount || days >= mode2EndDayCount)
    return false;

  uint16_t year = 0;
  uint8_t month = 0;
  uint8_t day = 0;
  civilFromDays(days, year, month, day);

  mode2Time.year = static_cast<uint8_t>(year - Mode2ReferenceYear);
  mode2Time.month = month;
  mode2Time.day = day;
  mode2Time.hour = static_cast<uint8_t>(secondsOfDay / 3600u);
  secondsOfDay %= 3600u;
  mode2Time.minute = static_cast<uint8_t>(secondsOfDay / 60u);
  mode2Time.second = static_cast<uint8_t>(secondsOfDay % 60u);
  return true;
}

bool rtc::mode2ToUnixTime(const Mode2Time &mode2Time, uint64_t &unixTimeOut) {
  static constexpr uint32_t kSecondsPerDay = 86400u;
  if (!mode2TimeIsValid(mode2Time))
    return false;

  const uint16_t year = mode2Year(mode2Time);
  const int64_t days = daysFromCivil(year, mode2Time.month, mode2Time.day);

  unixTimeOut = (static_cast<uint64_t>(days) * kSecondsPerDay) +
                (static_cast<uint32_t>(mode2Time.hour) * 3600u) +
                (static_cast<uint32_t>(mode2Time.minute) * 60u) +
                mode2Time.second;
  return true;
}

bool rtc::setAlarm(uint8_t index, const Mode2Time &time, AlarmMatch match) {
  if (!alarmSupported(index)) {
    rtcState.lastError = Error::UnsupportedAlarm;
    return false;
  }
  if (!mode2TimeIsValid(time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }
  if (!begin())
    return false;

  const uint16_t interrupt = index == 0 ? kAlarm0Interrupt : kAlarm1Interrupt;
  disableInterrupts(interrupt);
  writeAlarm(index, packMode2Time(time));
  writeAlarmMask(index, static_cast<uint8_t>(match));
  if (!waitSync(kSyncClock)) {
    rtcState.lastError = Error::AlarmWriteTimeout;
    return false;
  }
  clearInterruptFlags(interrupt);
  if (match != AlarmMatch::Disabled)
    enableInterrupts(interrupt);
  rtcState.lastError = Error::None;
  return true;
}

bool rtc::setAlarm(uint8_t index, uint64_t unixTimeValue, AlarmMatch match) {
  Mode2Time mode2Time = {};
  if (!unixTimeToMode2(unixTimeValue, mode2Time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }
  return setAlarm(index, mode2Time, match);
}

bool rtc::clearAlarm(uint8_t index) {
  if (!alarmSupported(index)) {
    rtcState.lastError = Error::UnsupportedAlarm;
    return false;
  }
  const uint16_t interrupt = index == 0 ? kAlarm0Interrupt : kAlarm1Interrupt;
  disableInterrupts(interrupt);
  clearInterruptFlags(interrupt);
  writeAlarmMask(index, static_cast<uint8_t>(AlarmMatch::Disabled));
  rtcState.lastError = Error::None;
  return true;
}

bool rtc::configureDebounce(PeriodicInterval interval, bool interrupt) {
  (void)interrupt;
  if (interval == PeriodicInterval::Disabled) {
    rtcState.lastError = Error::None;
    return true;
  }

  rtcState.lastError = Error::UnsupportedDebounce;
  return false;
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

uint32_t rtc::counter() { return clockReg(); }

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

uint16_t rtc::interruptFlags() { return interruptFlagReg(); }

void rtc::clearInterruptFlags(uint16_t flags) { writeInterruptFlag(flags); }

void rtc::enableInterrupts(uint16_t mask) { writeInterruptEnableSet(mask); }

void rtc::disableInterrupts(uint16_t mask) { writeInterruptEnableClear(mask); }

void rtc::handleInterrupt() {
  processInterruptFlags(interruptFlags(), true);
}

#if defined(UNIT_TEST)
void rtc::handleInterruptFlagsForTesting(uint16_t flags) {
  processInterruptFlags(flags, false);
}
#endif

extern "C" void RTC_Handler(void) { rtc::handleInterrupt(); }

#endif /* RTC_AVAILABLE */

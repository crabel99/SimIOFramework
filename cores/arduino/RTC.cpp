#include "RTC.h"

namespace {

#if defined(__SAMD51__) || defined(__SAME51__)
inline Rtc *rtcRegs() { return RTC; }
static constexpr uint16_t ControlEnable = RTC_MODE2_CTRLA_ENABLE;
static constexpr uint8_t ControlModePosition = RTC_MODE2_CTRLA_MODE_Pos;
static constexpr uint8_t ControlPrescalerPosition =
    RTC_MODE2_CTRLA_PRESCALER_Pos;
static constexpr uint16_t ControlPrescalerMask = RTC_MODE2_CTRLA_PRESCALER_Msk;
static constexpr uint32_t SyncEnable = RTC_MODE2_SYNCBUSY_ENABLE;
static constexpr uint32_t SyncClock = RTC_MODE2_SYNCBUSY_CLOCK;
static constexpr uint32_t SyncCount32 = RTC_MODE0_SYNCBUSY_COUNT;
static constexpr uint32_t SyncCount16 = RTC_MODE1_SYNCBUSY_COUNT;
static constexpr uint16_t PeriodicInterruptMask = RTC_MODE2_INTFLAG_PER_Msk;
static constexpr uint32_t PeriodicEventMask = RTC_MODE2_EVCTRL_PEREO_Msk;
static constexpr uint16_t Alarm0Interrupt = RTC_MODE2_INTFLAG_ALARM0;
static constexpr uint16_t Alarm1Interrupt = RTC_MODE2_INTFLAG_ALARM1;
static constexpr uint16_t OverflowInterrupt = RTC_MODE2_INTFLAG_OVF;
#elif defined(__SAME53__) || defined(__SAME54__)
inline rtc_registers_t *rtcRegs() { return RTC_REGS; }
static constexpr uint16_t ControlEnable = RTC_MODE2_CTRLA_ENABLE_Msk;
static constexpr uint8_t ControlModePosition = RTC_MODE2_CTRLA_MODE_Pos;
static constexpr uint8_t ControlPrescalerPosition =
    RTC_MODE2_CTRLA_PRESCALER_Pos;
static constexpr uint16_t ControlPrescalerMask = RTC_MODE2_CTRLA_PRESCALER_Msk;
static constexpr uint32_t SyncEnable = RTC_MODE2_SYNCBUSY_ENABLE_Msk;
static constexpr uint32_t SyncClock = RTC_MODE2_SYNCBUSY_CLOCK_Msk;
static constexpr uint32_t SyncCount32 = RTC_MODE0_SYNCBUSY_COUNT_Msk;
static constexpr uint32_t SyncCount16 = RTC_MODE1_SYNCBUSY_COUNT_Msk;
static constexpr uint16_t PeriodicInterruptMask = RTC_MODE2_INTFLAG_PER_Msk;
static constexpr uint32_t PeriodicEventMask = RTC_MODE2_EVCTRL_PEREO_Msk;
static constexpr uint16_t Alarm0Interrupt = RTC_MODE2_INTFLAG_ALARM0_Msk;
static constexpr uint16_t Alarm1Interrupt = RTC_MODE2_INTFLAG_ALARM1_Msk;
static constexpr uint16_t OverflowInterrupt = RTC_MODE2_INTFLAG_OVF_Msk;
#else
inline Rtc *rtcRegs() { return RTC; }
static constexpr uint16_t ControlEnable = RTC_MODE2_CTRL_ENABLE;
static constexpr uint8_t ControlModePosition = RTC_MODE2_CTRL_MODE_Pos;
static constexpr uint8_t ControlPrescalerPosition =
    RTC_MODE2_CTRL_PRESCALER_Pos;
static constexpr uint16_t ControlPrescalerMask = RTC_MODE2_CTRL_PRESCALER_Msk;
static constexpr uint32_t SyncEnable = 0;
static constexpr uint32_t SyncClock = 0;
static constexpr uint32_t SyncCount32 = 0;
static constexpr uint32_t SyncCount16 = 0;
static constexpr uint16_t PeriodicInterruptMask = 0;
static constexpr uint32_t PeriodicEventMask = RTC_MODE2_EVCTRL_PEREO_Msk;
static constexpr uint16_t Alarm0Interrupt = RTC_MODE2_INTFLAG_ALARM0;
static constexpr uint16_t Alarm1Interrupt = 0;
static constexpr uint16_t OverflowInterrupt = RTC_MODE2_INTFLAG_OVF;
#endif

static constexpr uint16_t BaseInterruptMask =
    Alarm0Interrupt | Alarm1Interrupt | OverflowInterrupt;

uint16_t controlModeBits(rtc::OperatingMode mode) {
  return static_cast<uint16_t>(static_cast<uint16_t>(mode)
                               << ControlModePosition);
}

// Prescaler is a semantic public enum, not a raw register field. D5x/E5x
// hardware uses CTRLA.PRESCALER=0 as OFF and shifts DIV1..DIV1024 up by one;
// D21 encodes DIV1..DIV1024 directly as 0x0..0xA. Keep all raw register writes
// behind this encoder so call sites cannot accidentally use the public enum as
// a family-portable bit pattern.
uint16_t encodedPrescaler(rtc::Prescaler prescaler) {
#if defined(__SAMD51__) || defined(__SAME51__) || defined(__SAME53__) ||       \
    defined(__SAME54__)
  return static_cast<uint16_t>(prescaler) + 1u;
#else
  return static_cast<uint16_t>(prescaler);
#endif
}

uint16_t controlPrescalerBits(rtc::Prescaler prescaler) {
  return static_cast<uint16_t>(
      (encodedPrescaler(prescaler) << ControlPrescalerPosition) &
      ControlPrescalerMask);
}

uint16_t controlReg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE2.CTRLA.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE2.RTC_CTRLA;
#else
  return rtcRegs()->MODE2.CTRL.reg;
#endif
}

void writeControl(uint16_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.CTRLA.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_CTRLA = value;
#else
  rtcRegs()->MODE2.CTRL.reg = value;
#endif
}

uint32_t syncBusyReg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE2.SYNCBUSY.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE2.RTC_SYNCBUSY;
#else
  return rtcRegs()->MODE2.STATUS.bit.SYNCBUSY;
#endif
}

uint32_t clockReg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE2.CLOCK.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE2.RTC_CLOCK;
#else
  return rtcRegs()->MODE2.CLOCK.reg;
#endif
}

void writeClock(uint32_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.CLOCK.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_CLOCK = value;
#else
  rtcRegs()->MODE2.CLOCK.reg = value;
#endif
}

uint16_t interruptFlagReg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE2.INTFLAG.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE2.RTC_INTFLAG;
#else
  return rtcRegs()->MODE2.INTFLAG.reg;
#endif
}

void writeInterruptFlag(uint16_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.INTFLAG.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_INTFLAG = value;
#else
  rtcRegs()->MODE2.INTFLAG.reg = value;
#endif
}

void writeInterruptEnableSet(uint16_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.INTENSET.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_INTENSET = value;
#else
  rtcRegs()->MODE2.INTENSET.reg = value;
#endif
}

void writeInterruptEnableClear(uint16_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.INTENCLR.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_INTENCLR = value;
#else
  rtcRegs()->MODE2.INTENCLR.reg = value;
#endif
}

uint32_t eventControlReg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE2.EVCTRL.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE2.RTC_EVCTRL;
#else
  return rtcRegs()->MODE2.EVCTRL.reg;
#endif
}

void writeEventControl(uint32_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.EVCTRL.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE2.RTC_EVCTRL = value;
#else
  rtcRegs()->MODE2.EVCTRL.reg = value;
#endif
}

uint32_t count32Reg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE0.COUNT.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE0.RTC_COUNT;
#else
  return rtcRegs()->MODE0.COUNT.reg;
#endif
}

void writeCount32(uint32_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE0.COUNT.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE0.RTC_COUNT = value;
#else
  rtcRegs()->MODE0.COUNT.reg = value;
#endif
}

uint16_t count16Reg() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return rtcRegs()->MODE1.COUNT.reg;
#elif defined(__SAME53__) || defined(__SAME54__)
  return rtcRegs()->MODE1.RTC_COUNT;
#else
  return rtcRegs()->MODE1.COUNT.reg;
#endif
}

void writeCount16(uint16_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE1.COUNT.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  rtcRegs()->MODE1.RTC_COUNT = value;
#else
  rtcRegs()->MODE1.COUNT.reg = value;
#endif
}

void writeAlarm(uint8_t index, uint32_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.Mode2Alarm[index].ALARM.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  if (index == 0)
    rtcRegs()->MODE2.RTC_ALARM0 = value;
  else
    rtcRegs()->MODE2.RTC_ALARM1 = value;
#else
  rtcRegs()->MODE2.Mode2Alarm[index].ALARM.reg = value;
#endif
}

void writeAlarmMask(uint8_t index, uint8_t value) {
#if defined(__SAMD51__) || defined(__SAME51__)
  rtcRegs()->MODE2.Mode2Alarm[index].MASK.reg = value;
#elif defined(__SAME53__) || defined(__SAME54__)
  if (index == 0)
    rtcRegs()->MODE2.RTC_MASK0 = value;
  else
    rtcRegs()->MODE2.RTC_MASK1 = value;
#else
  rtcRegs()->MODE2.Mode2Alarm[index].MASK.reg = value;
#endif
}

void setControlBits(uint16_t mask) { writeControl(controlReg() | mask); }

void clearControlBits(uint16_t mask) { writeControl(controlReg() & ~mask); }

uint8_t mode2AlarmCount() {
#if defined(__SAMD51__) || defined(__SAME51__) || defined(__SAME53__) ||       \
    defined(__SAME54__)
  return RTC_NUM_OF_ALARMS > 2 ? 2 : RTC_NUM_OF_ALARMS;
#else
  return RTC_ALARM_NUM > 2 ? 2 : RTC_ALARM_NUM;
#endif
}

bool mode2AlarmSupported(uint8_t index) {
  return index == 0 || (index == 1 && Alarm1Interrupt != 0);
}

uint16_t periodicInterruptMask(rtc::PeriodicInterval interval) {
  if (interval == rtc::PeriodicInterval::Disabled)
    return PeriodicInterruptMask;

  const uint8_t index = static_cast<uint8_t>(interval);
  if (index > 7u)
    return 0;

  const uint16_t mask = static_cast<uint16_t>(1u << index);
  return static_cast<uint16_t>(mask & PeriodicInterruptMask);
}

uint32_t periodicEventMask(rtc::PeriodicInterval interval) {
  if (interval == rtc::PeriodicInterval::Disabled)
    return PeriodicEventMask;

  const uint8_t index = static_cast<uint8_t>(interval);
  if (index > 7u)
    return 0;

  const uint32_t mask = static_cast<uint32_t>(1u << index);
  return mask & PeriodicEventMask;
}

rtc::EventMask periodicEventsFromFlags(uint16_t flags) {
  const uint16_t periodicFlags = flags & PeriodicInterruptMask;
  rtc::EventMask events = rtc::EventNone;
  for (uint8_t index = 0; index < 8u; ++index) {
    if ((periodicFlags & (static_cast<uint16_t>(1u << index))) != 0u)
      events |= static_cast<rtc::EventMask>(1u << index);
  }
  return events;
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) { __set_PRIMASK(primask); }

struct RtcState {
  struct HandlerSlot {
    rtc::EventCallback callback = nullptr;
    void *context = nullptr;
  };

  rtc::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  HandlerSlot periodicHandlers[8];
  HandlerSlot alarmHandlers[2];
  HandlerSlot overflowHandler;
  rtc::EventMask pendingEvents = rtc::EventNone;
  uint64_t pendingUnixTime = 0;
  uint64_t unixTime = 0;
  bool serviceRegistered = false;
  bool configured = false;
  rtc::RtcUse currentUse = rtc::RtcUse::Unclaimed;
  rtc::Error lastError = rtc::Error::None;
};

RtcState rtcState;

static_assert((rtc::Mode2ReferenceYear % 4u) == 0u,
              "RTC Mode2 reference year must be a leap year");
static_assert(rtc::Mode2ReferenceYear == 2000u,
              "RTC Mode2 Unix conversion is bounded to 2000-2063");

bool mode2YearIsLeap(uint8_t yearOffset) { return (yearOffset & 0x03u) == 0u; }

uint8_t mode2DaysInMonth(uint8_t yearOffset, uint8_t month) {
  static constexpr uint8_t kDaysByMonth[] = {31u, 28u, 31u, 30u, 31u, 30u,
                                             31u, 31u, 30u, 31u, 30u, 31u};
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
  const uint32_t yearOfEra = static_cast<uint32_t>(adjustedYear - era * 400);
  const uint32_t dayOfYear =
      (153u * (monthValue > 2u ? monthValue - 3u : monthValue + 9u) + 2u) / 5u +
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
      (dayOfEra - dayOfEra / 1460u + dayOfEra / 36524u - dayOfEra / 146096u) /
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
#if defined(__SAMD21__)
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
  RtcState::HandlerSlot periodicHandlers[8];
  RtcState::HandlerSlot alarmHandlers[2];
  RtcState::HandlerSlot overflowHandler;
  rtc::EventMask events = rtc::EventNone;
  uint64_t unixTime = 0;

  const uint32_t primask = enterCritical();
  callback = rtcState.callback;
  callbackContext = rtcState.callbackContext;
  for (uint8_t index = 0; index < 8u; ++index)
    periodicHandlers[index] = rtcState.periodicHandlers[index];
  for (uint8_t index = 0; index < 2u; ++index)
    alarmHandlers[index] = rtcState.alarmHandlers[index];
  overflowHandler = rtcState.overflowHandler;
  events = rtcState.pendingEvents;
  unixTime = rtcState.pendingUnixTime;
  rtcState.pendingEvents = rtc::EventNone;
  exitCritical(primask);

  for (uint8_t index = 0; index < 8u; ++index) {
    const rtc::EventMask event = static_cast<rtc::EventMask>(1u << index);
    if ((events & event) != 0u && periodicHandlers[index].callback != nullptr)
      periodicHandlers[index].callback(event, unixTime,
                                       periodicHandlers[index].context);
  }

  if ((events & rtc::EventAlarm0) != 0u &&
      alarmHandlers[0].callback != nullptr)
    alarmHandlers[0].callback(rtc::EventAlarm0, unixTime,
                              alarmHandlers[0].context);
  if ((events & rtc::EventAlarm1) != 0u &&
      alarmHandlers[1].callback != nullptr)
    alarmHandlers[1].callback(rtc::EventAlarm1, unixTime,
                              alarmHandlers[1].context);
  if ((events & rtc::EventOverflow) != 0u &&
      overflowHandler.callback != nullptr)
    overflowHandler.callback(rtc::EventOverflow, unixTime,
                             overflowHandler.context);

  if (callback != nullptr && events != rtc::EventNone)
    callback(events, unixTime, callbackContext);
}

void processInterruptFlags(uint16_t flags, bool clearHardwareFlags) {
  const uint16_t handled = flags & (BaseInterruptMask | PeriodicInterruptMask);
  if (handled == 0u)
    return;

  if (clearHardwareFlags)
    rtc::clearInterruptFlags(handled);

  uint64_t unixTimeValue = 0;
  rtc::EventMask events = rtc::EventNone;
  events |= periodicEventsFromFlags(handled);
  if ((handled & Alarm0Interrupt) != 0)
    events |= rtc::EventAlarm0;
  if ((handled & Alarm1Interrupt) != 0)
    events |= rtc::EventAlarm1;
  const bool overflow = (handled & OverflowInterrupt) != 0;
  if (overflow)
    events |= rtc::EventOverflow;

  if (overflow) {
    const uint32_t primask = enterCritical();
    rtcState.unixTime = 0;
    rtcState.configured = false;
    exitCritical(primask);
  } else if (rtcState.configured) {
    rtc::Mode2Time mode2Time = unpackMode2Time(clockReg());
    if (rtc::mode2ToUnixTime(mode2Time, unixTimeValue)) {
      const uint32_t primask = enterCritical();
      rtcState.unixTime = unixTimeValue;
      exitCritical(primask);
    }
  }

  queueEvent(events, unixTimeValue);
}

bool claimUse(rtc::RtcUse requested) {
  const uint32_t primask = enterCritical();
  const bool available = rtcState.currentUse == rtc::RtcUse::Unclaimed ||
                         rtcState.currentUse == requested;
  if (available) {
    rtcState.currentUse = requested;
    rtcState.lastError = rtc::Error::None;
  } else {
    rtcState.lastError = rtc::Error::ClaimConflict;
  }
  exitCritical(primask);
  return available;
}

bool ensurePendSvServiceRegistered() {
  if (rtcState.serviceRegistered)
    return true;

  const bool registered = PendSV::instance().registerService(
      rtc::pendSvServiceId(), rtcPendSvService);
  if (registered)
    rtcState.serviceRegistered = true;
  return registered;
}

bool configureRtcClock() {
#if defined(__SAMD51__) || defined(__SAME51__)
#if defined(CRYSTALLESS)
  OSC32KCTRL->RTCCTRL.reg = OSC32KCTRL_RTCCTRL_RTCSEL_ULP1K;
#else
  OSC32KCTRL->RTCCTRL.reg = OSC32KCTRL_RTCCTRL_RTCSEL_XOSC1K;
#endif
  return true;
#elif defined(__SAME53__) || defined(__SAME54__)
#if defined(CRYSTALLESS)
  OSC32KCTRL_REGS->OSC32KCTRL_RTCCTRL = OSC32KCTRL_RTCCTRL_RTCSEL_ULP1K;
#else
  OSC32KCTRL_REGS->OSC32KCTRL_RTCCTRL = OSC32KCTRL_RTCCTRL_RTCSEL_XOSC1K;
#endif
  return true;
#else
  constexpr uint8_t kRtcClockGenerator = 4u;

  GCLK->GENCTRL.reg = GCLK_GENCTRL_ID(kRtcClockGenerator);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }

  GCLK->GENDIV.reg = GCLK_GENDIV_ID(kRtcClockGenerator) | GCLK_GENDIV_DIV(32u);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  GCLK->GENCTRL.reg = GCLK_GENCTRL_ID(kRtcClockGenerator) |
#if defined(CRYSTALLESS)
                      GCLK_GENCTRL_SRC_OSC32K |
#else
                      GCLK_GENCTRL_SRC_XOSC32K |
#endif
                      GCLK_GENCTRL_GENEN;
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  GCLK->CLKCTRL.reg = static_cast<uint16_t>(
      GCLK_CLKCTRL_ID_RTC | GCLK_CLKCTRL_GEN(kRtcClockGenerator) |
      GCLK_CLKCTRL_CLKEN);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0u) {
  }
  return true;
#endif
}

} // namespace

int rtc::irqNumber() { return static_cast<int>(RTC_IRQn); }

void rtc::enableClock() {
#if defined(__SAMD51__) || defined(__SAME51__)
  MCLK->APBAMASK.reg |= MCLK_APBAMASK_RTC;
#elif defined(__SAME53__) || defined(__SAME54__)
  MCLK_REGS->MCLK_APBAMASK |= MCLK_APBAMASK_RTC_Msk;
#else
  PM->APBAMASK.reg |= PM_APBAMASK_RTC;
#endif
}

void rtc::disableClock() {
#if defined(__SAMD51__) || defined(__SAME51__)
  MCLK->APBAMASK.reg &= ~MCLK_APBAMASK_RTC;
#elif defined(__SAME53__) || defined(__SAME54__)
  MCLK_REGS->MCLK_APBAMASK &= ~MCLK_APBAMASK_RTC_Msk;
#else
  PM->APBAMASK.reg &= ~PM_APBAMASK_RTC;
#endif
}

#if RTC_CONFIGURED_USE != RTC_USE_DEBOUNCE
bool rtc::begin(bool runStandby) {
  ClockConfig config;
  config.runStandby = runStandby;
  return configureClock(config);
}
#endif

void rtc::end() {
  disableInterrupts(BaseInterruptMask | PeriodicInterruptMask);
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
  clearControlBits(ControlEnable);
  waitSync(SyncEnable);
}

bool rtc::enabled() { return (controlReg() & ControlEnable) != 0u; }

bool rtc::configure(OperatingMode mode, Prescaler prescaler) {
  if (mode == OperatingMode::Reserved) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  if (enabled()) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  writeControl(controlModeBits(mode) | controlPrescalerBits(prescaler));
  rtcState.lastError = Error::None;
  return true;
}

#if RTC_CONFIGURED_USE != RTC_USE_DEBOUNCE
bool rtc::configureClock() { return configureClock(ClockConfig{}); }

bool rtc::configureClock(const ClockConfig &config) {
  if (!claimUse(RtcUse::TimeDaemon))
    return false;
  (void)config.runStandby;
  if (!ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::PendSvRegistrationFailed;
    return false;
  }

  enableClock();
  if (!configureRtcClock()) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  disableInterrupts(BaseInterruptMask | PeriodicInterruptMask);
  clearInterruptFlags(BaseInterruptMask | PeriodicInterruptMask);

  if (enabled() && operatingMode() != OperatingMode::Clock) {
    clearControlBits(ControlEnable);
    if (!waitSync(SyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  if ((controlReg() & ControlEnable) == 0u) {
    if (!configure(OperatingMode::Clock, config.prescaler))
      return false;
    if (!write(Mode2Time{0, 1, 1, 0, 0, 0})) {
      rtcState.lastError = Error::ClockWriteTimeout;
      return false;
    }
    setControlBits(ControlEnable);
    if (!waitSync(SyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  uint16_t interruptMask = 0;
  if (config.enablePeriodicSecondInterrupt)
    interruptMask |= periodicInterruptMask(PeriodicInterval::Per7);
  if (config.enableOverflowInterrupt)
    interruptMask |= OverflowInterrupt;
  enableInterrupts(interruptMask);
  rtcState.lastError = Error::None;
  return true;
}
#endif

rtc::OperatingMode rtc::operatingMode() {
  return static_cast<OperatingMode>((controlReg() >> ControlModePosition) &
                                    0x3u);
}

uint8_t rtc::alarmCount() { return mode2AlarmCount(); }

bool rtc::alarmSupported(uint8_t index) {
  return index < mode2AlarmCount() && mode2AlarmSupported(index);
}

#if RTC_CONFIGURED_USE != RTC_USE_DEBOUNCE
bool rtc::setUnixTime(uint64_t unixTimeValue) {
  if (!claimUse(RtcUse::TimeDaemon))
    return false;
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
  rtcState.unixTime = unixTimeValue;
  rtcState.configured = true;
  rtcState.lastError = Error::None;
  exitCritical(primask);

  if (!write(mode2Time)) {
    rtcState.lastError = Error::ClockWriteTimeout;
    return false;
  }

  queueEvent(EventTimeSet, unixTimeValue);
  return true;
}
#endif

bool rtc::unixTime(uint64_t &unixTimeOut) {
  const uint32_t primask = enterCritical();
  const bool configured = rtcState.configured;
  exitCritical(primask);
  if (!configured)
    return false;

  Mode2Time mode2Time = unpackMode2Time(clockReg());
  if (!mode2ToUnixTime(mode2Time, unixTimeOut))
    return false;

  const uint32_t updateMask = enterCritical();
  if (rtcState.unixTime != 0 && unixTimeOut < rtcState.unixTime) {
    rtcState.unixTime = 0;
    rtcState.configured = false;
    exitCritical(updateMask);
    queueEvent(EventOverflow, 0);
    return false;
  }
  rtcState.unixTime = unixTimeOut;
  exitCritical(updateMask);
  return true;
}

bool rtc::read(uint32_t &value) {
  switch (operatingMode()) {
  case OperatingMode::Count32:
    value = count32Reg();
    return true;
  case OperatingMode::Count16:
    value = count16Reg();
    return true;
  case OperatingMode::Clock:
    value = clockReg();
    return true;
  case OperatingMode::Reserved:
  default:
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }
}

bool rtc::write(uint32_t value) {
  switch (operatingMode()) {
  case OperatingMode::Count32:
    writeCount32(value);
    if (!waitSync(SyncCount32)) {
      rtcState.lastError = Error::CountWriteTimeout;
      return false;
    }
    rtcState.lastError = Error::None;
    return true;
  case OperatingMode::Count16:
    writeCount16(static_cast<uint16_t>(value));
    if (!waitSync(SyncCount16)) {
      rtcState.lastError = Error::CountWriteTimeout;
      return false;
    }
    rtcState.lastError = Error::None;
    return true;
  case OperatingMode::Clock:
    writeClock(value);
    if (!waitSync(SyncClock)) {
      rtcState.lastError = Error::ClockWriteTimeout;
      return false;
    }
    rtcState.lastError = Error::None;
    return true;
  case OperatingMode::Reserved:
  default:
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }
}

bool rtc::read(Mode2Time &time) {
  if (operatingMode() != OperatingMode::Clock) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  time = unpackMode2Time(clockReg());
  if (!mode2TimeIsValid(time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }

  rtcState.lastError = Error::None;
  return true;
}

bool rtc::write(const Mode2Time &time) {
  if (operatingMode() != OperatingMode::Clock) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }
  if (!mode2TimeIsValid(time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }

  return write(packMode2Time(time));
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

#if RTC_CONFIGURED_USE != RTC_USE_DEBOUNCE
bool rtc::setAlarm(uint8_t index, const Mode2Time &time, AlarmMatch match) {
  if (!claimUse(RtcUse::TimeDaemon))
    return false;
  if (!rtc::alarmSupported(index)) {
    rtcState.lastError = Error::UnsupportedAlarm;
    return false;
  }
  if (!mode2TimeIsValid(time)) {
    rtcState.lastError = Error::InvalidUnixTime;
    return false;
  }
  if (!begin())
    return false;

  const uint16_t interrupt = index == 0 ? Alarm0Interrupt : Alarm1Interrupt;
  disableInterrupts(interrupt);
  writeAlarm(index, packMode2Time(time));
  writeAlarmMask(index, static_cast<uint8_t>(match));
  if (!waitSync(SyncClock)) {
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
  if (!claimUse(RtcUse::TimeDaemon))
    return false;
  if (!rtc::alarmSupported(index)) {
    rtcState.lastError = Error::UnsupportedAlarm;
    return false;
  }
  const uint16_t interrupt = index == 0 ? Alarm0Interrupt : Alarm1Interrupt;
  disableInterrupts(interrupt);
  clearInterruptFlags(interrupt);
  writeAlarmMask(index, static_cast<uint8_t>(AlarmMatch::Disabled));
  rtcState.lastError = Error::None;
  return true;
}
#endif

bool rtc::setPeriodicInterrupt(PeriodicInterval interval, bool enabled) {
  const uint16_t mask = periodicInterruptMask(interval);
  if (mask == 0u && interval != PeriodicInterval::Disabled) {
    rtcState.lastError = Error::UnsupportedDebounce;
    return false;
  }

  if (enabled)
    enableInterrupts(mask);
  else
    disableInterrupts(mask);
  if (interval == PeriodicInterval::Disabled)
    clearInterruptFlags(mask);

  rtcState.lastError = Error::None;
  return true;
}

bool rtc::setPeriodicEventOutput(PeriodicInterval interval, bool enabled) {
  const uint32_t mask = periodicEventMask(interval);
  if (mask == 0u && interval != PeriodicInterval::Disabled) {
    rtcState.lastError = Error::UnsupportedDebounce;
    return false;
  }

  const bool wasEnabled = rtc::enabled();
  if (wasEnabled) {
    clearControlBits(ControlEnable);
    if (!waitSync(SyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  uint32_t evctrl = eventControlReg();
  if (enabled)
    evctrl |= mask;
  else
    evctrl &= ~mask;
  writeEventControl(evctrl);

  if (wasEnabled) {
    setControlBits(ControlEnable);
    if (!waitSync(SyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  rtcState.lastError = Error::None;
  return true;
}

#if RTC_CONFIGURED_USE != RTC_USE_TIME_DAEMON
bool rtc::configureDebounce() { return configureDebounce(DebounceConfig{}); }

bool rtc::configureDebounce(const DebounceConfig &config) {
  if (!claimUse(RtcUse::Debounce))
    return false;
  (void)config.runStandby;
  if (config.interval == PeriodicInterval::Disabled)
    return configureDebounce(PeriodicInterval::Disabled, config.interrupt);

  if (config.mode == OperatingMode::Reserved) {
    rtcState.lastError = Error::UnsupportedDebounce;
    return false;
  }

  if (config.interrupt && !ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::PendSvRegistrationFailed;
    return false;
  }

  enableClock();
  if (!configureRtcClock()) {
    rtcState.lastError = Error::ClockConfigurationFailed;
    return false;
  }

  disableInterrupts(BaseInterruptMask | PeriodicInterruptMask);
  clearInterruptFlags(BaseInterruptMask | PeriodicInterruptMask);

  if (enabled()) {
    clearControlBits(ControlEnable);
    if (!waitSync(SyncEnable)) {
      rtcState.lastError = Error::EnableSyncTimeout;
      return false;
    }
  }

  setPeriodicEventOutput(PeriodicInterval::Disabled, false);

  if (!configure(config.mode, config.prescaler))
    return false;

  setControlBits(ControlEnable);
  if (!waitSync(SyncEnable)) {
    rtcState.lastError = Error::EnableSyncTimeout;
    return false;
  }

  if (config.interrupt) {
    NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
    NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  }

  return configureDebounce(config.interval, config.interrupt);
}

bool rtc::configureDebounce(PeriodicInterval interval, bool interrupt) {
  if (!claimUse(RtcUse::Debounce))
    return false;
  if (interval == PeriodicInterval::Disabled) {
    const bool interruptDisabled =
        setPeriodicInterrupt(PeriodicInterval::Disabled, false);
    const bool eventDisabled =
        setPeriodicEventOutput(PeriodicInterval::Disabled, false);
    return interruptDisabled && eventDisabled;
  }

  return interrupt ? setPeriodicInterrupt(interval, true)
                   : setPeriodicEventOutput(interval, true);
}
#endif

rtc::RtcUse rtc::currentUse() {
  const uint32_t primask = enterCritical();
  const RtcUse result = rtcState.currentUse;
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
  rtcState.configured = false;
  rtcState.lastError = Error::None;
  exitCritical(primask);
}

uint32_t rtc::counter() { return clockReg(); }

bool rtc::attachPeriodicInterrupt(PeriodicInterval interval,
                                  EventCallback callback, void *context) {
  const uint16_t mask = periodicInterruptMask(interval);
  if (callback == nullptr || interval == PeriodicInterval::Disabled ||
      mask == 0u || !ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::UnsupportedDebounce;
    return false;
  }

  const uint8_t index = static_cast<uint8_t>(interval);
  const uint32_t primask = enterCritical();
  rtcState.periodicHandlers[index].callback = callback;
  rtcState.periodicHandlers[index].context = context;
  exitCritical(primask);

  return setPeriodicInterrupt(interval, true);
}

void rtc::detachPeriodicInterrupt(PeriodicInterval interval) {
  if (interval == PeriodicInterval::Disabled)
    return;

  const uint8_t index = static_cast<uint8_t>(interval);
  if (index >= 8u)
    return;

  setPeriodicInterrupt(interval, false);
  const uint32_t primask = enterCritical();
  rtcState.periodicHandlers[index] = RtcState::HandlerSlot{};
  rtcState.pendingEvents &=
      static_cast<EventMask>(~static_cast<EventMask>(1u << index));
  exitCritical(primask);
}

bool rtc::attachAlarmHandler(uint8_t index, EventCallback callback,
                             void *context) {
  if (callback == nullptr || !alarmSupported(index) ||
      !ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::UnsupportedAlarm;
    return false;
  }

  const uint32_t primask = enterCritical();
  rtcState.alarmHandlers[index].callback = callback;
  rtcState.alarmHandlers[index].context = context;
  exitCritical(primask);
  rtcState.lastError = Error::None;
  return true;
}

void rtc::detachAlarmHandler(uint8_t index) {
  if (index >= 2u)
    return;

  const uint32_t primask = enterCritical();
  rtcState.alarmHandlers[index] = RtcState::HandlerSlot{};
  rtcState.pendingEvents &=
      static_cast<EventMask>(index == 0 ? ~EventAlarm0 : ~EventAlarm1);
  exitCritical(primask);
}

bool rtc::attachOverflowHandler(EventCallback callback, void *context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered()) {
    rtcState.lastError = Error::PendSvRegistrationFailed;
    return false;
  }

  const uint32_t primask = enterCritical();
  rtcState.overflowHandler.callback = callback;
  rtcState.overflowHandler.context = context;
  exitCritical(primask);
  enableInterrupts(OverflowInterrupt);
  rtcState.lastError = Error::None;
  return true;
}

void rtc::detachOverflowHandler() {
  const uint32_t primask = enterCritical();
  rtcState.overflowHandler = RtcState::HandlerSlot{};
  rtcState.pendingEvents &= static_cast<EventMask>(~EventOverflow);
  exitCritical(primask);
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
  for (uint8_t index = 0; index < 8u; ++index)
    rtcState.periodicHandlers[index] = RtcState::HandlerSlot{};
  for (uint8_t index = 0; index < 2u; ++index)
    rtcState.alarmHandlers[index] = RtcState::HandlerSlot{};
  rtcState.overflowHandler = RtcState::HandlerSlot{};
  rtcState.pendingEvents = EventNone;
  exitCritical(primask);
  PendSV::instance().clearService(pendSvServiceId());
  rtcState.serviceRegistered = false;
}

uint16_t rtc::interruptFlags() { return interruptFlagReg(); }

void rtc::clearInterruptFlags(uint16_t flags) { writeInterruptFlag(flags); }

void rtc::enableInterrupts(uint16_t mask) { writeInterruptEnableSet(mask); }

void rtc::disableInterrupts(uint16_t mask) { writeInterruptEnableClear(mask); }

void rtc::handleInterrupt() { processInterruptFlags(interruptFlags(), true); }

#if defined(UNIT_TEST)
void rtc::resetUseForTesting() {
  const uint32_t primask = enterCritical();
  rtcState.currentUse = RtcUse::Unclaimed;
  rtcState.lastError = Error::None;
  exitCritical(primask);
}

void rtc::handleInterruptFlagsForTesting(uint16_t flags) {
  processInterruptFlags(flags, false);
}
#endif

extern "C" void RTC_Handler(void) { rtc::handleInterrupt(); }

#pragma once

#include "PendSV.h"
#include "sam.h"

#include <stdint.h>

#if defined(RTC_REGS)
#define RTC_AVAILABLE 1
#define RTC_PERIPH (reinterpret_cast<uintptr_t>(RTC_REGS))
#elif defined(RTC)
#define RTC_AVAILABLE 1
#define RTC_PERIPH (reinterpret_cast<uintptr_t>(RTC))
#else
#define RTC_AVAILABLE 0
#endif

#if RTC_AVAILABLE

/**
 * @brief SAMD/SAME RTC Mode2 clock/calendar service.
 *
 * The RTC runs the hardware clock/calendar in Mode2 with a 1 Hz counter clock.
 * Public Unix-time APIs are intentionally bounded to the 64-year hardware
 * window from 2000-01-01 00:00:00 UTC through 2063-12-31 23:59:59 UTC.
 *
 * Time authority is tracked separately from the raw hardware clock:
 * - TimeState::Unset means the calendar may tick, but it must not be used for
 *   certificate validation or other trust-sensitive checks.
 * - TimeState::Manual means an application supplied plausible time.
 * - TimeState::Trusted means time came from a trusted authority.
 *
 * A trusted RTC value may only be replaced by another trusted value. Any RTC
 * overflow event clears the authority state because the calendar continuity has
 * been lost.
 */
class rtc {
public:
  /** @brief Bitmask of deferred RTC events delivered from the PendSV context. */
  using EventMask = uint16_t;

  /**
   * @brief Deferred RTC callback.
   * @param events ORed Event* bits that became pending.
   * @param unixTime Current Unix time when meaningful, or 0 when unavailable.
   * @param context User pointer passed to registerEventCallback().
   *
   * The callback runs from the PendSV dispatch path, not directly from the RTC
   * interrupt handler.
   */
  using EventCallback = void (*)(EventMask events, uint64_t unixTime,
                                void *context);

  /** @brief Authority level associated with the currently configured time. */
  enum class TimeState : uint8_t {
    /** @brief No authoritative time has been established. */
    Unset = 0,
    /** @brief Application-provided plausible time. */
    Manual = 1,
    /** @brief Time established by a trusted source. */
    Trusted = 2,
  };

  /** @brief Last failure reason for RTC setup, time conversion, or writes. */
  enum class Error : uint8_t {
    None = 0,
    InvalidUnixTime = 1,
    PendSvRegistrationFailed = 2,
    ClockConfigurationFailed = 3,
    CountSyncTimeout = 4,
    CountWriteTimeout = 5,
    EnableSyncTimeout = 6,
    ScheduleFailed = 7,
    TrustedAuthorityRejected = 8,
    ClockWriteTimeout = 9,
    AlarmWriteTimeout = 10,
    UnsupportedAlarm = 11,
    UnsupportedDebounce = 12,
  };

  /**
   * @brief Mode2 alarm match granularity.
   *
   * Values map directly to the hardware MASK register encoding. Broader match
   * modes ignore fields above the selected precision.
   */
  enum class AlarmMatch : uint8_t {
    Disabled = 0,
    Second = 1,
    MinuteSecond = 2,
    HourMinuteSecond = 3,
    DayHourMinuteSecond = 4,
    MonthDayHourMinuteSecond = 5,
    YearMonthDayHourMinuteSecond = 6,
  };

  /**
   * @brief RTC operating mode field encoding.
   *
   * Values intentionally match CTRLA/CTRL.MODE[1:0] across the supported
   * SAMD/SAME RTC families. Mode 3 is reserved by the hardware and is exposed
   * only so code that validates raw register fields can represent it.
   */
  enum class OperatingMode : uint8_t {
    Count32 = 0x0,
    Count16 = 0x1,
    Clock = 0x2,
    Reserved = 0x3,
  };

  /**
   * @brief Future RTC debounce prescaler selector.
   *
   * Debounce cannot share the Mode2 1 Hz calendar clock. A functional debounce
   * configuration must switch to a debounce-specific RTC clock source, divider,
   * and operating mode. Active debounce requests currently fail with
   * Error::UnsupportedDebounce instead of silently using the calendar clock.
   *
   * Values intentionally match the 4-bit RTC prescaler encoding: 0x0 selects
   * DIV1 and 0xA selects DIV1024. Encodings 0xB..0xF are reserved by the
   * supported SAMD/SAME RTC hardware and are not exposed here.
   */
  enum class PeriodicInterval : uint8_t {
    Disabled = 0xFF,
    Div1 = 0x0,
    Div2 = 0x1,
    Div4 = 0x2,
    Div8 = 0x3,
    Div16 = 0x4,
    Div32 = 0x5,
    Div64 = 0x6,
    Div128 = 0x7,
    Div256 = 0x8,
    Div512 = 0x9,
    Div1024 = 0xA,
  };

  /**
   * @brief Hardware Mode2 calendar fields.
   *
   * The year is a 6-bit offset from Mode2ReferenceYear. The hardware leap-year
   * rule is "offset divisible by 4", so the reference year is fixed to 2000 to
   * keep the full hardware range aligned with Gregorian leap years.
   */
  struct Mode2Time {
    uint8_t year;   // 6-bit offset from Mode2ReferenceYear.
    uint8_t month;  // 1-12.
    uint8_t day;    // 1-31.
    uint8_t hour;   // 0-23.
    uint8_t minute; // 0-59.
    uint8_t second; // 0-59.
  };

  /** @brief No pending RTC event. */
  static constexpr EventMask EventNone = 0;
  /** @brief One-second periodic RTC event. */
  static constexpr EventMask EventSecond = 1u << 0;
  /** @brief RTC time was explicitly set. */
  static constexpr EventMask EventTimeSet = 1u << 1;
  /** @brief Alarm 0 matched. */
  static constexpr EventMask EventAlarm0 = 1u << 2;
  /** @brief Alarm 1 matched, when supported by the target. */
  static constexpr EventMask EventAlarm1 = 1u << 3;
  /**
   * @brief Calendar continuity was lost.
   *
   * Mode2 overflow is not only year wrap. The hardware can also report overflow
   * when a clear-on-match path such as MATCHCLR resets the counter. Treat this
   * event as authority loss and re-establish time before trust-sensitive use.
   */
  static constexpr EventMask EventOverflow = 1u << 4;
  /** @brief Reserved for a future debounce-specific RTC configuration. */
  static constexpr EventMask EventDebounce = 1u << 5;
  /** @brief Calendar year represented by Mode2 year offset 0. */
  static constexpr uint16_t Mode2ReferenceYear = 2000u;
  /** @brief Number of calendar years representable by the 6-bit Mode2 year. */
  static constexpr uint16_t Mode2YearCount = 64u;

  /** @brief Return the CPU address of the RTC peripheral instance. */
  inline static uintptr_t baseAddress() { return RTC_PERIPH; }
  /** @brief Return the PendSV service id used for deferred RTC callbacks. */
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Rtc; }

  /** @brief Return the CMSIS IRQ number for the RTC peripheral. */
  static int irqNumber();
  /** @brief Return true when this target exposes an RTC peripheral. */
  static bool available();
  /**
   * @brief Start the RTC in Mode2 clock/calendar mode.
   * @param runStandby Reserved for standby behavior; currently ignored.
   * @return true when clocking, Mode2 setup, interrupts, and PendSV succeeded.
   */
  static bool begin(bool runStandby = false);
  /** @brief Disable RTC interrupts and the hardware counter. */
  static void end();
  /** @brief Return true when the RTC hardware enable bit is set. */
  static bool enabled();

  /**
   * @brief Set the RTC calendar from Unix time and assign authority state.
   * @param unixTime Seconds since 1970-01-01 UTC.
   * @param state Authority assigned to this update.
   * @return false if time is outside the Mode2 window or trust rules reject it.
   *
   * A trusted time can only be replaced by another trusted time. Passing
   * TimeState::Unset stores the value as Manual so callers cannot accidentally
   * set a usable clock with no authority label.
   */
  static bool setUnixTime(uint64_t unixTime, TimeState state);
  /**
   * @brief Set RTC time with the legacy trusted/manual boolean.
   * @param unixTime Seconds since 1970-01-01 UTC.
   * @param trusted true for TimeState::Trusted, false for TimeState::Manual.
   */
  static bool setUnixTime(uint64_t unixTime, bool trusted) {
    return setUnixTime(unixTime, trusted ? TimeState::Trusted
                                         : TimeState::Manual);
  }
  /**
   * @brief Read the current RTC time as Unix time.
   * @param unixTime Receives seconds since 1970-01-01 UTC.
   * @return true only when a Manual or Trusted time has been established.
   *
   * If the hardware calendar has moved backwards relative to the last accepted
   * value, the RTC authority state is cleared and this returns false.
   */
  static bool unixTime(uint64_t &unixTime);
  /**
   * @brief Read Unix time only when the current authority is Trusted.
   * @param unixTime Receives seconds since 1970-01-01 UTC.
   * @return false when time is unset, manual, invalid, or continuity was lost.
   */
  static bool trustedUnixTime(uint64_t &unixTime);
  /**
   * @brief Convert Unix time into hardware Mode2 calendar fields.
   * @return false outside the 2000-01-01 through 2063-12-31 Mode2 window.
   */
  static bool unixTimeToMode2(uint64_t unixTime, Mode2Time &mode2Time);
  /**
   * @brief Convert hardware Mode2 calendar fields into Unix time.
   * @return false when fields are outside the Mode2 calendar domain.
   */
  static bool mode2ToUnixTime(const Mode2Time &mode2Time,
                              uint64_t &unixTime);
  /**
   * @brief Program a hardware Mode2 alarm.
   * @param index Alarm index, usually 0; alarm 1 is target-dependent.
   * @param time Calendar fields to match.
   * @param match Match precision.
   * @return false if the alarm index or calendar fields are unsupported.
   */
  static bool setAlarm(uint8_t index, const Mode2Time &time,
                       AlarmMatch match);
  /**
   * @brief Program a hardware Mode2 alarm from Unix time.
   * @return false if Unix time is outside the Mode2 window.
   */
  static bool setAlarm(uint8_t index, uint64_t unixTime, AlarmMatch match);
  /** @brief Disable and clear a hardware Mode2 alarm. */
  static bool clearAlarm(uint8_t index);
  /**
   * @brief Configure RTC debounce timing.
   * @param interval Debounce interval source, or Disabled.
   * @param interrupt Also enable deferred callback delivery when supported.
   * @return true only for Disabled today; active debounce is not supported while
   * the RTC is owned by the Mode2 1 Hz calendar service.
   *
   * @todo Add a separate debounce mode that selects an appropriate RTC clock
   * source/divider and operating mode instead of reusing the calendar clock.
   */
  static bool configureDebounce(PeriodicInterval interval,
                                bool interrupt = false);
  /** @brief Return true when the current RTC authority is Trusted. */
  static bool trusted();
  /** @brief Return the current RTC authority state. */
  static TimeState timeState();
  /** @brief Return and retain the last RTC error code. */
  static Error lastError();
  /** @brief Clear stored Unix time and authority state without stopping RTC. */
  static void clearTime();
  /** @brief Demote Trusted time to Manual without changing the calendar. */
  static void clearTrusted();

  /** @brief Return the raw Mode2 CLOCK register value. */
  static uint32_t counter();
  /**
   * @brief Register a deferred RTC event callback.
   * @return false when callback is null or PendSV registration fails.
   */
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  /** @brief Remove the RTC event callback and clear pending callback state. */
  static void clearEventCallback();

  /** @brief Enable the RTC peripheral bus clock. */
  static void enableClock();
  /** @brief Disable the RTC peripheral bus clock. */
  static void disableClock();
  /** @brief Return raw Mode2 interrupt flags. */
  static uint16_t interruptFlags();
  /** @brief Clear selected Mode2 interrupt flags by writing one bits. */
  static void clearInterruptFlags(uint16_t flags);
  /** @brief Enable selected Mode2 interrupt sources. */
  static void enableInterrupts(uint16_t mask);
  /** @brief Disable selected Mode2 interrupt sources. */
  static void disableInterrupts(uint16_t mask);
  /** @brief Capture RTC IRQ state and schedule PendSV callback dispatch. */
  static void handleInterrupt();
#if defined(UNIT_TEST)
  /** @brief Inject RTC interrupt flags for embedded unit tests only. */
  static void handleInterruptFlagsForTesting(uint16_t flags);
#endif
};

#endif /* RTC_AVAILABLE */

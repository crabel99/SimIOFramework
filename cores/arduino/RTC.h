#pragma once

#include "PendSV.h"
#include "sam.h"

#include <stdint.h>

#if defined(__SAME53__) || defined(__SAME54__)
#define RTC_PERIPH (reinterpret_cast<uintptr_t>(RTC_REGS))
#else
#define RTC_PERIPH (reinterpret_cast<uintptr_t>(RTC))
#endif

/**
 * @brief SAMD/SAME RTC peripheral abstraction.
 *
 * This class owns the supported SAMD/SAME RTC register-layout differences,
 * hardware clock enable/disable, Mode0/Mode1/Mode2 read/write helpers, alarm
 * register access, interrupt flags, and PendSV callback dispatch. Higher-level
 * code such as NetworkTimeService owns time source authority and trust policy.
 *
 * Legacy Unix-time authority helpers remain temporarily for existing callers
 * while the network time daemon is introduced. New code should use the raw
 * peripheral operations plus explicit daemon-owned trust state.
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
   * @brief RTC input clock prescaler selector.
   *
   * Values intentionally match the 4-bit RTC prescaler encoding: 0x0 selects
   * DIV1 and 0xA selects DIV1024. Encodings 0xB..0xF are reserved by the
   * supported SAMD/SAME RTC hardware and are not exposed here.
   */
  enum class Prescaler : uint8_t {
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
   * @brief RTC periodic interval selector for PER0..PER7 sources.
   *
   * These values map directly to the RTC periodic event/interrupt source index.
   * Per SAMD21 19.6.9.1 and SAMD5x/E5x 21.6.8.1, PERn is generated from the
   * RTC prescaler on the 0-to-1 transition of prescaler bit n+2, so the source
   * period is 2^(n + 3) cycles of the internal RTC prescaler clock. For
   * example, PER0 fires every 8 cycles, PER1 every 16 cycles, and PER7 every
   * 1024 cycles.
   *
   * Periodic sources are independent of the counter prescaler except that the
   * hardware does not generate periodic events when the RTC prescaler is DIV1.
   * For the standard Mode2 clock path configured by configureClock(), the RTC
   * input is 1.024 kHz and PER7 is therefore the one-second periodic source.
   */
  enum class PeriodicInterval : uint8_t {
    Disabled = 0xFF,
    Per0 = 0,
    Per1 = 1,
    Per2 = 2,
    Per3 = 3,
    Per4 = 4,
    Per5 = 5,
    Per6 = 6,
    Per7 = 7,
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

  /**
   * @brief Mode2 clock/calendar configuration.
   *
   * The helper configures the silicon-specific RTC clock source for a 1.024 kHz
   * RTC input where supported, then uses DIV1024 by default so Mode2 advances
   * at 1 Hz as required by the SAMD21 and SAMD5x/E5x datasheets.
   */
  struct ClockConfig {
    Prescaler prescaler = Prescaler::Div1024;
    bool enableOverflowInterrupt = true;
    /**
     * @brief Optionally enable the PER7 interrupt for the default 1.024 kHz
     * path.
     *
     * This is not needed for the hardware calendar to advance. Mode2 increments
     * seconds from the configured 1 Hz counter clock without software service.
     * Enable this only when an application needs a PendSV callback every
     * second. NetworkTimeService should use Mode2 alarms for refresh scheduling
     * instead of a periodic one-second interrupt.
     */
    bool enablePeriodicSecondInterrupt = false;
    bool runStandby = false;
  };

  /**
   * @brief Debounce-oriented RTC configuration.
   *
   * The default preset uses the same chip-family 1.024 kHz RTC input as
   * configureClock(), switches the counter to Mode1, keeps the counter
   * prescaler away from DIV1 so periodic sources are generated, and enables
   * PER2 as an event output by default. PER2 is 32 cycles of the 1.024 kHz RTC
   * input, or about 31.25 ms.
   *
   * Periodic events are generated from the RTC prescaler taps and are
   * independent of the counter mode except that the hardware suppresses them
   * when the counter prescaler is DIV1.
   */
  struct DebounceConfig {
    OperatingMode mode = OperatingMode::Count16;
    Prescaler prescaler = Prescaler::Div2;
    PeriodicInterval interval = PeriodicInterval::Per2;
    bool interrupt = false;
    bool runStandby = false;
  };

  /** @brief No pending RTC event. */
  static constexpr EventMask EventNone = 0;
  /** @brief Hardware periodic interval 0 event. */
  static constexpr EventMask EventPeriodic0 = 1u << 0;
  /** @brief Hardware periodic interval 1 event. */
  static constexpr EventMask EventPeriodic1 = 1u << 1;
  /** @brief Hardware periodic interval 2 event. */
  static constexpr EventMask EventPeriodic2 = 1u << 2;
  /** @brief Hardware periodic interval 3 event. */
  static constexpr EventMask EventPeriodic3 = 1u << 3;
  /** @brief Hardware periodic interval 4 event. */
  static constexpr EventMask EventPeriodic4 = 1u << 4;
  /** @brief Hardware periodic interval 5 event. */
  static constexpr EventMask EventPeriodic5 = 1u << 5;
  /** @brief Hardware periodic interval 6 event. */
  static constexpr EventMask EventPeriodic6 = 1u << 6;
  /** @brief Hardware periodic interval 7 event. */
  static constexpr EventMask EventPeriodic7 = 1u << 7;
  /** @brief One-second periodic event for configureClock()'s 1.024 kHz input.
   */
  static constexpr EventMask EventSecond = EventPeriodic7;
  /** @brief RTC time was explicitly set. */
  static constexpr EventMask EventTimeSet = 1u << 8;
  /** @brief Alarm 0 matched. */
  static constexpr EventMask EventAlarm0 = 1u << 9;
  /** @brief Alarm 1 matched, when supported by the target. */
  static constexpr EventMask EventAlarm1 = 1u << 10;
  /**
   * @brief Calendar continuity was lost.
   *
   * Mode2 overflow is not only year wrap. The hardware can also report overflow
   * when a clear-on-match path such as MATCHCLR resets the counter. Treat this
   * event as authority loss and re-establish time before trust-sensitive use.
   */
  static constexpr EventMask EventOverflow = 1u << 11;
  /** @brief Any periodic interval event useful for debounce sampling. */
  static constexpr EventMask EventDebounce =
      EventPeriodic0 | EventPeriodic1 | EventPeriodic2 | EventPeriodic3 |
      EventPeriodic4 | EventPeriodic5 | EventPeriodic6 | EventPeriodic7;
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
   * @brief Configure the RTC operating mode and prescaler while disabled.
   *
   * This does not select the chip's RTC clock source; call enableClock() and
   * configure the appropriate GCLK/OSC32K path before enabling the peripheral.
   */
  static bool configure(OperatingMode mode, Prescaler prescaler);
  /**
   * @brief Configure Mode2 clock/calendar mode with a 1 Hz counter tick.
   *
   * This enables the RTC bus clock, selects the chip-family RTC clock source
   * used for a 1.024 kHz RTC input, configures Mode2 with the requested
   * prescaler, initializes the calendar register if the RTC was disabled, and
   * enables the requested Mode2 interrupts.
   */
  static bool configureClock();
  static bool configureClock(const ClockConfig &config);
  /** @brief Return the current hardware operating mode. */
  static OperatingMode operatingMode();
  /** @brief Return the number of Mode2 alarm channels exposed by this target.
   */
  static uint8_t alarmCount();
  /** @brief Return true when the target exposes the selected Mode2 alarm. */
  static bool alarmSupported(uint8_t index);

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
   * @brief Read the current RTC count/calendar register for the active mode.
   *
   * Mode0 returns the 32-bit COUNT value, Mode1 returns COUNT[15:0], and Mode2
   * returns the packed CLOCK register.
   */
  static bool read(uint32_t &value);
  /**
   * @brief Write the current RTC count/calendar register for the active mode.
   *
   * Mode0 writes COUNT[31:0], Mode1 writes COUNT[15:0], and Mode2 writes the
   * packed CLOCK register.
   */
  static bool write(uint32_t value);
  /** @brief Read hardware Mode2 calendar fields from the CLOCK register. */
  static bool read(Mode2Time &time);
  /** @brief Write hardware Mode2 calendar fields to the CLOCK register. */
  static bool write(const Mode2Time &time);
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
   * @brief Enable or disable a periodic interval interrupt source.
   *
   * PeriodicInterval::Disabled clears all periodic interval interrupts. The
   * actual wall-clock interval depends on the currently configured RTC clock
   * source, prescaler, and operating mode.
   */
  static bool setPeriodicInterrupt(PeriodicInterval interval, bool enabled);
  /**
   * @brief Enable or disable a periodic interval event output.
   *
   * PeriodicInterval::Disabled clears all periodic interval event outputs.
   */
  static bool setPeriodicEventOutput(PeriodicInterval interval, bool enabled);
  /**
   * @brief Configure the RTC for an approximately 30 ms debounce source.
   *
   * This preset owns RTC mode/clock/prescaler selection. Use the PERn overload
   * only when the RTC has already been configured elsewhere.
   */
  static bool configureDebounce();
  static bool configureDebounce(const DebounceConfig &config);
  /**
   * @brief Configure a periodic RTC source for debounce sampling.
   * @param interval Periodic interval source, or Disabled.
   * @param interrupt true for PendSV callback delivery, false for event output.
   * @return false when the requested periodic path is not supported.
   *
   * This helper does not choose the RTC operating mode, clock source, or
   * prescaler. Callers that need debounce must configure an RTC mode/clock fast
   * enough for their debounce window before enabling this periodic source.
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

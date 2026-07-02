#pragma once

#include "PendSV.h"
#include "sam.h"

#include <stdint.h>

#define RTC_USE_UNCLAIMED 0
#define RTC_USE_DEBOUNCE 1
#define RTC_USE_TIME_DAEMON 2

#ifndef RTC_CONFIGURED_USE
#define RTC_CONFIGURED_USE RTC_USE_UNCLAIMED
#endif

#if RTC_CONFIGURED_USE != RTC_USE_UNCLAIMED &&                                 \
    RTC_CONFIGURED_USE != RTC_USE_DEBOUNCE &&                                  \
    RTC_CONFIGURED_USE != RTC_USE_TIME_DAEMON
#error                                                                         \
    "RTC_CONFIGURED_USE must be RTC_USE_UNCLAIMED, RTC_USE_DEBOUNCE, or RTC_USE_TIME_DAEMON"
#endif

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
 * Unix-time helpers are raw calendar convenience functions only. Higher-level
 * code such as NetworkTimeService owns source authority and trust policy.
 */
class rtc {
public:
  /** @brief Bitmask of deferred RTC events delivered from the PendSV context.
   */
  using EventMask = uint16_t;

  /**
   * @brief Deferred RTC callback.
   * @param events ORed Event* bits that became pending.
   * @param unixTime Current Unix time when meaningful, or 0 when unavailable.
   * @param context User pointer passed to the attached handler.
   *
   * The callback runs from the PendSV dispatch path, not directly from the RTC
   * interrupt handler.
   */
  using EventCallback = void (*)(EventMask events, uint64_t unixTime,
                                 void *context);

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
    ClockWriteTimeout = 9,
    AlarmWriteTimeout = 10,
    UnsupportedAlarm = 11,
    UnsupportedDebounce = 12,
    ClaimConflict = 13,
  };

  /**
   * @brief Exclusive high-level use currently claimed for RTC helpers.
   *
   * The raw register read/write helpers remain available for peripheral-level
   * code, but configuration helpers that establish a role claim the RTC as
   * either a debounce source or the Mode2 time-daemon clock. Default builds
   * start unclaimed and enforce conflicts at runtime. Builds may define
   * RTC_CONFIGURED_USE to RTC_USE_DEBOUNCE or RTC_USE_TIME_DAEMON to make
   * incompatible helper calls compile-time errors.
   */
  enum class RtcUse : uint8_t {
    Unclaimed = RTC_USE_UNCLAIMED,
    Debounce = RTC_USE_DEBOUNCE,
    TimeDaemon = RTC_USE_TIME_DAEMON,
  };

  /**
   * @brief Mode2 alarm match granularity.
   *
   * Values map directly to the hardware MASK register encoding. Broader match
   * modes ignore fields above the selected precision.
   *
   * When the Ethernet stack is active, Mode2 alarm 0 is reserved for
   * NetworkTimeService refresh scheduling. Applications using Ethernet must not
   * reuse ALARM0 for their own RTC alarm callbacks.
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
   * These values are API-level divider selectors. They are not portable raw
   * CTRLA.PRESCALER bit patterns.
   *
   * Do not write static_cast<uint8_t>(Prescaler) directly into RTC hardware
   * registers. SAMD21 encodes DIV1..DIV1024 as 0x0..0xA. SAMD5x/E5x reserves
   * 0x0 as OFF and encodes DIV1..DIV1024 as 0x1..0xB. Use configure(),
   * configureClock(), configureDebounce(), or the RTC.cpp encoder so the
   * selected hardware family receives the correct raw field value.
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
   * Per SAMD21 19.6.9.1 and SAMD5x/E5x 21.6.8.1, PERn is generated on the
   * 0-to-1 transition of prescaler bit n+2, so the source period is 2^(n + 3)
   * cycles of the periodic source clock. For example, PER0 fires every 8
   * cycles, PER1 every 16 cycles, and PER7 every 1024 cycles.
   *
   * SAMD5x/E5x periodic sources are independent of the counter prescaler value
   * except when the raw CTRLA.PRESCALER field is OFF. This API does not expose
   * the OFF encoding. For the standard Mode2 clock path configured by
   * configureClock(), the RTC input is 1.024 kHz and PER7 is therefore the
   * one-second periodic source.
   *
   * When the Ethernet stack is active, PER4 is reserved for lwIP NO_SYS timer
   * service. Applications using Ethernet must not reuse PER4 for debounce,
   * alarms, or other periodic callbacks.
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
   * configureClock(), switches the counter to Mode1, and enables PER2 as an
   * event output by default. PER2 is 32 cycles of the 1.024 kHz RTC input, or
   * about 31.25 ms.
   *
   * Periodic events are generated from the RTC prescaler taps and are
   * independent of the counter mode. On SAMD5x/E5x they require the raw
   * CTRLA.PRESCALER field to be something other than OFF, which this API
   * already guarantees for every exposed Prescaler value.
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
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool begin(bool runStandby = false) = delete;
#else
  static bool begin(bool runStandby = false);
#endif
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
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool configureClock() = delete;
  static bool configureClock(const ClockConfig &config) = delete;
#else
  static bool configureClock();
  static bool configureClock(const ClockConfig &config);
#endif
  /** @brief Return the current hardware operating mode. */
  static OperatingMode operatingMode();
  /** @brief Return the number of Mode2 alarm channels exposed by this target.
   */
  static uint8_t alarmCount();
  /** @brief Return true when the target exposes the selected Mode2 alarm. */
  static bool alarmSupported(uint8_t index);

  /**
   * @brief Set the Mode2 calendar from Unix time.
   * @param unixTime Seconds since 1970-01-01 UTC.
   * @return true when the time is representable and written successfully.
   *
   * This is a raw peripheral write. Source authority and trust policy are owned
   * by NetworkTimeService or another higher-level clock authority.
   */
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool setUnixTime(uint64_t unixTime) = delete;
#else
  static bool setUnixTime(uint64_t unixTime);
#endif
  /**
   * @brief Read the current RTC time as Unix time.
   * @param unixTime Receives seconds since 1970-01-01 UTC.
   * @return true only when time has been written and continuity is intact.
   *
   * If the hardware calendar has moved backwards relative to the last accepted
   * value, the RTC configured state is cleared and this returns false.
   */
  static bool unixTime(uint64_t &unixTime);
  /**
   * @brief Convert Unix time into hardware Mode2 calendar fields.
   * @return false outside the 2000-01-01 through 2063-12-31 Mode2 window.
   */
  static bool unixTimeToMode2(uint64_t unixTime, Mode2Time &mode2Time);
  /**
   * @brief Convert hardware Mode2 calendar fields into Unix time.
   * @return false when fields are outside the Mode2 calendar domain.
   */
  static bool mode2ToUnixTime(const Mode2Time &mode2Time, uint64_t &unixTime);
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
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool setAlarm(uint8_t index, const Mode2Time &time,
                       AlarmMatch match) = delete;
#else
  static bool setAlarm(uint8_t index, const Mode2Time &time, AlarmMatch match);
#endif
  /**
   * @brief Program a hardware Mode2 alarm from Unix time.
   * @return false if Unix time is outside the Mode2 window.
   */
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool setAlarm(uint8_t index, uint64_t unixTime,
                       AlarmMatch match) = delete;
#else
  static bool setAlarm(uint8_t index, uint64_t unixTime, AlarmMatch match);
#endif
  /** @brief Disable and clear a hardware Mode2 alarm. */
#if RTC_CONFIGURED_USE == RTC_USE_DEBOUNCE
  static bool clearAlarm(uint8_t index) = delete;
#else
  static bool clearAlarm(uint8_t index);
#endif
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
#if RTC_CONFIGURED_USE == RTC_USE_TIME_DAEMON
  static bool configureDebounce() = delete;
  static bool configureDebounce(const DebounceConfig &config) = delete;
#else
  static bool configureDebounce();
  static bool configureDebounce(const DebounceConfig &config);
#endif
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
#if RTC_CONFIGURED_USE == RTC_USE_TIME_DAEMON
  static bool configureDebounce(PeriodicInterval interval,
                                bool interrupt = false) = delete;
#else
  static bool configureDebounce(PeriodicInterval interval,
                                bool interrupt = false);
#endif
  /** @brief Return the currently claimed high-level RTC helper role. */
  static RtcUse currentUse();
  /** @brief Return and retain the last RTC error code. */
  static Error lastError();
  /** @brief Clear stored Unix time without stopping RTC or changing RTC use. */
  static void clearTime();

  /** @brief Return the raw Mode2 CLOCK register value. */
  static uint32_t counter();
  /**
   * @brief Attach a deferred handler to one periodic interrupt source.
   *
   * This enables the selected periodic interrupt. The callback runs from the
   * PendSV dispatch path and receives the single matching EventPeriodic* bit.
   */
  static bool attachPeriodicInterrupt(PeriodicInterval interval,
                                      EventCallback callback,
                                      void *context = nullptr);
  /** @brief Disable one periodic interrupt source and clear its handler. */
  static void detachPeriodicInterrupt(PeriodicInterval interval);
  /**
   * @brief Attach a deferred handler to one Mode2 alarm interrupt source.
   *
   * This only installs the handler. Use setAlarm() to program and enable the
   * hardware alarm match.
   */
  static bool attachAlarmHandler(uint8_t index, EventCallback callback,
                                 void *context = nullptr);
  /** @brief Clear one Mode2 alarm handler without changing the alarm register. */
  static void detachAlarmHandler(uint8_t index);
  /** @brief Attach a deferred handler to Mode2 overflow events. */
  static bool attachOverflowHandler(EventCallback callback,
                                    void *context = nullptr);
  /** @brief Clear the Mode2 overflow handler. */
  static void detachOverflowHandler();
  /**
   * @brief Register a deferred aggregate RTC event callback.
   *
   * Prefer the source-specific attach* APIs for new code. This compatibility
   * callback observes all queued RTC events but does not own individual sources.
   * @return false when callback is null or PendSV registration fails.
   */
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  /** @brief Remove all RTC callbacks and clear pending callback state. */
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
  /** @brief Reset the RTC helper ownership claim for embedded unit tests only.
   */
  static void resetUseForTesting();
  /** @brief Inject RTC interrupt flags for embedded unit tests only. */
  static void handleInterruptFlagsForTesting(uint16_t flags);
#endif
};

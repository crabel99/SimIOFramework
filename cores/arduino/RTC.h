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

class rtc {
public:
  using EventMask = uint8_t;
  using EventCallback = void (*)(EventMask events, uint64_t unixTime,
                                void *context);

  enum class TimeState : uint8_t {
    Unset = 0,
    Manual = 1,
    Trusted = 2,
  };

  static constexpr EventMask EventNone = 0;
  static constexpr EventMask EventSecond = 1u << 0;
  static constexpr EventMask EventTimeSet = 1u << 1;

#if defined(RTC_MODE0_INTFLAG_CMP0_Msk)
  static constexpr uint16_t Compare0Interrupt = RTC_MODE0_INTFLAG_CMP0_Msk;
#elif defined(RTC_MODE0_INTFLAG_CMP0)
  static constexpr uint16_t Compare0Interrupt = RTC_MODE0_INTFLAG_CMP0;
#endif
  static constexpr uint32_t TicksPerSecond = 32u;

  inline static uintptr_t baseAddress() { return RTC_PERIPH; }
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Rtc; }

  static int irqNumber();
  static bool available();
  static bool begin(bool runStandby = false);
  static void end();
  static bool enabled();

  static bool setUnixTime(uint64_t unixTime, TimeState state);
  static bool setUnixTime(uint64_t unixTime, bool trusted) {
    return setUnixTime(unixTime, trusted ? TimeState::Trusted
                                         : TimeState::Manual);
  }
  static bool unixTime(uint64_t &unixTime);
  static bool trustedUnixTime(uint64_t &unixTime);
  static bool trusted();
  static TimeState timeState();
  static void clearTime();
  static void clearTrusted();

  static uint32_t counter();
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  static void clearEventCallback();

  static void enableClock();
  static void disableClock();
  static uint16_t interruptFlags();
  static void clearInterruptFlags(uint16_t flags);
  static void enableInterrupts(uint16_t mask);
  static void disableInterrupts(uint16_t mask);
  static void handleInterrupt();

private:
  static bool scheduleSecondTick();
};

#endif /* RTC_AVAILABLE */

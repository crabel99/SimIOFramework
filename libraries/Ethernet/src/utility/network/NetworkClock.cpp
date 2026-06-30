#include "NetworkClock.h"

#include <SecureClient.h>

#if __has_include(<sam.h>) && __has_include(<RTC.h>)
#include <RTC.h>
#endif

namespace {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
rtc::TimeState rtcTimeState(NetworkTimeState state) {
  switch (state) {
  case NetworkTimeState::Trusted:
    return rtc::TimeState::Trusted;
  case NetworkTimeState::Manual:
    return rtc::TimeState::Manual;
  case NetworkTimeState::Unset:
  default:
    return rtc::TimeState::Unset;
  }
}
#endif
} // namespace

bool NetworkClock::setUnixTime(uint64_t unixTime, NetworkTimeState state) {
  if (unixTime == 0)
    return false;

  if (_state == NetworkTimeState::Trusted && state != NetworkTimeState::Trusted)
    return false;

  const NetworkTimeState nextState =
      state == NetworkTimeState::Unset ? NetworkTimeState::Manual : state;

#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (!rtc::setUnixTime(unixTime, rtcTimeState(nextState)))
    return false;
#endif

  _unixTime = unixTime;
  _state = nextState;
  return true;
}

void NetworkClock::clear() {
  _unixTime = 0;
  _state = NetworkTimeState::Unset;
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  rtc::clearTime();
#endif
}

void NetworkClock::clearTrusted() {
  if (_state == NetworkTimeState::Trusted)
    _state = NetworkTimeState::Manual;
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  rtc::clearTrusted();
#endif
}

bool NetworkClock::unixTime(uint64_t &unixTimeOut) const {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (rtc::unixTime(unixTimeOut))
    return true;
#endif
  unixTimeOut = _unixTime;
  return _state != NetworkTimeState::Unset;
}

bool NetworkClock::trustedUnixTime(uint64_t &unixTimeOut) const {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (rtc::trustedUnixTime(unixTimeOut))
    return true;
#endif
  unixTimeOut = _unixTime;
  return _state == NetworkTimeState::Trusted;
}

bool NetworkClock::trusted() const {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (rtc::trusted())
    return true;
#endif
  return _state == NetworkTimeState::Trusted;
}

NetworkTimeState NetworkClock::timeState() const {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  switch (rtc::timeState()) {
  case rtc::TimeState::Trusted:
    return NetworkTimeState::Trusted;
  case rtc::TimeState::Manual:
    return NetworkTimeState::Manual;
  case rtc::TimeState::Unset:
  default:
    break;
  }
#endif
  return _state;
}

bool NetworkClock::applyTrustedTime(SecureClient &client) const {
  uint64_t unixTimeValue = 0;
  if (!trustedUnixTime(unixTimeValue))
    return false;
  return client.setTrustedTime(unixTimeValue);
}

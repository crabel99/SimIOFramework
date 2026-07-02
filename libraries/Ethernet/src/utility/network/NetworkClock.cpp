#include "NetworkClock.h"

#include <SecureClient.h>

#if __has_include(<sam.h>) && __has_include(<RTC.h>)
#include <RTC.h>
#endif

bool NetworkClock::setUnixTime(uint64_t unixTime, NetworkTimeState state) {
  if (unixTime == 0)
    return false;

  if (_state == NetworkTimeState::Trusted && state != NetworkTimeState::Trusted)
    return false;

  const NetworkTimeState nextState =
      state == NetworkTimeState::Unset ? NetworkTimeState::Manual : state;

#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (!rtc::setUnixTime(unixTime))
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
}

bool NetworkClock::unixTime(uint64_t &unixTimeOut) const {
  if (_state == NetworkTimeState::Unset) {
    unixTimeOut = 0;
    return false;
  }
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (rtc::unixTime(unixTimeOut))
    return true;
#endif
  unixTimeOut = _unixTime;
  return _unixTime != 0;
}

bool NetworkClock::trustedUnixTime(uint64_t &unixTimeOut) const {
  if (_state != NetworkTimeState::Trusted) {
    unixTimeOut = 0;
    return false;
  }
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (rtc::unixTime(unixTimeOut))
    return true;
#endif
  unixTimeOut = _unixTime;
  return _unixTime != 0;
}

bool NetworkClock::trusted() const { return _state == NetworkTimeState::Trusted; }

NetworkTimeState NetworkClock::timeState() const {
#if defined(RTC_AVAILABLE) && RTC_AVAILABLE
  if (_state != NetworkTimeState::Unset) {
    uint64_t unixTimeValue = 0;
    if (!rtc::unixTime(unixTimeValue))
      return NetworkTimeState::Unset;
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

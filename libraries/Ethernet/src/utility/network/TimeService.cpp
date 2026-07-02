#include "TimeService.h"

#include <RTC.h>

NetworkTimeService &NetworkTimeService::instance() {
  static NetworkTimeService service;
  return service;
}

NetworkTimeService &NetworkTime = NetworkTimeService::instance();

bool NetworkTimeService::begin() {
  if (!rtc::configureClock()) {
    _status = NetworkTimeServiceStatus::RtcUnavailable;
    _warnings |= NetworkTimeWarningRtcSetFailed;
    return false;
  }

  _begun = true;
  if (_status == NetworkTimeServiceStatus::Stopped)
    _status = NetworkTimeServiceStatus::Ready;
  return true;
}

void NetworkTimeService::reset() {
  _provisionalSource = NetworkTimeProvisionalSource{};
  _trustedSource = TrustedTimeSourcePolicy{};
  _unixTime = 0;
  _currentLevel = NetworkTimeLevel::Unset;
  _highestLevel = NetworkTimeLevel::Unset;
  _status = NetworkTimeServiceStatus::Stopped;
  _warnings = NetworkTimeWarningNone;
  _refreshIntervalSeconds = DefaultRefreshIntervalSeconds;
  _begun = false;
  rtc::clearTime();
}

bool NetworkTimeService::configureProvisionalSource(
    const NetworkTimeProvisionalSource &source) {
  if (!source.configured())
    return false;

  _provisionalSource = source;
  return true;
}

bool NetworkTimeService::configureProvisionalSource(IPAddress server,
                                                    uint16_t serverPort,
                                                    uint16_t localPort) {
  NetworkTimeProvisionalSource source;
  source.server = server;
  source.serverPort = serverPort;
  source.localPort = localPort;
  return configureProvisionalSource(source);
}

bool NetworkTimeService::configureTrustedSource(
    const TrustedTimeSourcePolicy &policy) {
  if (!policy.valid())
    return false;

  _trustedSource = policy;
  return true;
}

bool NetworkTimeService::setRefreshInterval(uint32_t seconds) {
  if (seconds == 0)
    return false;

  _refreshIntervalSeconds = seconds;
  return true;
}

bool NetworkTimeService::setManualUnixTime(uint64_t unixTime) {
  return applyTime(unixTime, NetworkTimeLevel::Manual);
}

NetworkTimeSnapshot NetworkTimeService::unixTime() const {
  NetworkTimeSnapshot snapshot;
  snapshot.unixTime = _unixTime;
  snapshot.trustLevel = _highestLevel;
  snapshot.status = _status;
  snapshot.warnings = _warnings;

  if (_highestLevel != NetworkTimeLevel::Unset) {
    uint64_t rtcUnixTime = 0;
    if (rtc::unixTime(rtcUnixTime))
      snapshot.unixTime = rtcUnixTime;
  }

  return snapshot;
}

bool NetworkTimeService::applyTime(uint64_t unixTime, NetworkTimeLevel level) {
  if (unixTime == 0 || level == NetworkTimeLevel::Unset)
    return false;

  if (_highestLevel >= NetworkTimeLevel::Trusted &&
      level < NetworkTimeLevel::Trusted) {
    _warnings |= NetworkTimeWarningLowerTrustUpdateRejected;
    _status = NetworkTimeServiceStatus::SourceUpdateFailed;
    return false;
  }

  if (!writeRtc(unixTime)) {
    _warnings |= NetworkTimeWarningRtcSetFailed;
    _status = NetworkTimeServiceStatus::RtcUnavailable;
    return false;
  }

  _unixTime = unixTime;
  _currentLevel = level;
  if (level > _highestLevel)
    _highestLevel = level;
  _status = NetworkTimeServiceStatus::TimeSet;
  return true;
}

bool NetworkTimeService::writeRtc(uint64_t unixTime) {
  return rtc::setUnixTime(unixTime);
}

#include "TimeService.h"

#include <RTC.h>
#include <utility/transport/TransportProvider.h>

NetworkTimeService &NetworkTimeService::instance() {
  static NetworkTimeService service;
  return service;
}

NetworkTimeService &NetworkTime = NetworkTimeService::instance();

bool NetworkTimeService::begin() {
  if (!_begun) {
    if (!rtc::configureClock() || !rtc::attachAlarmHandler(0, handleRtcEvent,
                                                           this)) {
      _status = NetworkTimeServiceStatus::RtcUnavailable;
      _warnings |= NetworkTimeWarningRtcSetFailed;
      return false;
    }

    _begun = true;
    if (_status == NetworkTimeServiceStatus::Stopped)
      _status = NetworkTimeServiceStatus::Ready;
  }

  if (_provider != nullptr)
    startSourceUpdate();
  return true;
}

bool NetworkTimeService::begin(TransportProvider &provider) {
  _provider = &provider;
  _provisionalClient.attach(provider, *this);
  _trustedClient.attach(provider, *this);
  return begin();
}

void NetworkTimeService::reset() {
  _provisionalSource = NetworkTimeProvisionalSource{};
  _trustedSource = NetworkTimeTrustedSourcePolicy{};
  _unixTime = 0;
  _highestLevel = NetworkTimeLevel::Unset;
  _status = NetworkTimeServiceStatus::Stopped;
  _warnings = NetworkTimeWarningNone;
  _refreshIntervalSeconds = DefaultRefreshIntervalSeconds;
  _begun = false;
  _refreshDue = false;
  _provider = nullptr;
  _provisionalClient.stop();
  _trustedClient.stop();
  rtc::clearAlarm(0);
  rtc::detachAlarmHandler(0);
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
    const NetworkTimeTrustedSourcePolicy &policy) {
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
  snapshot.highestConnectedLevel = _highestLevel;
  snapshot.status = _status;
  snapshot.warnings = _warnings;

  if (_highestLevel != NetworkTimeLevel::Unset) {
    uint64_t rtcUnixTime = 0;
    if (rtc::unixTime(rtcUnixTime)) {
      snapshot.unixTime = rtcUnixTime;
    } else {
      snapshot.unixTime = 0;
      snapshot.trustLevel = NetworkTimeLevel::Unset;
      snapshot.status = NetworkTimeServiceStatus::RtcUnavailable;
      snapshot.warnings |= NetworkTimeWarningRtcReadFailed;
    }
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
  if (level > _highestLevel)
    _highestLevel = level;
  _status = NetworkTimeServiceStatus::TimeSet;
  scheduleRefreshAlarm();
  return true;
}

bool NetworkTimeService::writeRtc(uint64_t unixTime) {
  return rtc::setUnixTime(unixTime);
}

void NetworkTimeService::handleRtcEvent(rtc::EventMask events, uint64_t,
                                        void *context) {
  auto *service = static_cast<NetworkTimeService *>(context);
  if (service == nullptr)
    return;

  if ((events & rtc::EventAlarm0) != 0)
    service->_refreshDue = true;
}

bool NetworkTimeService::startSourceUpdate() {
  _refreshDue = false;
  if (_provider == nullptr)
    return false;
  if (_provisionalClient.active() || _trustedClient.active())
    return true;

  if (_trustedSource.valid() &&
      _highestLevel >= NetworkTimeLevel::Provisional &&
      _highestLevel <= NetworkTimeLevel::Trusted) {
    if (_trustedClient.begin(_trustedSource)) {
      _status = NetworkTimeServiceStatus::SourceUpdatePending;
      return true;
    }
    recordSourceFailure(NetworkTimeLevel::Trusted);
    return false;
  }

  if (_provisionalSource.configured() &&
      _highestLevel < NetworkTimeLevel::Trusted) {
    if (_provisionalClient.beginRequest(_provisionalSource.server,
                                        _provisionalSource.serverPort,
                                        _provisionalSource.localPort)) {
      _status = NetworkTimeServiceStatus::SourceUpdatePending;
      return true;
    }
    recordSourceFailure(NetworkTimeLevel::Provisional);
    return false;
  }

  return false;
}

bool NetworkTimeService::advance() {
  if (_provisionalClient.active()) {
    const NetworkTimeClientStatus status = _provisionalClient.poll();
    if (status == NetworkTimeClientStatus::Pending)
      return true;
    if (status == NetworkTimeClientStatus::Failed) {
      recordSourceFailure(NetworkTimeLevel::Provisional);
      return false;
    }
    if (status == NetworkTimeClientStatus::Updated && _trustedSource.valid())
      startSourceUpdate();
    else if (status == NetworkTimeClientStatus::Updated)
      scheduleRefreshAlarm();
    return true;
  }

  if (_trustedClient.active()) {
    const NetworkTimeTrustedClientStatus status = _trustedClient.poll();
    if (status == NetworkTimeTrustedClientStatus::Connecting ||
        status == NetworkTimeTrustedClientStatus::Handshaking ||
        status == NetworkTimeTrustedClientStatus::Requesting ||
        status == NetworkTimeTrustedClientStatus::Receiving ||
        status == NetworkTimeTrustedClientStatus::Authenticating) {
      return true;
    }
    if (status == NetworkTimeTrustedClientStatus::Failed) {
      recordSourceFailure(NetworkTimeLevel::Trusted);
      return false;
    }
    if (status == NetworkTimeTrustedClientStatus::Updated)
      scheduleRefreshAlarm();
    return true;
  }

  if (_refreshDue)
    return startSourceUpdate();

  return false;
}

void NetworkTimeService::detachProvider(TransportProvider &provider) {
  if (_provider != &provider)
    return;

  _provisionalClient.stop();
  _trustedClient.stop();
  _provider = nullptr;
}

void NetworkTimeService::recordSourceFailure(NetworkTimeLevel level) {
  if (level == NetworkTimeLevel::Trusted)
    _warnings |= NetworkTimeWarningTrustedSourceFailed;
  else if (level == NetworkTimeLevel::Provisional)
    _warnings |= NetworkTimeWarningProvisionalSourceFailed;
  _status = NetworkTimeServiceStatus::SourceUpdateFailed;
  scheduleRefreshAlarm();
}

bool NetworkTimeService::scheduleRefreshAlarm() {
  if (!_begun || _refreshIntervalSeconds == 0)
    return false;

  uint64_t currentUnixTime = 0;
  if (!rtc::unixTime(currentUnixTime))
    currentUnixTime = _unixTime;
  if (currentUnixTime == 0)
    return false;

  return rtc::setAlarm(0, currentUnixTime + _refreshIntervalSeconds,
                       rtc::AlarmMatch::YearMonthDayHourMinuteSecond);
}

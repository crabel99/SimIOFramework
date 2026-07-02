#pragma once

#include <stdint.h>
#include <utility/network/NetworkTimeClient.h>
#include <utility/network/TrustedTimeClient.h>
#include <utility/network/time/Config.h>

class NetworkService;
class TransportProvider;

/**
 * @brief Singleton system-time daemon boundary for network-backed time.
 *
 * The service owns system-time authority above the RTC peripheral. RTC remains
 * a register/peripheral abstraction; this class owns source quality, trusted
 * promotion rules, refresh interval configuration, and the snapshot consumed by
 * SecureClient policy.
 */
class NetworkTimeService {
public:
  static constexpr uint32_t DefaultRefreshIntervalSeconds = 300;

  static NetworkTimeService &instance();
  NetworkTimeService(const NetworkTimeService &) = delete;
  NetworkTimeService &operator=(const NetworkTimeService &) = delete;

  bool begin();
  bool begin(TransportProvider &provider);
  void reset();

  bool configureProvisionalSource(const NetworkTimeProvisionalSource &source);
  bool configureProvisionalSource(
      IPAddress server,
      uint16_t serverPort = NetworkTimeProvisionalSource::DefaultServerPort,
      uint16_t localPort = NetworkTimeProvisionalSource::DefaultLocalPort);
  bool configureTrustedSource(const TrustedTimeSourcePolicy &policy);

  bool setRefreshInterval(uint32_t seconds);
  uint32_t refreshInterval() const { return _refreshIntervalSeconds; }

  bool setManualUnixTime(uint64_t unixTime);
  NetworkTimeSnapshot unixTime() const;

  NetworkTimeServiceStatus status() const { return _status; }
  uint16_t warnings() const { return _warnings; }
  bool provisionalSourceConfigured() const {
    return _provisionalSource.configured();
  }
  bool trustedSourceConfigured() const { return _trustedSource.valid(); }
  bool transportProviderConfigured() const { return _provider != nullptr; }
  bool updateActive() const {
    return _provisionalClient.active() || _trustedClient.active();
  }

private:
  friend class NetworkTimeClient;
  friend class TrustedTimeClient;
  friend class NetworkService;

  NetworkTimeService() = default;

  bool applyTime(uint64_t unixTime, NetworkTimeLevel level);
  bool writeRtc(uint64_t unixTime);
  bool startSourceUpdate();
  bool advance();
  void detachProvider(TransportProvider &provider);
  void recordSourceFailure(NetworkTimeLevel level);

  TransportProvider *_provider = nullptr;
  NetworkTimeProvisionalSource _provisionalSource;
  TrustedTimeSourcePolicy _trustedSource;
  NetworkTimeClient _provisionalClient;
  TrustedTimeClient _trustedClient;
  uint64_t _unixTime = 0;
  NetworkTimeLevel _currentLevel = NetworkTimeLevel::Unset;
  NetworkTimeLevel _highestLevel = NetworkTimeLevel::Unset;
  NetworkTimeServiceStatus _status = NetworkTimeServiceStatus::Stopped;
  uint16_t _warnings = NetworkTimeWarningNone;
  uint32_t _refreshIntervalSeconds = DefaultRefreshIntervalSeconds;
  bool _begun = false;
};

extern NetworkTimeService &NetworkTime;

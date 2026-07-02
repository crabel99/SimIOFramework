#pragma once

#include <RTC.h>
#include <stdint.h>
#include <utility/network/time/Client.h>
#include <utility/network/time/Config.h>
#include <utility/network/time/TrustedClient.h>

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

  /**
   * @brief Configure RTC/time-daemon plumbing and start any configured source.
   *
   * This is bounded and non-blocking. If a transport provider and time source
   * are configured, the source transaction is submitted and later advanced by
   * Ethernet service/RTC alarm flow. Read `unixTime()` for status, warnings,
   * and the current RTC-backed snapshot.
   */
  bool begin();
  bool begin(TransportProvider &provider);
  void reset();

  bool configureProvisionalSource(const NetworkTimeProvisionalSource &source);
  bool configureProvisionalSource(
      IPAddress server,
      uint16_t serverPort = NetworkTimeProvisionalSource::DefaultServerPort,
      uint16_t localPort = NetworkTimeProvisionalSource::DefaultLocalPort);
  bool configureTrustedSource(const NetworkTimeTrustedSourcePolicy &policy);

  bool setRefreshInterval(uint32_t seconds);
  uint32_t refreshInterval() const { return _refreshIntervalSeconds; }

  bool setManualUnixTime(uint64_t unixTime);
  NetworkTimeSnapshot unixTime() const;

private:
  friend class NetworkTimeClient;
  friend class NetworkTimeTrustedClient;
  friend class NetworkService;

  NetworkTimeService() = default;

  bool applyTime(uint64_t unixTime, NetworkTimeLevel level);
  bool writeRtc(uint64_t unixTime);
  static void handleRtcEvent(rtc::EventMask events, uint64_t unixTime,
                             void *context);

  bool startSourceUpdate();
  bool advance();
  void detachProvider(TransportProvider &provider);
  void recordSourceFailure(NetworkTimeLevel level);
  bool scheduleRefreshAlarm();

  TransportProvider *_provider = nullptr;
  NetworkTimeProvisionalSource _provisionalSource;
  NetworkTimeTrustedSourcePolicy _trustedSource;
  NetworkTimeClient _provisionalClient;
  NetworkTimeTrustedClient _trustedClient;
  uint64_t _unixTime = 0;
  NetworkTimeLevel _highestLevel = NetworkTimeLevel::Unset;
  NetworkTimeServiceStatus _status = NetworkTimeServiceStatus::Stopped;
  uint16_t _warnings = NetworkTimeWarningNone;
  uint32_t _refreshIntervalSeconds = DefaultRefreshIntervalSeconds;
  bool _begun = false;
  bool _refreshDue = false;
};

extern NetworkTimeService &NetworkTime;

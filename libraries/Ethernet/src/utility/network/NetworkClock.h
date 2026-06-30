#pragma once

#include <stdint.h>

class SecureClient;

enum class NetworkTimeTrust : uint8_t {
  Untrusted = 0,
  Trusted = 1,
};

enum class NetworkTimeState : uint8_t {
  Unset = 0,
  Manual = 1,
  Trusted = 2,
};

/**
 * @brief Network-facing Unix-time cache backed by the core RTC when present.
 *
 * This class stores wall-clock time separately from its authority. Manual or
 * unauthenticated NTP/SNTP time may establish a plausible wall clock for
 * certificate date validation, but TLS trust anchors must only consume time
 * supplied with `NetworkTimeState::Trusted`. Once trusted time is established,
 * manual time cannot overwrite or downgrade it.
 *
 * @todo Add an authenticated network-time source, such as NTS or a product
 * provisioning channel, before marking NTP-derived time trusted.
 */
class NetworkClock {
public:
  bool setUnixTime(uint64_t unixTime, NetworkTimeState state);
  bool setUnixTime(uint64_t unixTime, NetworkTimeTrust trust) {
    return setUnixTime(unixTime, trust == NetworkTimeTrust::Trusted
                                     ? NetworkTimeState::Trusted
                                     : NetworkTimeState::Manual);
  }
  void clear();
  void clearTrusted();

  bool unixTime(uint64_t &unixTime) const;
  bool trustedUnixTime(uint64_t &unixTime) const;
  bool trusted() const;
  NetworkTimeState timeState() const;

  bool applyTrustedTime(SecureClient &client) const;

private:
  uint64_t _unixTime = 0;
  NetworkTimeState _state = NetworkTimeState::Unset;
};

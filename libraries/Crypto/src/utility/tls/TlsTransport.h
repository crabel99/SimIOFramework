/**
 * @file TlsTransport.h
 * @brief Transport abstraction consumed by async TLS sessions.
 *
 * TLS is not Ethernet-specific. `TlsTransport` is the small non-blocking I/O
 * boundary that Ethernet, Wi-Fi, USB, or a test harness can adapt into the
 * Crypto TLS layer. Implementations must return immediately and report
 * fail-closed values when disconnected, carrier is down, or no data/space is
 * available.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace Crypto {

class TlsTransport {
public:
  virtual ~TlsTransport() = default;

  virtual bool carrierUp() const = 0;
  virtual uint8_t connected() = 0;
  virtual size_t write(const uint8_t *buffer, size_t size) = 0;
  virtual int available() = 0;
  virtual int read(uint8_t *buffer, size_t size) = 0;
  virtual void stop() = 0;
};

} // namespace Crypto

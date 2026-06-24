#pragma once

#include <Client.h>
#include <IPAddress.h>

#include <stddef.h>
#include <stdint.h>

class EthernetSocket {
public:
  virtual ~EthernetSocket() = default;

  virtual bool carrierUp() const = 0;
  virtual int connect(IPAddress ip, uint16_t port) = 0;
  virtual int connect(const char *host, uint16_t port) = 0;
  virtual size_t write(uint8_t value) = 0;
  virtual size_t write(const uint8_t *buffer, size_t size) = 0;
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int read(uint8_t *buffer, size_t size) = 0;
  virtual int peek() = 0;
  virtual void flush() = 0;
  virtual void stop() = 0;
  virtual uint8_t connected() = 0;
};

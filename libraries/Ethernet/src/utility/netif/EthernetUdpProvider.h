#pragma once

#include <IPAddress.h>

#include <stddef.h>
#include <stdint.h>

class EthernetUdpProvider {
public:
  virtual ~EthernetUdpProvider() = default;

  virtual uint8_t beginUdp(uint16_t port) = 0;
  virtual uint8_t beginUdpMulticast(IPAddress ip, uint16_t port) = 0;
  virtual void stopUdp() = 0;
  virtual int beginUdpPacket(IPAddress ip, uint16_t port) = 0;
  virtual int beginUdpPacket(const char *host, uint16_t port) = 0;
  virtual int endUdpPacket() = 0;
  virtual size_t writeUdp(uint8_t value) = 0;
  virtual size_t writeUdp(const uint8_t *buffer, size_t size) = 0;
  virtual int parseUdpPacket() = 0;
  virtual int availableUdp() = 0;
  virtual int readUdp() = 0;
  virtual int readUdp(uint8_t *buffer, size_t size) = 0;
  virtual int peekUdp() = 0;
  virtual void flushUdp() = 0;
  virtual IPAddress remoteUdpIP() = 0;
  virtual uint16_t remoteUdpPort() = 0;
};

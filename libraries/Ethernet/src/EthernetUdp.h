#pragma once

#include <Udp.h>
#include <utility/netif/EthernetUdpProvider.h>

class EthernetUDP : public UDP {
public:
  EthernetUDP();
  explicit EthernetUDP(EthernetUdpProvider &provider);

  void setProvider(EthernetUdpProvider &provider);
  void clearProvider();

  uint8_t begin(uint16_t port) override;
  uint8_t beginMulticast(IPAddress ip, uint16_t port) override;
  void stop() override;
  int beginPacket(IPAddress ip, uint16_t port) override;
  int beginPacket(const char *host, uint16_t port) override;
  int endPacket() override;
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int parsePacket() override;
  int available() override;
  int read() override;
  int read(unsigned char *buffer, size_t len) override;
  int read(char *buffer, size_t len) override;
  int peek() override;
  void flush() override;
  IPAddress remoteIP() override;
  uint16_t remotePort() override;
  operator bool() const { return _provider != nullptr; }

  using Print::write;

private:
  EthernetUdpProvider *_provider;
};

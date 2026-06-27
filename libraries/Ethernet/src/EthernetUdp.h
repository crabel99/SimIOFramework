/**
 * @file EthernetUdp.h
 * @brief Arduino UDP facade backed by TransportProvider UDP operations.
 *
 * `EthernetUDP` owns Arduino `UDP` API validation and delegates endpoint,
 * packet, and receive-buffer behavior to the provider. It must not own lwIP UDP
 * control blocks, network interface state, frame buffers, or hardware details.
 */
#pragma once

#include <Udp.h>
#include <utility/transport/TransportProvider.h>

class EthernetUDP : public UDP {
public:
  EthernetUDP();
  explicit EthernetUDP(TransportProvider &provider);

  void setProvider(TransportProvider &provider);
  void clearProvider();

  /**
   * @brief Bind UDP endpoint state through the provider.
   */
  uint8_t begin(uint16_t port) override;
  uint8_t beginMulticast(IPAddress ip, uint16_t port) override;
  void stop() override;

  /**
   * @brief Delegate one outbound UDP packet lifecycle to the provider.
   */
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
  TransportProvider *_provider;
};

/**
 * @file EthernetUdp.h
 * @brief Arduino UDP facade backed by TransportProvider UDP operations.
 *
 * `EthernetUDP` owns Arduino `UDP` API validation and delegates endpoint,
 * packet, and receive-buffer behavior to the provider. It must not own lwIP UDP
 * control blocks, network interface state, frame buffers, or hardware details.
 */
#pragma once

#include <utility/EthernetTarget.h>

#include <Udp.h>
#include <utility/transport/TransportProvider.h>

class EthernetUDP : public UDP {
public:
  /**
   * @brief Construct using the registered default provider, if any.
   *
   * The provider is snapshotted at construction. Without a default provider,
   * UDP operations fail closed until `setProvider()` is called.
   */
  EthernetUDP();

  /**
   * @brief Construct around an explicit transport provider.
   */
  explicit EthernetUDP(TransportProvider &provider);

  /**
   * @brief Replace the provider after stopping the current UDP endpoint.
   */
  void setProvider(TransportProvider &provider);

  /**
   * @brief Stop the current UDP endpoint and fail closed.
   */
  void clearProvider();

  /**
   * @brief Bind UDP endpoint state through the provider.
   */
  uint8_t begin(uint16_t port) override;
  uint8_t beginMulticast(IPAddress ip, uint16_t port) override;
  void stop() override;

  /**
   * @brief Delegate one outbound UDP packet lifecycle to the provider.
   *
   * The provider owns packet buffering, DNS policy, multicast membership, and
   * receive state. This facade validates Arduino API inputs and fails closed
   * when no provider is attached.
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
  bool _active;
};

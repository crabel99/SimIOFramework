/**
 * @file EthernetServer.h
 * @brief Arduino Server facade backed by TransportProvider listener state.
 *
 * `EthernetServer` owns Arduino `Server` API behavior for a single listen port.
 * The provider owns actual listener/socket objects. Accepted clients receive
 * provider-owned sockets and release them through `EthernetClient`.
 */
#pragma once

#include <EthernetClient.h>
#include <Server.h>
#include <utility/transport/TransportProvider.h>

class EthernetServer : public Server {
public:
  explicit EthernetServer(uint16_t port);
  EthernetServer(uint16_t port, TransportProvider &provider);
  ~EthernetServer();

  void setProvider(TransportProvider &provider);
  void clearProvider();

  /**
   * @brief Start listening through the provider.
   */
  void begin() override;
  void stop();

  /**
   * @brief Return the next accepted client, or a disconnected client if none.
   */
  EthernetClient available();
  EthernetClient accept();

  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;

  bool listening() const { return _listening; }
  uint16_t port() const { return _port; }

  using Print::write;

private:
  uint16_t _port;
  TransportProvider *_provider;
  bool _listening;
};

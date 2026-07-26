/**
 * @file EthernetServer.h
 * @brief Arduino Server facade backed by TransportProvider listener state.
 *
 * `EthernetServer` owns Arduino `Server` API behavior for a single listen port.
 * The provider owns actual listener/socket objects. Accepted clients receive
 * provider-owned sockets and release them through `EthernetClient`.
 */
#pragma once

#include <utility/EthernetTarget.h>

#include <EthernetClient.h>
#include <Server.h>
#include <utility/transport/TransportProvider.h>

class EthernetServer : public Server {
public:
  /**
   * @brief Construct using the registered default provider, if any.
   *
   * The provider is snapshotted at construction. Without a default provider,
   * `begin()` leaves the server fail-closed.
   */
  explicit EthernetServer(uint16_t port);

  /**
   * @brief Construct around an explicit transport provider.
   */
  EthernetServer(uint16_t port, TransportProvider &provider);
  ~EthernetServer();

  /**
   * @brief Replace the provider after stopping the current listener.
   */
  void setProvider(TransportProvider &provider);

  /**
   * @brief Stop the current listener and fail closed until a provider is set.
   */
  void clearProvider();

  /**
   * @brief Start listening through the provider.
   */
  void begin() override;

  /**
   * @brief Stop the provider listener without invalidating accepted clients.
   */
  void stop();

  /**
   * @brief Return the next accepted client, or a disconnected client if none.
   *
   * Accepted clients own their provider socket independently from the server
   * listener and release it through `EthernetClient`.
   */
  EthernetClient available();
  EthernetClient accept();

  /**
   * @brief Write to all provider-managed accepted server clients.
   */
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

#pragma once

#include <EthernetClient.h>
#include <Server.h>
#include <utility/netif/EthernetServerProvider.h>

class EthernetServer : public Server {
public:
  EthernetServer(uint16_t port, EthernetServerProvider &provider);
  ~EthernetServer();

  void begin() override;
  void stop();
  EthernetClient available();
  EthernetClient accept();

  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;

  bool listening() const { return _listening; }
  uint16_t port() const { return _port; }

  using Print::write;

private:
  uint16_t _port;
  EthernetServerProvider *_provider;
  bool _listening;
};

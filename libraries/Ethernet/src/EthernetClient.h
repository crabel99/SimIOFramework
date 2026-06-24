#pragma once

#include <Client.h>
#include <utility/netif/EthernetSocket.h>

class EthernetClient : public Client {
public:
  EthernetClient();
  explicit EthernetClient(EthernetSocket &socket);

  void setSocket(EthernetSocket &socket);
  void clearSocket();

  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t *buffer, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;
  operator bool() override;

  using Print::write;

private:
  EthernetSocket *_socket;
};

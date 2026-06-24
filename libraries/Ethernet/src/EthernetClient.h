#pragma once

#include <Client.h>
#include <utility/transport/TransportProvider.h>

class EthernetClient : public Client {
public:
  EthernetClient();
  explicit EthernetClient(EthernetSocket &socket);
  explicit EthernetClient(TransportProvider &provider);
  EthernetClient(TransportProvider &provider, EthernetSocket &socket);
  EthernetClient(const EthernetClient &) = delete;
  EthernetClient &operator=(const EthernetClient &) = delete;
  EthernetClient(EthernetClient &&other);
  EthernetClient &operator=(EthernetClient &&other);
  ~EthernetClient();

  void setSocket(EthernetSocket &socket);
  void setTransportProvider(TransportProvider &provider);
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

protected:
  virtual EthernetSocket *acquireProviderSocket();
  TransportProvider *transportProvider() const { return _provider; }

private:
  bool ensureSocket();
  void releaseOwnedSocket();

  EthernetSocket *_socket;
  TransportProvider *_provider;
  bool _ownsSocket;
};

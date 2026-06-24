#pragma once

#include <EthernetClient.h>
#include <utility/transport/TransportProvider.h>

enum SecureClientError : int {
  SecureClientNoError = 0,
  SecureClientTlsUnavailable = -1,
  SecureClientConnectFailed = -2,
};

class SecureClient : public EthernetClient {
public:
  SecureClient();
  explicit SecureClient(EthernetSocket &socket);
  explicit SecureClient(TransportProvider &provider);
  SecureClient(const SecureClient &) = delete;
  SecureClient &operator=(const SecureClient &) = delete;
  SecureClient(SecureClient &&other);
  SecureClient &operator=(SecureClient &&other);

  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;

  bool tlsAvailable() const;
  int lastError() const;

private:
  EthernetSocket *acquireProviderSocket() override;

  int _lastError;
};

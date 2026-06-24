#pragma once

#include <EthernetClient.h>

enum SecureClientError : int {
  SecureClientNoError = 0,
  SecureClientTlsUnavailable = -1,
};

class SecureClient : public EthernetClient {
public:
  SecureClient() : EthernetClient(), _lastError(SecureClientNoError) {}
  explicit SecureClient(EthernetSocket &socket)
      : EthernetClient(socket), _lastError(SecureClientNoError) {}

  int connect(IPAddress, uint16_t) override {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }

  int connect(const char *, uint16_t) override {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }

  bool tlsAvailable() const { return false; }
  int lastError() const { return _lastError; }

private:
  int _lastError;
};

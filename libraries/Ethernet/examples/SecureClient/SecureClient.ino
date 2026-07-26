#include <Arduino.h>
#include <Ethernet.h>
#include <SecureClient.h>
#include <utility/mbedtls/MbedTlsPort.h>
#include <utility/netif/FrameDriverAdapter.h>
#include <utility/network/NetworkService.h>
#include <utility/network/TimeService.h>
#include <utility/phy/KSZ8091Phy/KSZ8091Phy.h>

#include <string.h>

namespace {
constexpr uint8_t MacAddress[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

constexpr char TlsHost[] = "example.com";
constexpr uint16_t TlsPort = 443;

const IPAddress ProvisionalTimeServer(129, 6, 15, 28);

constexpr char TrustAnchors[] = R"pem(
-----BEGIN CERTIFICATE-----
Replace this PEM block with the CA certificate that signs TlsHost.
-----END CERTIFICATE-----
)pem";

class ExamplePacket : public EthernetPacket {
public:
  const uint8_t *data() const override { return _frame; }
  uint16_t length() const override { return _length; }
  void release() override { _inUse = false; }

  bool copyFrom(const uint8_t *frame, uint16_t length) {
    if (_inUse || frame == nullptr || length == 0 || length > sizeof(_frame))
      return false;

    memcpy(_frame, frame, length);
    _length = length;
    _inUse = true;
    return true;
  }

private:
  bool _inUse = false;
  uint16_t _length = 0;
  uint8_t _frame[1536] = {};
};

class ExamplePacketAllocator : public EthernetPacketAllocator {
public:
  EthernetPacket *allocateCopy(const uint8_t *frame, uint16_t length) override {
    return _packet.copyFrom(frame, length) ? &_packet : nullptr;
  }

private:
  ExamplePacket _packet;
};

KSZ8091Phy phy(0);
EthernetClass ethernet(MacAddress, phy);
EthernetClassFrameDriver frameDriver(ethernet);
ExamplePacketAllocator packetAllocator;
NetworkService network(frameDriver, packetAllocator);
Crypto::MbedTlsPort::MbedTlsCryptoProvider tlsCrypto;
SecureClient client(network.transportProvider());

void logLine(const char *message) {
#if defined(USBCON)
  Serial.println(message);
#else
  (void)message;
#endif
}

void logByte(int value) {
#if defined(USBCON)
  Serial.write(value);
#else
  (void)value;
#endif
}

void configureBoardEthernetPins() {
  // Board packages should configure the GMAC RMII pins before Ethernet begin.
}

bool waitForAddress(uint32_t timeoutMs) {
  const uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    ethernet.service();
    network.service();
    if (network.addressAssigned())
      return true;
  }
  return false;
}

bool waitForNetworkTime(NetworkTimeLevel required, uint32_t timeoutMs) {
  const uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    ethernet.service();
    network.service();
    if (NetworkTime.unixTime().satisfies(required))
      return true;
  }
  return false;
}

bool waitForTlsHandshake(uint32_t timeoutMs) {
  const uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    ethernet.service();
    network.service();
    client.pollTls();
    if (client.tlsHandshakeComplete())
      return true;
    if (client.tlsLastError() != SecureClientNoError)
      return false;
  }
  return false;
}
} // namespace

void setup() {
#if defined(USBCON)
  Serial.begin(115200);
  while (!Serial && millis() < 3000) {
  }
#endif

  configureBoardEthernetPins();

  if (ethernet.begin() != 1) {
    logLine("Ethernet hardware start failed");
    return;
  }

  network.configureDhcp();
  if (!network.begin()) {
    logLine("Network stack start failed");
    return;
  }
  network.registerAsDefaultProvider();

  // While the Ethernet network stack is active, RTC ALARM0 is reserved for the
  // network time daemon and RTC PER4 is reserved for lwIP NO_SYS timers.

  if (!waitForAddress(15000)) {
    logLine("No DHCP address");
    return;
  }

  NetworkTime.configureProvisionalSource(ProvisionalTimeServer);
  NetworkTime.begin(network.transportProvider());

  if (!waitForNetworkTime(NetworkTimeLevel::Provisional, 10000)) {
    logLine("No provisional network time");
    return;
  }

  if (!client.setCryptoProvider(tlsCrypto) ||
      !client.setTlsSecurityLevel(SecureClientTlsSecurityLevel::Medium) ||
      !client.setTrustAnchors(reinterpret_cast<const uint8_t *>(TrustAnchors),
                              sizeof(TrustAnchors)) ||
      !client.setHostname(TlsHost)) {
    logLine("TLS configuration failed");
    return;
  }

  if (client.connect(TlsHost, TlsPort) != 1) {
    logLine("TCP connect submit failed");
    return;
  }

  if (!waitForTlsHandshake(15000)) {
    logLine("TLS handshake failed");
    return;
  }

  client.println("GET / HTTP/1.1");
  client.print("Host: ");
  client.println(TlsHost);
  client.println("Connection: close");
  client.println();
}

void loop() {
  ethernet.service();
  network.service();
  client.pollTls();

  while (client.available() > 0)
    logByte(client.read());

  if (!client.connected())
    client.stop();
}

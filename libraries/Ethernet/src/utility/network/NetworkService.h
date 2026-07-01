#pragma once

#include <utility/lwip/LwipPort.h>
#include <utility/lwip/LwipTransportBackend.h>
#include <utility/netif/FrameDriver.h>
#include <utility/netif/Netif.h>
#include <utility/network/NetworkConfig.h>
#include <utility/network/NetworkClock.h>

/**
 * @file NetworkService.h
 * @brief Lifecycle owner for the Ethernet network stack above frame I/O.
 *
 * `NetworkService` wires a frame driver through `EthernetNetif`, `LwipPort`,
 * and the lwIP socket backend. It owns network stack start/service/stop order,
 * packet allocator binding, and address configuration application.
 *
 * This class is intentionally below public `EthernetClient`, `EthernetServer`,
 * `EthernetUDP`, and `SecureClient` objects. It must not decode PHY registers,
 * perform MDIO/MIIM transactions, own GMAC descriptors, or expose lwIP protocol
 * control blocks to public API classes.
 */
class NetworkService {
public:
  NetworkService(EthernetFrameDriver &frameDriver,
                 EthernetPacketAllocator &packetAllocator);

  /**
   * @brief Apply configured addressing and start the netif/lwIP boundary.
   *
   * This call is bounded. DHCP mode starts the DHCP client but does not wait for
   * a lease to be assigned.
   */
  bool begin();

  /**
   * @brief Stop lwIP-facing transport and detach netif callbacks.
   */
  void end();

  /**
   * @brief Advance bounded network work.
   *
   * This delegates to `LwipPort::service()` only after `begin()` succeeds.
   */
  bool service();

  /**
   * @brief Return cached carrier state from the netif/lwIP boundary.
   */
  bool carrierUp() const;

  /**
   * @brief Select DHCP address configuration.
   *
   * DHCP activation is deferred to `begin()` or applied immediately if the
   * service is already started. Lease acquisition remains asynchronous.
   */
  void configureDhcp();

  /**
   * @brief Select static address configuration.
   */
  void configureStatic(IPAddress localIp);
  void configureStatic(IPAddress localIp, IPAddress dnsServer);
  void configureStatic(IPAddress localIp, IPAddress dnsServer,
                       IPAddress gateway);
  void configureStatic(IPAddress localIp, IPAddress dnsServer,
                       IPAddress gateway, IPAddress subnet);

  /**
   * @brief Return the stored network configuration.
   */
  const NetworkConfig &networkConfig() const { return _networkConfig; }

  /**
   * @brief Access the service-owned network clock bridge.
   *
   * Unauthenticated NTP/SNTP updates must be stored as untrusted. Only
   * authenticated time sources should be marked trusted and applied to TLS.
   */
  NetworkClock &clock() { return _clock; }
  const NetworkClock &clock() const { return _clock; }

  /**
   * @brief Return true when DHCP or static addressing has been selected.
   */
  bool networkConfigured() const;

  /**
   * @brief Return true when the lwIP DHCP client is active.
   *
   * Active does not mean that a lease has been supplied.
   */
  bool dhcpActive() const;

  /**
   * @brief Return true when lwIP reports a DHCP lease address is supplied.
   */
  bool dhcpAddressSupplied() const;

  /**
   * @brief Return true when lwIP currently has a non-zero local IPv4 address.
   */
  bool addressAssigned() const;

  /**
   * @brief Return lwIP's current local IPv4 address or zero when unavailable.
   */
  IPAddress localIP() const;
  IPAddress gatewayIP() const;
  IPAddress subnetMask() const;
  IPAddress dnsServerIP() const;

  /**
   * @brief Access the underlying netif for tests and internal wiring.
   */
  EthernetNetif &netif() { return _netif; }

  /**
   * @brief Access the lwIP port for tests and internal wiring.
   */
  EthernetLwipPort &lwipPort() { return _lwipPort; }

  /**
   * @brief Access the concrete lwIP transport backend for diagnostics.
   *
   * This remains below the public Arduino API boundary. It is intended for
   * focused stack tests and bring-up diagnostics that need backend counters
   * without exposing lwIP protocol control blocks.
   */
  LwipTransportBackend &transportBackend() { return _socketBackend; }
  const LwipTransportBackend &transportBackend() const { return _socketBackend; }

  /**
   * @brief Return the provider boundary consumed by public TCP/UDP/TLS facades.
   *
   * Callers may pass this explicitly to `EthernetClient`, `EthernetServer`,
   * `EthernetUDP`, or `SecureClient`, or register it with
   * `TransportProvider::setDefaultProvider()` while this service remains alive.
   * The service retains ownership; public facades must not delete or inspect the
   * provider.
   */
  TransportProvider &transportProvider() { return _lwipPort; }
  const TransportProvider &transportProvider() const { return _lwipPort; }

  /**
   * @brief Install optional provider-owned trusted-time bootstrap logic.
   *
   * `SecureClient` can trigger this when it has all TLS policy except trusted
   * time. The bootstrapper remains caller-owned and must outlive this service
   * registration. It must promote only authenticated trusted time into
   * `clock()`.
   */
  void setTrustedTimeBootstrapper(TrustedTimeBootstrapper &bootstrapper);
  void clearTrustedTimeBootstrapper();

  /**
   * @brief Register this service as the default provider for public facades.
   *
   * This is a non-owning registration. Board packages, examples, or application
   * composition code should call this after constructing the long-lived service
   * object that owns the frame driver and packet allocator. `EthernetClass`
   * remains the low-level hardware object and does not own this registration.
   */
  void registerAsDefaultProvider();

  /**
   * @brief Clear the default provider if it currently points at this service.
   */
  void clearDefaultProvider();

private:
  EthernetPacketAllocator *_packetAllocator;
  EthernetNetif _netif;
  LwipTransportBackend _socketBackend;
  EthernetLwipPort _lwipPort;
  NetworkConfig _networkConfig;
  NetworkClock _clock;
  bool _started;
};

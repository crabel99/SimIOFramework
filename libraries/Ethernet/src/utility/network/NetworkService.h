#pragma once

#include <utility/lwip/LwipPort.h>
#include <utility/lwip/LwipTransportBackend.h>
#include <utility/netif/FrameDriver.h>
#include <utility/netif/Netif.h>
#include <utility/network/NetworkConfig.h>

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

private:
  EthernetPacketAllocator *_packetAllocator;
  EthernetNetif _netif;
  LwipTransportBackend _socketBackend;
  EthernetLwipPort _lwipPort;
  NetworkConfig _networkConfig;
  bool _started;
};

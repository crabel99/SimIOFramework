/**
 * @file EthernetTarget.h
 * @brief Compile-time target gate for Ethernet public APIs.
 *
 * The Ethernet library is backed by the SAME53/SAME54 GMAC peripheral.
 * Public Ethernet facades fail at compile time on unsupported production
 * targets so sketches cannot accidentally build TCP/UDP/TLS APIs with no MAC
 * hardware underneath them.
 */
#pragma once

#if defined(__SAME53__) || defined(__SAME54__)
#define ETHERNET_TARGET_SUPPORTED 1
#else
#define ETHERNET_TARGET_SUPPORTED 0
#endif

#if !ETHERNET_TARGET_SUPPORTED && !defined(NATIVE_TEST) &&                   \
    !defined(ETHERNET_ALLOW_UNSUPPORTED_TEST_BUILD)
#error "Ethernet requires SAME53/SAME54 GMAC hardware; this target cannot use Ethernet, EthernetClient, EthernetServer, EthernetUDP, SecureClient, or TransportProvider."
#endif

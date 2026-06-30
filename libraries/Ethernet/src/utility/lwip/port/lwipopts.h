/**
 * @file lwipopts.h
 * @brief SimIO Ethernet lwIP configuration.
 *
 * This configuration imports lwIP as a service-driven, no-OS TCP/IP stack.
 * Public Arduino sockets remain behind SimIO transport adapters; do not enable
 * lwIP's BSD socket/netconn layer here unless a real `sys_arch` port is added.
 */
#pragma once

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 1

#define LWIP_IPV4 1
#define LWIP_IPV6 0

#define LWIP_ARP 1
#define LWIP_ETHERNET 1
#define LWIP_ICMP 1
#define LWIP_IGMP 1
/* Raw IP PCBs are not used; UDP/TCP still use lwIP's callback APIs. */
#define LWIP_RAW 0

#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DHCP 1
#define LWIP_DNS 1
#define LWIP_AUTOIP 0

#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_API 0

#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_EXT_STATUS_CALLBACK 0

#define LWIP_TCPIP_CORE_LOCKING 0
#define LWIP_TIMERS 1

#define MEM_ALIGNMENT 4
#ifndef MEM_SIZE
#define MEM_SIZE (24 * 1024)
#endif
#if defined(NATIVE_TEST)
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#else
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#endif
#ifndef MEMP_NUM_PBUF
#define MEMP_NUM_PBUF 16
#endif
#ifndef MEMP_NUM_UDP_PCB
#define MEMP_NUM_UDP_PCB 8
#endif
#ifndef MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB 6
#endif
#ifndef MEMP_NUM_TCP_PCB_LISTEN
#define MEMP_NUM_TCP_PCB_LISTEN 4
#endif
#ifndef MEMP_NUM_TCP_SEG
#define MEMP_NUM_TCP_SEG 24
#endif
#ifndef MEMP_NUM_SYS_TIMEOUT
#define MEMP_NUM_SYS_TIMEOUT 12
#endif

#ifndef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE 16
#endif
#ifndef PBUF_POOL_BUFSIZE
#define PBUF_POOL_BUFSIZE 1536
#endif

#define TCP_MSS 1460
#ifndef TCP_SND_BUF
#define TCP_SND_BUF (4 * TCP_MSS)
#endif
#ifndef TCP_WND
#define TCP_WND (4 * TCP_MSS)
#endif
#ifndef TCP_SND_QUEUELEN
#define TCP_SND_QUEUELEN 16
#endif
#define TCP_LISTEN_BACKLOG 1

#ifndef DNS_TABLE_SIZE
#define DNS_TABLE_SIZE 4
#endif
#ifndef DNS_MAX_NAME_LENGTH
#define DNS_MAX_NAME_LENGTH 128
#endif

#define LWIP_STATS 0
#define LWIP_PROVIDE_ERRNO 1
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
uint32_t simio_lwip_rand(void);
#ifdef __cplusplus
}
#endif

#define LWIP_RAND() simio_lwip_rand()

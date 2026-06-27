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
#define MEM_SIZE (24 * 1024)
#if defined(NATIVE_TEST)
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#else
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#endif
#define MEMP_NUM_PBUF 16
#define MEMP_NUM_UDP_PCB 8
#define MEMP_NUM_TCP_PCB 6
#define MEMP_NUM_TCP_PCB_LISTEN 4
#define MEMP_NUM_TCP_SEG 24
#define MEMP_NUM_SYS_TIMEOUT 12

#define PBUF_POOL_SIZE 16
#define PBUF_POOL_BUFSIZE 1536

#define TCP_MSS 1460
#define TCP_SND_BUF (4 * TCP_MSS)
#define TCP_WND (4 * TCP_MSS)
#define TCP_SND_QUEUELEN 16
#define TCP_LISTEN_BACKLOG 1

#define DNS_TABLE_SIZE 4
#define DNS_MAX_NAME_LENGTH 128

#define LWIP_STATS 0
#define LWIP_PROVIDE_ERRNO 1
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_RAND() 0x12345678UL

/**
 * @file cc.h
 * @brief Arduino lwIP compiler/CPU definitions.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

typedef int sys_prot_t;

#define SYS_ARCH_DECL_PROTECT(lev) sys_prot_t lev
#define SYS_ARCH_PROTECT(lev)                                                   \
  do {                                                                          \
    (lev) = 0;                                                                  \
  } while (0)
#define SYS_ARCH_UNPROTECT(lev)                                                 \
  do {                                                                          \
    (void)(lev);                                                                \
  } while (0)

#define LWIP_PLATFORM_DIAG(x)                                                   \
  do {                                                                          \
    printf x;                                                                   \
  } while (0)

#define LWIP_PLATFORM_ASSERT(x)                                                 \
  do {                                                                          \
    printf("lwIP assert: %s\n", (x));                                           \
  } while (0)

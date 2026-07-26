/**
 * @file LwipSystem.cpp
 * @brief Minimal lwIP time hook for the Arduino no-OS port.
 */
#include <Arduino.h>
#include <lwip/sys.h>

extern "C" u32_t sys_now(void) { return static_cast<u32_t>(millis()); }

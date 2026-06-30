#pragma once

#include <stdint.h>

namespace EthernetLwipRandom {

/**
 * @brief Seed the lwIP random stream used for TCP/DHCP/DNS IDs and ports.
 *
 * The stream is intentionally owned by the Ethernet/lwIP port, not by TLS.
 * Hardware builds seed it from TRNG during explicit Ethernet setup; packet I/O
 * and lwIP callbacks only consume already-seeded state.
 */
void seed(uint32_t value);

/**
 * @brief Mix additional entropy into the current stream state.
 */
void mix(uint32_t value);

/**
 * @brief Return true once the stream has been explicitly seeded.
 */
bool seeded();

/**
 * @brief Try to seed from the hardware entropy source at setup time.
 */
bool seedFromHardware();

/**
 * @brief Return one non-constant lwIP random word.
 */
uint32_t next();

#if defined(NATIVE_TEST)
void resetForTest();
#endif

} // namespace EthernetLwipRandom

extern "C" uint32_t simio_lwip_rand(void);

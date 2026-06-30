#include "LwipRandom.h"

#include <stdint.h>

#if !defined(NATIVE_TEST)
#include <TRNG.h>
#endif

namespace {
uint32_t state = 0x6d2b79f5UL;
bool hasSeed = false;

uint32_t normalizeSeed(uint32_t value) {
  return value == 0 ? 0xa5a5a5a5UL : value;
}

uint32_t mixWord(uint32_t value) {
  value ^= value >> 16;
  value *= 0x7feb352dUL;
  value ^= value >> 15;
  value *= 0x846ca68bUL;
  value ^= value >> 16;
  return normalizeSeed(value);
}

uint32_t advance(uint32_t value) {
  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  return normalizeSeed(value);
}

void scrub(uint32_t &value) {
  volatile uint32_t *word = &value;
  *word = 0;
}
} // namespace

namespace EthernetLwipRandom {

void seed(uint32_t value) {
  state = mixWord(value);
  hasSeed = true;
}

void mix(uint32_t value) {
  state = mixWord(state ^ value ^ 0x9e3779b9UL);
  hasSeed = true;
}

bool seeded() { return hasSeed; }

bool seedFromHardware() {
  if (hasSeed)
    return true;

#if defined(NATIVE_TEST)
  seed(0x13579bdfUL);
  return true;
#elif TRNG_AVAILABLE
  const bool wasEnabled = trng::enabled();
  if (!wasEnabled)
    trng::begin(false);

  uint32_t value = 0;
  bool read = false;
  for (uint16_t attempt = 0; attempt < 1024; ++attempt) {
    if (trng::read(value)) {
      read = true;
      break;
    }
  }

  if (!wasEnabled)
    trng::end();

  if (!read)
    return false;

  mix(value);
  scrub(value);
  return true;
#else
  return hasSeed;
#endif
}

uint32_t next() {
  state = advance(state);
  return state;
}

#if defined(NATIVE_TEST)
void resetForTest() {
  state = 0x6d2b79f5UL;
  hasSeed = false;
}
#endif

} // namespace EthernetLwipRandom

extern "C" uint32_t simio_lwip_rand(void) {
  return EthernetLwipRandom::next();
}

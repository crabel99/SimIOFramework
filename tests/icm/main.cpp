#include "../../cores/arduino/ICM.cpp"
#include <assert.h>
#include <stdio.h>
#include <vector>
#include <openssl/sha.h>

icm_registers_t testIcm{};
mclk_registers_t testMclk{};
nvmctrl_registers_t testNvm{};
TestDwt testDwt{};
PendSV& PendSV::instance() { static PendSV instance; return instance; }
bool PendSV::registerService(uint8_t id, ServiceFn fn, void* context) {
  services_[id].fn = fn; services_[id].context = context; return true;
}
void PendSV::clearService(uint8_t id) { services_[id] = {}; pendingMask_ = 0; }
void PendSV::setPending(uint8_t id) { pendingMask_ |= 1u << id; }
void PendSV::dispatchPending() {
  while (pendingMask_) {
    for (uint8_t id = 0; id < kMaxServices; ++id) {
      if (pendingMask_ & (1u << id)) {
        pendingMask_ &= ~(1u << id);
        if (services_[id].fn) services_[id].fn(id, services_[id].context);
      }
    }
  }
}

static unsigned callbacks;
static icm::EventMask delivered;
static void callback(icm::EventMask events, void*) { ++callbacks; delivered = events; }
static void resetTest() {
  icm::clearEventCallback();
  asyncState = {};
  testIcm.ICM_SR = 0;
  testIcm.ICM_ISR = 0;
  callbacks = 0;
  delivered = 0;
  assert(icm::registerEventCallback(callback));
}
static void paddingAndDigest(size_t length) {
  std::vector<uint8_t> input(length);
  for (size_t i = 0; i < length; ++i) input[i] = uint8_t(i);
  const icm::HashSegment segment{input.data(), length};
  assert(prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 0));
  const size_t tail = length % 64;
  const size_t padded = tail < 56 ? 64 : 128;
  assert(hashPadding[tail] == 0x80);
  for (size_t i = tail + 1; i < padded - 8; ++i) assert(hashPadding[i] == 0);
  uint64_t bits = 0;
  for (size_t i = padded - 8; i < padded; ++i) bits = (bits << 8) | hashPadding[i];
  assert(bits == length * 8);
  const size_t last = length < 64 ? 0 : 1;
  assert(descriptors[last].rctrl == padded / 64 - 1);
  assert(descriptors[last].rcfg & ICM_RCFG_EOM_YES);
  assert(descriptors[last].rnext == 0);
  if (last) {
    assert(descriptors[0].rctrl == length / 64 - 1);
    assert(descriptors[0].rnext == uint32_t(uintptr_t(&descriptors[1])));
    assert(!(descriptors[0].rcfg & ICM_RCFG_EOM_YES));
  }
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  for (size_t i = 0; i < length - tail; i += 64) SHA256_Transform(&ctx, input.data() + i);
  for (size_t i = 0; i < padded; i += 64) SHA256_Transform(&ctx, hashPadding + i);
  uint8_t expected[32];
  SHA256(input.data(), length, expected);
  for (size_t i = 0; i < 32; ++i) assert(uint8_t(ctx.h[i / 4] >> (24 - (i % 4) * 8)) == expected[i]);
}
int main() {
  for (size_t length : {0u, 1u, 3u, 55u, 56u, 63u, 64u, 65u, 119u, 120u, 128u, 1024u}) paddingAndDigest(length);
  assert(uintptr_t(descriptors) % 64 == 0);
  assert(uintptr_t(hashArea) % 128 == 0);
  std::vector<uint8_t> large(icm::MaxInputLength + 1);
  icm::HashSegment segment{large.data(), icm::MaxInputLength};
  assert(prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 0));
  for (size_t i = 0; i < 7; ++i) assert(descriptors[i].rctrl == 65535);
  assert(descriptors[7].rcfg & ICM_RCFG_EOM_YES);
  ++segment.length;
  assert(!prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 0));
  segment = {nullptr, 1};
  assert(!prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 0));
  icm::HashSegment segments[] = {{large.data(), 64}, {large.data() + 64, 3}};
  assert(prepareHashDescriptors(icm::Algorithm::Sha256, segments, 2, 0));
  segments[0].length = 63;
  assert(!prepareHashDescriptors(icm::Algorithm::Sha256, segments, 2, 0));
  assert(!prepareHashDescriptors(icm::Algorithm::Sha256, segments, 0, 0));
  assert(!prepareHashDescriptors(icm::Algorithm::Sha256, segments, 8, 0));
  segment = {large.data(), 4u * 1024u * 1024u + 64u};
  assert(prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 0));
  assert(descriptors[0].rctrl == 65535 && descriptors[1].rctrl == 0);
  assert(descriptors[1].rnext == uint32_t(uintptr_t(&descriptors[2])));
  segment = {large.data(), 3};
  assert(prepareHashDescriptors(icm::Algorithm::Sha256, &segment, 1, 64));
  assert(hashPadding[62] == 2 && hashPadding[63] == 24);
  assert(prepareHashBlockStateDescriptors(icm::Algorithm::Sha256, large.data(), 64));
  assert(descriptors[0].rctrl == 0 && descriptors[0].rnext == 0);
  assert(!prepareHashBlockStateDescriptors(icm::Algorithm::Sha256, large.data(), 63));
  uint8_t output[32];
  resetTest();
  testIcm.ICM_ISR = kCompleteInterrupt;
  assert(icm::startHashAsync(icm::Algorithm::Sha256, nullptr, 0, output, sizeof(output)));
  assert(icm::asyncBusy());
  assert(!icm::startHashAsync(icm::Algorithm::Sha256, nullptr, 0, output, sizeof(output)));
  for (size_t i = 0; i < sizeof(output); ++i) hashArea[i] = uint8_t(i);
  icm::handleInterrupt();
  assert(callbacks == 0);
  PendSV::instance().dispatchPending();
  assert(callbacks == 1 && delivered == icm::EventComplete && !icm::asyncBusy());
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == i);
  PendSV::instance().dispatchPending();
  assert(callbacks == 1);
  resetTest();
  assert(!icm::startHashAsync(icm::Algorithm::Sha256, nullptr, 0, output, sizeof(output)));
  assert(!icm::asyncBusy() && callbacks == 0);
  resetTest();
  testIcm.ICM_ISR = kErrorInterrupt;
  memset(output, 0xa5, sizeof(output));
  assert(icm::startHashAsync(icm::Algorithm::Sha256, nullptr, 0, output, sizeof(output)));
  icm::handleInterrupt();
  PendSV::instance().dispatchPending();
  assert(callbacks == 1 && delivered == icm::EventError && !icm::asyncBusy());
  for (auto byte : output) assert(byte == 0xa5);
  resetTest();
  testIcm.ICM_ISR = kCompleteInterrupt;
  assert(!icm::startHashAsync(static_cast<icm::Algorithm>(255), nullptr, 0, output, 0));
  segment = {nullptr, 0};
  assert(!icm::startHashContinuationAsync(icm::Algorithm::Sha256, output, 32,
      icm::MaxInputLength + 1, &segment, 1, output, 32));
  resetTest();
  testIcm.ICM_ISR = kCompleteInterrupt;
  for (size_t i = 0; i < 32; ++i) output[i] = uint8_t(i);
  assert(icm::startHashContinuationAsync(icm::Algorithm::Sha256, output, 32,
      64, &segment, 1, output, 32));
  for (size_t i = 0; i < 8; ++i) {
    uint32_t word = 0;
    for (size_t j = 0; j < 4; ++j) word |= uint32_t(i * 4 + j) << (j * 8);
    assert(testIcm.ICM_UIHVAL[i] == word);
  }
  icm::clearEventCallback();
  assert(!icm::asyncBusy());
  assert(!icm::startHashAsync(icm::Algorithm::Sha256, nullptr, 0, output, 32));
  puts("ICM descriptor/padding/reference SHA256 and async/error tests passed");
}

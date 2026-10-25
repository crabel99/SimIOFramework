#include "PendSV.h"

#include <Arduino.h>
#include <limits.h>

#if defined(USE_TINYUSB)
extern "C" void TinyUSB_Device_Task(void);
#endif

namespace {
PendSV pendSv;

#if defined(USE_TINYUSB)
void tinyUsbDeviceTaskService(uint8_t serviceId, void *context) {
  (void)serviceId;
  (void)context;
  // One invocation drains TinyUSB's queued controller events under OPT_OS_NONE.
  TinyUSB_Device_Task();
}
#endif
}

PendSV &PendSV::instance() {
  return pendSv;
}

#if defined(USE_TINYUSB)
extern "C" void tud_event_hook_cb(uint8_t rhport, uint32_t eventId, bool inIsr) {
  (void)rhport;
  (void)eventId;
  (void)inIsr;
  // TinyUSB owns the event queue. PendSV is only its deferred wake signal, so
  // multiple controller events before dispatch require only one service call.
  PendSV::instance().setPendingOnce(PendSVChannels::Usb);
}
#endif

bool PendSV::initializeCoreServices() {
  NVIC_SetPriority(PendSV_IRQn, (1 << __NVIC_PRIO_BITS) - 1);
#if defined(USE_TINYUSB)
  return instance().registerService(PendSVChannels::Usb, tinyUsbDeviceTaskService, nullptr);
#else
  return true;
#endif
}

uint32_t PendSV::enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void PendSV::exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
}

bool PendSV::registerService(uint8_t serviceId, ServiceFn fn, void *context) {
  if (serviceId >= kMaxServices || fn == nullptr)
    return false;

  const uint32_t primask = enterCritical();
  pendingCount_[serviceId] = 0;
  pendingMask_ &= ~(1u << serviceId);
  delayedMask_ &= ~(1u << serviceId);
  services_[serviceId].fn = fn;
  services_[serviceId].context = context;
  exitCritical(primask);

  return true;
}

void PendSV::clearService(uint8_t serviceId) {
  if (serviceId >= kMaxServices)
    return;

  const uint32_t primask = enterCritical();
  services_[serviceId].fn = nullptr;
  services_[serviceId].context = nullptr;
  pendingCount_[serviceId] = 0;
  pendingMask_ &= ~(1u << serviceId);
  delayedMask_ &= ~(1u << serviceId);
  exitCritical(primask);
}

void PendSV::setPending(uint8_t serviceId) {
  if (serviceId >= kMaxServices)
    return;

  const uint32_t primask = enterCritical();
  uint16_t &pendingCount = pendingCount_[serviceId];
  if (pendingCount < UINT16_MAX)
    ++pendingCount;
  pendingMask_ |= (1u << serviceId);
  exitCritical(primask);

  __DMB();
  SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
}

void PendSV::setPendingOnce(uint8_t serviceId) {
  if (serviceId >= kMaxServices)
    return;

  const uint32_t primask = enterCritical();
  pendingCount_[serviceId] = 1;
  pendingMask_ |= (1u << serviceId);
  exitCritical(primask);

  __DMB();
  SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
}

bool PendSV::setPendingAfter(uint8_t serviceId, uint32_t delayMs) {
  if (serviceId >= kMaxServices || delayMs > INT32_MAX)
    return false;

  const uint32_t primask = enterCritical();
  if (services_[serviceId].fn == nullptr) {
    exitCritical(primask);
    return false;
  }

  const uint32_t bit = 1u << serviceId;
  if (delayMs != 0) {
    deadlines_[serviceId] = static_cast<uint32_t>(millis()) + delayMs;
    delayedMask_ |= bit;
  } else {
    delayedMask_ &= ~bit;
    if (pendingCount_[serviceId] == 0)
      pendingCount_[serviceId] = 1;
    pendingMask_ |= bit;
  }
  exitCritical(primask);

  if (delayMs == 0) {
    __DMB();
    SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
  }
  return true;
}

void PendSV::cancelPendingAfter(uint8_t serviceId) {
  if (serviceId >= kMaxServices)
    return;

  const uint32_t primask = enterCritical();
  delayedMask_ &= ~(1u << serviceId);
  exitCritical(primask);
}

void PendSV::onSysTick(uint32_t now) {
  if (delayedMask_ == 0)
    return;

  const uint32_t primask = enterCritical();
  uint32_t remaining = delayedMask_;
  uint32_t ready = 0;
  while (remaining != 0) {
    const uint8_t serviceId = static_cast<uint8_t>(__builtin_ctz(remaining));
    const uint32_t bit = 1u << serviceId;
    remaining &= ~bit;
    if (static_cast<int32_t>(now - deadlines_[serviceId]) < 0)
      continue;

    delayedMask_ &= ~bit;
    if (pendingCount_[serviceId] == 0)
      pendingCount_[serviceId] = 1;
    ready |= bit;
  }
  pendingMask_ |= ready;
  exitCritical(primask);

  if (ready != 0) {
    __DMB();
    SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
  }
}

extern "C" void PendSV_Tick(uint32_t now) {
  PendSV::instance().onSysTick(now);
}

void PendSV::dispatchPending() {
  // Bound one PendSV entry so high-rate producers do not monopolize return to
  // thread mode. Remaining work re-pends PendSV below.
  uint8_t dispatched = 0;

  while (dispatched < kDispatchBudget) {
    uint32_t primask = enterCritical();
    const uint32_t pending = pendingMask_;
    if (pending == 0) {
      exitCritical(primask);
      return;
    }

    const uint8_t serviceId = static_cast<uint8_t>(__builtin_ctz(pending));
    uint16_t &pendingCount = pendingCount_[serviceId];

    if (pendingCount == 0) {
      // Defensive scrub in case mask and count drift out of sync.
      pendingMask_ &= ~(1u << serviceId);
      exitCritical(primask);
      continue;
    }

    --pendingCount;
    if (pendingCount == 0)
      pendingMask_ &= ~(1u << serviceId);

    ServiceEntry entry = services_[serviceId];
    exitCritical(primask);

    // Pending work without a registered service is intentionally dropped.
    // Producers are expected to register before calling setPending(), and
    // clearService() cancels queued work for that service.
    if (entry.fn != nullptr)
      entry.fn(serviceId, entry.context);

    ++dispatched;
  }

  const uint32_t primask = enterCritical();
  const bool hasRemaining = (pendingMask_ != 0);
  exitCritical(primask);

  if (hasRemaining) {
    __DMB();
    SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
  }
}

extern "C" void PendSV_Handler(void) {
  PendSV::instance().dispatchPending();
}

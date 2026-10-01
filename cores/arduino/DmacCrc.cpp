#include "DmacCrc.h"
#include <sam.h>

namespace {
uint8_t owner = 0xff;
class CriticalSection {
  uint32_t mask;
public:
  CriticalSection() : mask(__get_PRIMASK()) { __disable_irq(); }
  ~CriticalSection() { __set_PRIMASK(mask); }
};
#if defined(__SAME53__) || defined(__SAME54__)
#define CRC_CONTROL DMAC_REGS->DMAC_CRCCTRL
#define CRC_CHECKSUM DMAC_REGS->DMAC_CRCCHKSUM
#define CRC_STATUS DMAC_REGS->DMAC_CRCSTATUS
#define CRC_BUSY DMAC_CRCSTATUS_CRCBUSY_Msk
#define DMA_CONTROL DMAC_REGS->DMAC_CTRL
#else
#define CRC_CONTROL DMAC->CRCCTRL.reg
#define CRC_CHECKSUM DMAC->CRCCHKSUM.reg
#define CRC_STATUS DMAC->CRCSTATUS.reg
#define CRC_BUSY DMAC_CRCSTATUS_CRCBUSY
#define DMA_CONTROL DMAC->CTRL.reg
#endif

bool channelEnabled(uint8_t channel) {
#if defined(__SAME53__) || defined(__SAME54__)
  return (DMAC_REGS->CHANNEL[channel].DMAC_CHCTRLA & DMAC_CHCTRLA_ENABLE_Msk) != 0;
#elif defined(__SAMD51__)
  return (DMAC->Channel[channel].CHCTRLA.reg & DMAC_CHCTRLA_ENABLE) != 0;
#else
  const uint8_t selected = DMAC->CHID.reg;
  DMAC->CHID.reg = channel;
  const bool enabled = (DMAC->CHCTRLA.reg & DMAC_CHCTRLA_ENABLE) != 0;
  DMAC->CHID.reg = selected;
  return enabled;
#endif
}
void disableCrc() {
#if !defined(__SAMD51__) && !defined(__SAME53__) && !defined(__SAME54__)
  DMA_CONTROL &= ~DMAC_CTRL_CRCENABLE;
#endif
  CRC_CONTROL = 0;
}
}

DmacCrc::Status DmacCrc::begin(uint8_t channel, Polynomial polynomial, uint32_t seed) {
  if (channel >= DMAC_CH_NUM ||
      (polynomial != Polynomial::Crc16 && polynomial != Polynomial::Crc32))
    return Status::InvalidArgument;
  CriticalSection critical;
  if (owner != 0xff || CRC_CONTROL != 0 || (CRC_STATUS & CRC_BUSY) != 0)
    return Status::Busy;
#if defined(__SAME53__) || defined(__SAME54__)
  if ((DMA_CONTROL & DMAC_CTRL_DMAENABLE_Msk) == 0)
#else
  if ((DMA_CONTROL & DMAC_CTRL_DMAENABLE) == 0)
#endif
    return Status::NotConfigured;
#if !defined(__SAMD51__) && !defined(__SAME53__) && !defined(__SAME54__)
  if ((DMA_CONTROL & DMAC_CTRL_CRCENABLE) != 0)
    return Status::Busy;
#endif
  if (channelEnabled(channel))
    return Status::Busy;
  disableCrc();
  CRC_CHECKSUM = polynomial == Polynomial::Crc16 ? (seed & 0xffffu) : seed;
  CRC_CONTROL = DMAC_CRCCTRL_CRCPOLY(polynomial == Polynomial::Crc32 ? 1u : 0u) |
                DMAC_CRCCTRL_CRCSRC(0x20u + channel);
#if !defined(__SAMD51__) && !defined(__SAME53__) && !defined(__SAME54__)
  DMA_CONTROL |= DMAC_CTRL_CRCENABLE;
#endif
  owner = channel;
  return Status::Ok;
}

DmacCrc::Status DmacCrc::finish(uint8_t channel, bool transferSucceeded, uint32_t& checksum) {
  CriticalSection critical;
  if (owner == 0xff || owner != channel)
    return Status::NotOwner;
  if (channelEnabled(channel) || (CRC_STATUS & CRC_BUSY) != 0)
    return Status::Busy;
  // Read while CRC is configured and idle: CRC32 readout then includes the
  // hardware's bit reversal and complement (D21 20.6.3, D5x/E5x 22.6.3.8).
  if (transferSucceeded)
    checksum = CRC_CHECKSUM;
  disableCrc();
  owner = 0xff;
  return transferSucceeded ? Status::Ok : Status::TransferFailed;
}

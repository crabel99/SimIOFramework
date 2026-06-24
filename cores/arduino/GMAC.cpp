#include "GMAC.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>

namespace {
constexpr uint32_t kMdioTimeoutMs = 10;
constexpr uint32_t kMdioWriteTen = 2;
constexpr uint32_t kMdioReadOperation = 2;
constexpr uint32_t kMdioWriteOperation = 1;

gmac_registers_t *gmacRegisters() {
  return reinterpret_cast<gmac_registers_t *>(GMAC_PERIPH);
}

uint32_t mdcClockBits(uint32_t mckHz) {
  if (mckHz <= 20000000UL) {
    return GMAC_NCFGR_CLK_MCK8;
  }
  if (mckHz <= 40000000UL) {
    return GMAC_NCFGR_CLK_MCK16;
  }
  if (mckHz <= 80000000UL) {
    return GMAC_NCFGR_CLK_MCK32;
  }
  if (mckHz <= 120000000UL) {
    return GMAC_NCFGR_CLK_MCK64;
  }
  return GMAC_NCFGR_CLK_MCK96;
}

bool waitManagementIdle() {
  gmac_registers_t *regs = gmacRegisters();
  const uint32_t startMs = millis();

  do {
    if ((regs->GMAC_NSR & GMAC_NSR_IDLE_Msk) != 0) {
      return true;
    }
    yield();
  } while ((millis() - startMs) < kMdioTimeoutMs);

  return false;
}
} // namespace

bool gmac::available() { return true; }

int gmac::irqNumber() { return static_cast<int>(GMAC_IRQn); }

bool gmac::beginManagement(uint32_t mckHz) {
  gmac_registers_t *regs = gmacRegisters();

#if defined(MCLK_AHBMASK_GMAC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_AHBMASK |= MCLK_AHBMASK_GMAC_Msk;
#elif defined(MCLK)
  MCLK->AHBMASK.reg |= MCLK_AHBMASK_GMAC_Msk;
#endif
#endif
#if defined(MCLK_APBCMASK_GMAC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_GMAC_Msk;
#elif defined(MCLK)
  MCLK->APBCMASK.reg |= MCLK_APBCMASK_GMAC_Msk;
#endif
#endif

  regs->GMAC_NCFGR =
      (regs->GMAC_NCFGR & ~GMAC_NCFGR_CLK_Msk) | mdcClockBits(mckHz);
  regs->GMAC_NCR |= GMAC_NCR_MPE_Msk;

  return waitManagementIdle();
}

bool gmac::isManagementIdle() { return waitManagementIdle(); }

void gmac::setMacAddress(const uint8_t mac[6]) {
  if (mac == nullptr) {
    return;
  }

  gmac_registers_t *regs = gmacRegisters();

  regs->SA[0].GMAC_SAB = static_cast<uint32_t>(mac[0]) |
                         (static_cast<uint32_t>(mac[1]) << 8) |
                         (static_cast<uint32_t>(mac[2]) << 16) |
                         (static_cast<uint32_t>(mac[3]) << 24);
  regs->SA[0].GMAC_SAT =
      static_cast<uint32_t>(mac[4]) | (static_cast<uint32_t>(mac[5]) << 8);
}

void gmac::getMacAddress(uint8_t mac[6]) {
  if (mac == nullptr)
    return;

  gmac_registers_t *regs = gmacRegisters();
  const uint32_t bottom = regs->SA[0].GMAC_SAB;
  const uint32_t top = regs->SA[0].GMAC_SAT;

  mac[0] = static_cast<uint8_t>(bottom & 0xFFu);
  mac[1] = static_cast<uint8_t>((bottom >> 8) & 0xFFu);
  mac[2] = static_cast<uint8_t>((bottom >> 16) & 0xFFu);
  mac[3] = static_cast<uint8_t>((bottom >> 24) & 0xFFu);
  mac[4] = static_cast<uint8_t>(top & 0xFFu);
  mac[5] = static_cast<uint8_t>((top >> 8) & 0xFFu);
}

bool gmac::mdioRead(uint8_t phyAddress, uint8_t registerAddress,
                    uint16_t *value) {
  if (value == nullptr || phyAddress > 31 || registerAddress > 31)
    return false;

  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle())
    return false;

  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioReadOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen);

  if (!waitManagementIdle())
    return false;
  
  *value = static_cast<uint16_t>(regs->GMAC_MAN & GMAC_MAN_DATA_Msk);
  return true;
}

bool gmac::mdioWrite(uint8_t phyAddress, uint8_t registerAddress,
                     uint16_t value) {
  if (phyAddress > 31 || registerAddress > 31) {
    return false;
  }

  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle()) 
    return false;

  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioWriteOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen) | GMAC_MAN_DATA(value);

  return waitManagementIdle();
}

bool gmac::mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                          uint16_t value) {
  if (phyAddress > 31 || registerAddress > 31)
    return false;
  
  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle()) 
    return false;
  
  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioWriteOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen) | GMAC_MAN_DATA(value);

  return true;
}

#endif /* ETHERNET_HARDWARE_AVAILABLE */

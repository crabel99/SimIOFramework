#pragma once

#include <stdint.h>

typedef enum {
  // Basic IEEE 802.3 clause-22 registers.
  PHY_REG_BMCON = 0,
  PHY_REG_BMSTAT = 1,
  PHY_REG_PHYID1 = 2,
  PHY_REG_PHYID2 = 3,
  PHY_REG_ANAD = 4,
  PHY_REG_ANLPAD = 5,
  PHY_REG_ANLPADNP = 5,
  PHY_REG_ANEXP = 6,
  PHY_REG_ANNPTR = 7,
  PHY_REG_ANLPRNP = 8,
  PHY_REG_1000BASECON = 9,
  PHY_REG_1000BASESTAT = 10,
  PHY_REG_MMD_CONTROL = 13,
  PHY_REG_MMD_DATA = 14,
  PHY_REG_EXTSTAT = 15,

  // Vendor-specific registers occupy 16-31.
  PHY_REG_VENDOR = 16,
  PHY_REGISTERS = 32,
} PhyReg;

struct PhyRegBmcon {
  static constexpr PhyReg addr = PHY_REG_BMCON;

  struct bit {
    static constexpr uint16_t Reset = 1u << 15;
    static constexpr uint16_t Loopback = 1u << 14;
    static constexpr uint16_t SpeedSelect = 1u << 13;
    static constexpr uint16_t AutoNegotiationEnable = 1u << 12;
    static constexpr uint16_t PowerDown = 1u << 11;
    static constexpr uint16_t Isolate = 1u << 10;
    static constexpr uint16_t RestartAutoNegotiation = 1u << 9;
    static constexpr uint16_t DuplexMode = 1u << 8;
    static constexpr uint16_t CollisionTest = 1u << 7;
  };

  uint16_t reg;
};

struct PhyRegBmstat {
  static constexpr PhyReg addr = PHY_REG_BMSTAT;

  struct bit {
    static constexpr uint16_t HundredBaseT4 = 1u << 15;
    static constexpr uint16_t HundredBaseTXFull = 1u << 14;
    static constexpr uint16_t HundredBaseTXHalf = 1u << 13;
    static constexpr uint16_t TenBaseTFull = 1u << 12;
    static constexpr uint16_t TenBaseTHalf = 1u << 11;
    static constexpr uint16_t ExtendedStatus = 1u << 8;
    static constexpr uint16_t AutoNegotiationComplete = 1u << 5;
    static constexpr uint16_t AutoNegotiationAbility = 1u << 3;
    static constexpr uint16_t LinkStatus = 1u << 2;
  };

  uint16_t reg;
};

struct PhyRegAnad {
  static constexpr PhyReg addr = PHY_REG_ANAD;

  struct bit {
    static constexpr uint16_t NextPage = 1u << 15;
    static constexpr uint16_t Acknowledge = 1u << 14;
    static constexpr uint16_t RemoteFault = 1u << 13;
    static constexpr uint16_t HundredBaseT4 = 1u << 9;
    static constexpr uint16_t HundredBaseTXFull = 1u << 8;
    static constexpr uint16_t HundredBaseTXHalf = 1u << 7;
    static constexpr uint16_t TenBaseTFull = 1u << 6;
    static constexpr uint16_t TenBaseTHalf = 1u << 5;
  };

  struct mask {
    static constexpr uint16_t Pause = 0x0C00u;
    static constexpr uint16_t Selector = 0x001Fu;
  };

  struct shift {
    static constexpr uint8_t Pause = 10;
  };

  uint16_t reg;
};

struct PhyRegAnlpad {
  static constexpr PhyReg addr = PHY_REG_ANLPAD;

  struct bit {
    static constexpr uint16_t NextPage = PhyRegAnad::bit::NextPage;
    static constexpr uint16_t Acknowledge = PhyRegAnad::bit::Acknowledge;
    static constexpr uint16_t RemoteFault = PhyRegAnad::bit::RemoteFault;
    static constexpr uint16_t HundredBaseT4 = PhyRegAnad::bit::HundredBaseT4;
    static constexpr uint16_t HundredBaseTXFull =
        PhyRegAnad::bit::HundredBaseTXFull;
    static constexpr uint16_t HundredBaseTXHalf =
        PhyRegAnad::bit::HundredBaseTXHalf;
    static constexpr uint16_t TenBaseTFull = PhyRegAnad::bit::TenBaseTFull;
    static constexpr uint16_t TenBaseTHalf = PhyRegAnad::bit::TenBaseTHalf;
  };

  struct mask {
    static constexpr uint16_t Pause = PhyRegAnad::mask::Pause;
    static constexpr uint16_t Selector = PhyRegAnad::mask::Selector;
  };

  struct shift {
    static constexpr uint8_t Pause = PhyRegAnad::shift::Pause;
  };

  uint16_t reg;
};

struct PhyRegAnexp {
  static constexpr PhyReg addr = PHY_REG_ANEXP;

  struct bit {
    static constexpr uint16_t ParallelDetectionFault = 1u << 4;
    static constexpr uint16_t LinkPartnerNextPageAble = 1u << 3;
    static constexpr uint16_t NextPageAble = 1u << 2;
    static constexpr uint16_t PageReceived = 1u << 1;
    static constexpr uint16_t LinkPartnerAutoNegotiationAble = 1u << 0;
  };

  uint16_t reg;
};

struct PhyRegAnptr {
  static constexpr PhyReg addr = PHY_REG_ANNPTR;
  uint16_t reg;
};

struct PhyRegAnlprnp {
  static constexpr PhyReg addr = PHY_REG_ANLPRNP;
  uint16_t reg;
};

struct PhyRegMmdControl {
  static constexpr PhyReg addr = PHY_REG_MMD_CONTROL;

  struct bit {
    static constexpr uint16_t RegisterMode = 0u << 14;
    static constexpr uint16_t DataNoPostIncrement = 1u << 14;
  };

  struct mask {
    static constexpr uint16_t DeviceAddress = 0x001Fu;
  };

  uint16_t reg;
};

struct PhyRegMmdData {
  static constexpr PhyReg addr = PHY_REG_MMD_DATA;
  uint16_t reg;
};

struct PhyRegExtStat {
  static constexpr PhyReg addr = PHY_REG_EXTSTAT;

  struct bit {
    static constexpr uint16_t ThousandBaseXFull = 1u << 15;
    static constexpr uint16_t ThousandBaseXHalf = 1u << 14;
    static constexpr uint16_t ThousandBaseTFull = 1u << 13;
    static constexpr uint16_t ThousandBaseTHalf = 1u << 12;
  };

  uint16_t reg;
};

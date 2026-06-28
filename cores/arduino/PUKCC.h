#pragma once

#include "sam.h"
#include "PendSV.h"

#include <stdint.h>

#if defined(PUKCC) || defined(ID_PUKCC) || defined(PUKCC_INSTANCE_ID)
#define PUKCC_AVAILABLE 1
#else
#define PUKCC_AVAILABLE 0
#endif /* PUKCC || ID_PUKCC || PUKCC_INSTANCE_ID */

#if defined(PUKCC)
#define PUKCC_PERIPH_APB (reinterpret_cast<uintptr_t>(PUKCC))
#else
#define PUKCC_PERIPH_APB (static_cast<uintptr_t>(0))
#endif /* PUKCC */

#if defined(PUKCC_AHB)
#define PUKCC_PERIPH_AHB (reinterpret_cast<uintptr_t>(PUKCC_AHB))
#else
#define PUKCC_PERIPH_AHB (static_cast<uintptr_t>(0))
#endif /* PUKCC_AHB */

#if PUKCC_AVAILABLE

#define CRYPTO_HARDWARE_AVAILABLE

/**
 * @brief SAME5x PUKCC hardware boundary and ROM service metadata.
 *
 * The CMSIS device pack exposes PUKCC as an instance, IRQ, AHB clocked service
 * block, and ROM address space instead of a typed register peripheral. `pukcc`
 * owns that hardware boundary: clock gating, mandatory Crypto RAM clear
 * readiness, IRQ/PendSV identity, address sizing, stable ROM service entry
 * metadata, PUKCL near-pointer translation, and minimal service dispatch needed
 * to prove the ROM ABI. It does not own RSA/ECC policy, key management, or TLS
 * integration; those belong to higher-level crypto library code built on this
 * boundary.
 */
class pukcc {
public:
  static constexpr uintptr_t StatusRegisterAddress = 0x4200302Cu;
  static constexpr uint32_t ClearRamBusyMask = 0x00000001u;
  static constexpr uintptr_t RomJumpTableAddress = 0x02000001u;
  static constexpr uintptr_t CryptoRamAddressPrefix = 0x02010000u;
  static constexpr uint16_t CryptoRamNearBase = 0x1000u;
  static constexpr uint16_t CryptoRamSize = 4096u;
  static constexpr uint16_t CryptoRamReservedTailSize = 8u;
  static constexpr uint16_t CryptoRamUsableSize =
      CryptoRamSize - CryptoRamReservedTailSize;
  static constexpr uintptr_t SelfTestFunctionAddress =
      RomJumpTableAddress + 0x54u;
  static constexpr uintptr_t ClearFlagsFunctionAddress =
      RomJumpTableAddress + 0x10u;
  static constexpr uintptr_t FillFunctionAddress = RomJumpTableAddress + 0x3Cu;
  static constexpr uint8_t SelfTestServiceId = 0x5Bu;
  static constexpr uint8_t ClearFlagsServiceId = 0x5Fu;
  static constexpr uint8_t FillServiceId = 0x6Fu;
  static constexpr uint16_t StatusOk = 0x0000u;
  static constexpr uint16_t StatusComputationNotStarted = 0xC001u;
  static constexpr uint16_t StatusError = 0xC007u;
  static constexpr uint16_t StatusParameterNotInPukccRam = 0xC011u;
  static constexpr uint16_t StatusParameterWrongLength = 0xC014u;
  static constexpr uint16_t StatusParameterBadAlignment = 0xC015u;
  static constexpr uint32_t SelfTestExpectedCheck1 = 0x6E70DDD2u;
  static constexpr uint32_t SelfTestExpectedCheck2 = 0x25C8D64Fu;
  static constexpr uint8_t SelfTestExpectedStep = 3u;

  struct SelfTestResult {
    uint16_t status;
    uint32_t libraryVersion;
    uint32_t hardwareVersion;
    uint32_t check1;
    uint32_t check2;
    uint8_t step;
  };

  enum StatusFlag : uint32_t {
    CarryInFlag = 1u << 0,
    CarryOutFlag = 1u << 1,
    ZeroFlag = 1u << 2,
    Gf2nFlag = 1u << 3,
    ViolationFlag = 1u << 4,
  };

  struct ServiceResult {
    uint8_t service;
    uint16_t status;
    uint32_t specific;
  };

  inline static uintptr_t apbBaseAddress() { return PUKCC_PERIPH_APB; }
  inline static uintptr_t ahbBaseAddress() { return PUKCC_PERIPH_AHB; }
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Pukcc; }
  inline static uintptr_t cryptoRamBaseAddress() {
    return CryptoRamAddressPrefix | CryptoRamNearBase;
  }

  /** @brief Return the CMSIS IRQ number for the PUKCC service block. */
  static int irqNumber();
  /**
   * @brief Enable the PUKCC AHB clock gate and wait for Crypto RAM readiness.
   * @param loopBudget Maximum status-register polls before giving up.
   * @return true when the PUKCC clear-RAM busy bit is deasserted.
   */
  static bool begin(uint32_t loopBudget = 1000000u);
  /** @brief Disable the PUKCC AHB clock gate. */
  static void end();
  /** @brief Enable the PUKCC AHB clock gate without waiting for readiness. */
  static void enableClock();
  /** @brief Disable the PUKCC AHB clock gate. */
  static void disableClock();
  /** @brief Return the raw PUKCC status register value. */
  static uint32_t status();
  /** @brief Return true while PUKCC is clearing its private Crypto RAM. */
  static bool ramClearBusy();
  /**
   * @brief Poll the mandatory Crypto RAM clear state with a bounded budget.
   * @param loopBudget Maximum status-register polls before returning false.
   * @return true once the clear-RAM busy bit is deasserted.
   */
  static bool waitForRamClear(uint32_t loopBudget);
  /** @brief Return true when the PUKCC service block is ready for ROM calls. */
  static bool ready();
  /**
   * @brief Run the mandatory PUKCL ROM self-test service.
   *
   * This is the only PUKCL ROM service owned directly by the hardware boundary
   * because the datasheet requires it before any other service call. The method
   * enables PUKCC, waits for Crypto RAM clear readiness, dispatches the ROM
   * SelfTest entry, captures returned version/check values, and validates the
   * documented check words and final step. RSA/ECC primitive parameter blocks
   * remain the responsibility of the later PUKCL service wrapper.
   *
   * @param result Filled with raw self-test status and return values.
   * @param loopBudget Maximum clear-RAM status polls before dispatch.
   * @return true when status is OK and documented check values match.
   */
  static bool selfTest(SelfTestResult &result,
                       uint32_t loopBudget = 1000000u);
  /**
   * @brief Dispatch the PUKCL ClearFlags service on an owned header block.
   *
   * ClearFlags is the minimal non-self-test ROM service: it touches only the
   * common PUKCL status field and requires no Crypto RAM workspace. It proves
   * generic service dispatch and status decoding while keeping RSA/ECC service
   * parameter ownership deferred to the later PUKCL wrapper.
   *
   * @param initialFlags Initial PUKCL specific-status bits to pass.
   * @param result Filled with the service ID, returned status, and final bits.
   * @return true when the service returns StatusOk.
   */
  static bool clearFlags(uint32_t initialFlags, ServiceResult &result);
  /**
   * @brief Return the CPU-visible address for a Crypto RAM offset.
   * @param offset Offset from the start of PUKCC Crypto RAM.
   */
  static volatile uint8_t *cryptoRam(uint16_t offset = 0);
  /** @brief Return true when offset/length are valid for PUKCL RAM services. */
  static bool validCryptoRamRange(uint16_t offset, uint16_t length);
  /**
   * @brief Convert a public Crypto RAM offset to a PUKCL near pointer.
   *
   * PUKCL services do not take CPU addresses for Crypto RAM. They take 16-bit
   * near pointers whose first usable Crypto RAM byte is `CryptoRamNearBase`.
   */
  static uint16_t cryptoRamNearPointer(uint16_t offset);
  /**
   * @brief Dispatch the PUKCL Fill service into owned Crypto RAM.
   *
   * Fill is the first workspace-backed PUKCL service exposed by this boundary.
   * It validates the Crypto RAM range, dispatches the ROM Fill entry, and
   * reports the common service status. More complex arithmetic/RSA/ECC services
   * should build on the same range validation and near-pointer model.
   *
   * @param offset Four-byte aligned offset into PUKCC Crypto RAM.
   * @param length Four-byte multiple in [4, CryptoRamUsableSize].
   * @param fillValue 32-bit pattern written by the ROM service.
   * @param result Filled with the service ID, returned status, and final bits.
   * @return true when the service returns StatusOk.
   */
  static bool fillCryptoRam(uint16_t offset, uint16_t length,
                            uint32_t fillValue, ServiceResult &result);
  /** @brief Return the CMSIS peripheral instance ID when exposed. */
  inline static int instanceId() {
#if defined(PUKCC_INSTANCE_ID)
    return static_cast<int>(PUKCC_INSTANCE_ID);
#elif defined(ID_PUKCC)
    return static_cast<int>(ID_PUKCC);
#else
    return -1;
#endif
  }
  /** @brief Return PUKCC RAM address width metadata from CMSIS. */
  inline static uint8_t ramAddressSize() {
#if defined(PUKCC_RAM_ADDR_SIZE)
    return static_cast<uint8_t>(PUKCC_RAM_ADDR_SIZE);
#else
    return 0;
#endif
  }
  /** @brief Return PUKCC ROM address width metadata from CMSIS. */
  inline static uint8_t romAddressSize() {
#if defined(PUKCC_ROM_ADDR_SIZE)
    return static_cast<uint8_t>(PUKCC_ROM_ADDR_SIZE);
#else
    return 0;
#endif
  }
};
#endif /* PUKCC_AVAILABLE */

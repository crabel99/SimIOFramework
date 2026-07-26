#pragma once

#include "sam.h"
#include "PendSV.h"

#if __has_include("instance/pukcc.h")
#include "instance/pukcc.h"
#endif

#include <stdint.h>

#if defined(__SAMD51__) || defined(__SAME51__) || defined(__SAME53__) ||       \
    defined(__SAME54__)
#define PUKCC_AVAILABLE 1
#else
#define PUKCC_AVAILABLE 0
#endif /* SAMD5x/E5x PUKCC target */

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
  using EventMask = uint8_t;
  using EventCallback = void (*)(EventMask events, uint8_t serviceId,
                                 uint16_t status, void *context);

  static constexpr EventMask EventNone = 0;
  static constexpr EventMask EventComplete = 1u << 0;
  static constexpr EventMask EventError = 1u << 1;

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
  static constexpr uintptr_t RngFunctionAddress = RomJumpTableAddress + 0x70u;
  static constexpr uintptr_t ExpModFunctionAddress =
      RomJumpTableAddress + 0x80u;
  static constexpr uintptr_t RedModFunctionAddress = RomJumpTableAddress + 0x8u;
  static constexpr uintptr_t ZpEcDsaGenerateFastFunctionAddress =
      RomJumpTableAddress + 0x28u;
  static constexpr uintptr_t ZpEcDsaVerifyFastFunctionAddress =
      RomJumpTableAddress + 0x2Cu;
  static constexpr uintptr_t ZpEccMulFastFunctionAddress =
      RomJumpTableAddress + 0x40u;
  static constexpr uintptr_t ZpEcConvProjToAffineFunctionAddress =
      RomJumpTableAddress + 0x84u;
  static constexpr uintptr_t ZpEcPointIsOnCurveFunctionAddress =
      RomJumpTableAddress + 0x8Cu;
  static constexpr uintptr_t ZpEccQuickDualMulFastFunctionAddress =
      RomJumpTableAddress + 0x98u;
  static constexpr uintptr_t ZpEcDsaQuickVerifyFunctionAddress =
      RomJumpTableAddress + 0x9Cu;
  static constexpr uint8_t RedModServiceId = 0x50u;
  static constexpr uint8_t CondCopyServiceId = 0x51u;
  static constexpr uint8_t DivServiceId = 0x52u;
  static constexpr uint8_t ZpEcDsaGenerateFastServiceId = 0x53u;
  static constexpr uint8_t ZpEcDsaVerifyFastServiceId = 0x55u;
  static constexpr uint8_t ZpEcConvProjToAffineServiceId = 0x56u;
  static constexpr uint8_t SelfTestServiceId = 0x5Bu;
  static constexpr uint8_t FastCopyServiceId = 0x5Cu;
  static constexpr uint8_t GcdServiceId = 0x5Du;
  static constexpr uint8_t ZpEcRandomizeCoordinateServiceId = 0x5Eu;
  static constexpr uint8_t ClearFlagsServiceId = 0x5Fu;
  static constexpr uint8_t ZpEccDblFastServiceId = 0x60u;
  static constexpr uint8_t ZpEcConvAffineToProjectiveServiceId = 0x61u;
  static constexpr uint8_t RngServiceId = 0x62u;
  static constexpr uint8_t SwapServiceId = 0x63u;
  static constexpr uint8_t ZpEccMulFastServiceId = 0x65u;
  static constexpr uint8_t ZpEccAddFastServiceId = 0x66u;
  static constexpr uint8_t SmultServiceId = 0x67u;
  static constexpr uint8_t ZpEcPointIsOnCurveServiceId = 0x68u;
  static constexpr uint8_t CompServiceId = 0x6Bu;
  static constexpr uint8_t ExpModServiceId = 0x6Cu;
  static constexpr uint8_t SquareServiceId = 0x6Du;
  static constexpr uint8_t PrimeGenServiceId = 0x6Eu;
  static constexpr uint8_t FillServiceId = 0x6Fu;
  static constexpr uint8_t ZpEccAddSubFastServiceId = 0x75u;
  static constexpr uint8_t ZpEccQuickDualMulFastServiceId = 0x76u;
  static constexpr uint8_t ZpEcDsaQuickVerifyServiceId = 0x77u;
  static constexpr uint16_t StatusOk = 0x0000u;
  static constexpr uint16_t StatusSeverityMask = 0xC000u;
  static constexpr uint16_t StatusReasonMask = 0x3FFFu;
  static constexpr uint16_t StatusComputationNotStarted = 0xC001u;
  static constexpr uint16_t StatusUnknownService = 0xC002u;
  static constexpr uint16_t StatusUnexploitableOptions = 0xC003u;
  static constexpr uint16_t StatusHardwareIssue = 0xC004u;
  static constexpr uint16_t StatusWrongHardware = 0xC005u;
  static constexpr uint16_t StatusLibraryMalformed = 0xC006u;
  static constexpr uint16_t StatusError = 0xC007u;
  static constexpr uint16_t StatusUnknownSubservice = 0xC008u;
  static constexpr uint16_t StatusOverlapNotAllowed = 0xC010u;
  static constexpr uint16_t StatusParameterNotInPukccRam = 0xC011u;
  static constexpr uint16_t StatusParameterNotInRam = 0xC012u;
  static constexpr uint16_t StatusParameterNotInCpuRam = 0xC013u;
  static constexpr uint16_t StatusParameterWrongLength = 0xC014u;
  static constexpr uint16_t StatusParameterBadAlignment = 0xC015u;
  static constexpr uint16_t StatusParameterXBiggerThanY = 0xC016u;
  static constexpr uint16_t StatusParameterLengthTooSmall = 0xC017u;
  static constexpr uint16_t StatusDivisionByZero = 0xC101u;
  static constexpr uint16_t StatusMalformedModulus = 0xC102u;
  static constexpr uint16_t StatusFaultDetected = 0xC103u;
  static constexpr uint16_t StatusMalformedKey = 0xC104u;
  static constexpr uint16_t StatusWrongSignature = 0x8002u;
  static constexpr uint16_t StatusPointAtInfinity = 0x8001u;
  static constexpr uint16_t StatusPointIsNotOnCurve = 0x8004u;
  static constexpr uint16_t StatusNumberIsNotPrime = 0x4001u;
  static constexpr uint16_t StatusNumberIsPrime = 0x4002u;
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

  /**
   * @brief Common PUKCL ROM parameter header.
   *
   * Every PUKCL service parameter block begins with this header. Higher-level
   * crypto adapters build service-specific parameter blocks with this as the
   * first field, then submit the whole block through `serviceAsync()`. The
   * runner only schedules and completes the ROM call; it does not interpret
   * ECC/RSA/TLS policy or key material.
   */
  struct ServiceParamHeader {
    uint8_t service;
    uint8_t subService;
    uint16_t option;
    uint32_t specific;
    uint16_t status;
    uint16_t reserved16;
    uint32_t reserved32;
  };

  enum class StatusSeverity : uint8_t {
    Ok,
    Information,
    Warning,
    Severe,
  };

  static uintptr_t apbBaseAddress();
  static uintptr_t ahbBaseAddress();
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Pukcc; }
  inline static uintptr_t cryptoRamBaseAddress() {
    return CryptoRamAddressPrefix | CryptoRamNearBase;
  }

  /** @brief Return the CMSIS IRQ number for the PUKCC service block. */
  static int irqNumber();
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
  /** @brief Return true when the PUKCC service block is ready for ROM calls. */
  static bool ready();
  /** @brief Return the PUKCL severity class encoded in a service status. */
  static StatusSeverity statusSeverity(uint16_t serviceStatus);
  /** @brief Return the PUKCL status reason with severity bits removed. */
  static uint16_t statusReason(uint16_t serviceStatus);
  /** @brief Return true when a PUKCL status is an exact success. */
  static bool statusIsOk(uint16_t serviceStatus);
  /** @brief Return true when a PUKCL status is informational. */
  static bool statusIsInformation(uint16_t serviceStatus);
  /** @brief Return true when a PUKCL status is a warning. */
  static bool statusIsWarning(uint16_t serviceStatus);
  /** @brief Return true when a PUKCL status is a severe failure. */
  static bool statusIsSevere(uint16_t serviceStatus);
  /**
   * @brief Return the ROM jump-table entry for a known PUKCL service.
   * @return Thumb function address for known services, or 0 for unknown ones.
   */
  static uintptr_t serviceFunctionAddress(uint8_t serviceId);
  /** @brief Return true when the clean-room boundary knows this service ID. */
  static bool serviceHasKnownEntry(uint8_t serviceId);
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
   * @brief Register the PUKCC service callback.
   *
   * PUKCL ROM services are submitted from thread context and executed by the
   * PUKCC PendSV service. The callback also runs from PendSV context after the
   * result structure has been filled.
   */
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  /** @brief Clear callback state and cancel queued PUKCC service dispatch. */
  static void clearEventCallback();
  /** @brief Queue the mandatory PUKCL SelfTest service without blocking. */
  static bool selfTestAsync(SelfTestResult &result);
  /** @brief Queue the PUKCL ClearFlags service without blocking. */
  static bool clearFlagsAsync(uint32_t initialFlags, ServiceResult &result);
  /** @brief Queue the PUKCL Fill service without blocking. */
  static bool fillCryptoRamAsync(uint16_t offset, uint16_t length,
                                 uint32_t fillValue, ServiceResult &result);
  /**
   * @brief Queue a known PUKCL ROM service parameter block without blocking.
   *
   * The parameter object must remain alive until the registered callback fires.
   * `param` must be the first field of the service-specific parameter block,
   * not a detached copy, because the ROM service reads fields that follow this
   * header. Unknown service IDs and overlapping async submissions are rejected.
   */
  static bool serviceAsync(uint8_t serviceId, ServiceParamHeader &param,
                           ServiceResult &result);
  /** @brief Return true while a PUKCC async service is outstanding. */
  static bool asyncBusy();
  /** @brief Schedule PUKCC PendSV work from the PUKCC IRQ, when used. */
  static void handleInterrupt();
  /** @brief Return the CMSIS peripheral instance ID when exposed. */
  static int instanceId();
  /** @brief Return PUKCC RAM address width metadata from CMSIS. */
  static uint8_t ramAddressSize();
  /** @brief Return PUKCC ROM address width metadata from CMSIS. */
  static uint8_t romAddressSize();
};
#endif /* PUKCC_AVAILABLE */

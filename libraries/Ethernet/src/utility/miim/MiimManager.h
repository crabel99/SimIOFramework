#pragma once

/**
 * @file MiimManager.h
 * @brief Bounded non-blocking Clause-22 MDIO/MIIM operation manager.
 *
 * `MiimManager` serializes PHY management transactions over the SAME5x GMAC
 * MDIO controller. It is the Ethernet library's management-bus layer: callers
 * queue reads, writes, and PHY-address scans, then advance those operations
 * with bounded `service()` calls.
 *
 * This file intentionally does not define PHY policy. It validates management
 * bus addresses and registers, owns operation lifetime, and reports operation
 * completion. PHY identification, link decoding, speed/duplex resolution, and
 * MAC reconfiguration belong to the PHY and Ethernet coordinator layers.
 */

#include <GMAC.h>
#include <stdint.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE
/**
 * @brief Non-blocking MDIO/MIIM operation queue for the SAME5x GMAC controller.
 *
 * Contract:
 * - At most one MDIO transaction is active in the GMAC hardware at a time.
 * - Public queueing APIs fail immediately when the queue is full or the address
 *   arguments are invalid; they never spin waiting for hardware.
 * - `service()` performs one bounded progression step: complete the active
 *   transaction if possible, then start the next queued operation if possible.
 * - Completed results remain owned by the manager until the caller explicitly
 *   releases the operation handle.
 * - Callbacks are completion notifications only. They receive the same handle
 *   that can be inspected with `operationResult()` and freed with `release()`.
 *
 * This class maps to the MIIM/MDIO bus role. It must not decode PHY register
 * meaning, decide link state, configure GMAC speed/duplex, allocate packets, or
 * touch TCP/UDP/TLS state.
 */
class MiimManager {
public:
  /**
   * @brief Opaque operation identifier returned by queued operations.
   *
   * Handles stay valid until `release()` succeeds. A completed operation still
   * occupies a manager slot so callers can inspect the result after callback
   * delivery.
   */
  using OperationHandle = uint8_t;

  /**
   * @brief Queueing and completion result for MIIM operations.
   */
  enum OperationResult : int8_t {
    /// Operation completed successfully.
    ResultOk = 0,
    /// Operation is queued or active and has not completed.
    ResultPending,
    /// Queue is full, hardware cannot start now, or handle is still active.
    ResultBusy,
    /// Handle does not name a live queued, active, or completed operation.
    ResultInvalidHandle,
    /// PHY address is outside the Clause-22 range 0..31.
    ResultInvalidAddress,
    /// Register address is outside the Clause-22 register range.
    ResultInvalidRegister,
    /// Scan completed without finding a valid register value.
    ResultNotFound,
    /// Active operation exceeded the bounded service-pass limit.
    ResultTimeout,
    /// Queued operation was aborted before it reached hardware.
    ResultAborted,
    /// Reserved for internal consistency failures.
    ResultInternalError,
  };

  /**
   * @brief Completion callback for queued operations.
   *
   * @param handle Operation handle whose state just changed to complete.
   * @param result Completion result.
   * @param value Read value, written value, scan value, or zero on failure.
   * @param context Caller-provided context pointer.
   *
   * The callback runs from `service()` context. It must stay bounded and must
   * not block. The operation remains retained after callback delivery until
   * `release(handle)` succeeds.
   */
  using OperationCallback = void (*)(OperationHandle handle,
                                     OperationResult result, uint16_t value,
                                     void *context);

  /**
   * @brief MIIM controller setup policy.
   *
   * The GMAC owns the MDC divider bits, but the Ethernet management layer owns
   * the policy inputs: the GMAC host clock and the maximum MDC clock accepted by
   * the attached PHY. This setup path may touch hardware synchronously during
   * Ethernet startup; queued runtime MIIM operations remain non-blocking.
   */
  struct Setup {
    Setup(uint32_t hostClockHz = F_CPU,
          uint32_t maxMdcHz = gmac::DefaultMaxMdcHz)
        : hostClockHz(hostClockHz), maxMdcHz(maxMdcHz) {}

    uint32_t hostClockHz;
    uint32_t maxMdcHz;
  };

  /**
   * @brief Sentinel returned when an operation could not be queued.
   */
  static constexpr OperationHandle InvalidOperationHandle = 0;

  MiimManager();

  /**
   * @brief Configure the underlying GMAC MDIO controller.
   *
   * This method applies setup-time clock policy only. It does not reset queued
   * operations, scan for PHYs, decode link state, or wait for runtime MDIO
   * transactions to complete.
   */
  bool setup(const Setup &setup = Setup());

  /**
   * @brief Set the default PHY address recorded by the manager.
   *
   * This value is retained for callers that need to remember the selected PHY.
   * Queueing APIs still take an explicit PHY address so link-management code can
   * scan or address multiple PHYs without mutating shared state.
   */
  void setPhyAddress(uint8_t address);

  /**
   * @brief Return the retained default PHY address.
   */
  uint8_t phyAddress() const;

  /**
   * @brief Clear queued, active, and completed operations.
   *
   * `reset()` does not reset the external PHY and does not touch link policy.
   * It only resets the MIIM operation manager state.
   */
  void reset();

  /**
   * @brief Queue a Clause-22 register read.
   *
   * @param phyAddress PHY address, 0..31.
   * @param registerAddress Clause-22 register address.
   * @param callback Optional completion callback.
   * @param context Optional callback context.
   * @param result Optional immediate queueing result.
   * @return Operation handle, or `InvalidOperationHandle` if rejected.
   */
  OperationHandle read(uint8_t phyAddress, uint8_t registerAddress,
                       OperationCallback callback = nullptr,
                       void *context = nullptr,
                       OperationResult *result = nullptr);

  /**
   * @brief Queue a Clause-22 register write.
   *
   * The write value is returned through the callback/result path when the GMAC
   * management transaction reaches idle, giving callers one uniform completion
   * model for read and write operations.
   */
  OperationHandle write(uint8_t phyAddress, uint8_t registerAddress,
                        uint16_t value, OperationCallback callback = nullptr,
                        void *context = nullptr,
                        OperationResult *result = nullptr);

  /**
   * @brief Queue a PHY-address scan over an inclusive address range.
   *
   * The scan reads `registerAddress` from each address until a value other than
   * `0x0000` or `0xFFFF` is returned. The first valid value completes the
   * operation with `ResultOk`; exhausting the range completes with
   * `ResultNotFound`.
   */
  OperationHandle scan(uint8_t registerAddress, uint8_t firstPhyAddress,
                       uint8_t lastPhyAddress,
                       OperationCallback callback = nullptr,
                       void *context = nullptr,
                       OperationResult *result = nullptr);

  /**
   * @brief Inspect a queued, active, or completed operation.
   *
   * @param handle Operation handle returned by `read()`, `write()`, or `scan()`.
   * @param value Optional completed value output.
   * @return `ResultPending` while queued/active, final result when complete, or
   *         `ResultInvalidHandle` after release or for an unknown handle.
   */
  OperationResult operationResult(OperationHandle handle,
                                  uint16_t *value = nullptr) const;

  /**
   * @brief Release a completed operation slot.
   *
   * Releasing a queued or active operation returns `ResultBusy`; use `abort()`
   * for queued operations that should not reach hardware.
   */
  OperationResult release(OperationHandle handle);

  /**
   * @brief Abort or release an operation by handle.
   *
   * Queued operations complete immediately with `ResultAborted` and invoke their
   * callback. Completed operations are released. Active hardware transactions
   * cannot be cancelled and return `ResultBusy`.
   */
  OperationResult abort(OperationHandle handle);

  /**
   * @brief Advance the operation queue by one bounded step.
   *
   * @return true when an operation completed, a queued operation was skipped, or
   *         a new hardware transaction was started; false when no progress was
   *         possible during this pass.
   */
  bool service();

  /**
   * @brief Return true while any operation is queued or active.
   *
   * Completed-but-unreleased operations retain slots but are no longer busy.
   */
  bool busy() const;

  /**
   * @brief Return true when no operation slot is available.
   */
  bool full() const;

private:
  enum OperationType : uint8_t {
    OperationRead,
    OperationWrite,
    OperationScan,
  };

  enum OperationState : uint8_t {
    OperationFree,
    OperationQueued,
    OperationActive,
    OperationComplete,
  };

  struct Operation {
    OperationHandle handle;
    OperationType type;
    OperationState state;
    uint8_t phyAddress;
    uint8_t registerAddress;
    uint8_t scanEndAddress;
    uint16_t writeValue;
    uint16_t resultValue;
    OperationResult result;
    OperationCallback callback;
    void *context;
  };

  static constexpr uint8_t QueueDepth = 4;
  static constexpr uint8_t MaxPhyAddress = 31;
  static constexpr uint16_t OperationTimeoutServicePasses = 1000;

  Operation _operations[QueueDepth];
  uint8_t _queue[QueueDepth];
  uint8_t _phyAddress;
  uint8_t _queueReadIndex;
  uint8_t _queueWriteIndex;
  uint8_t _queueCount;
  uint8_t _activeOperationIndex;
  uint16_t _activeServicePasses;
  OperationHandle _nextHandle;

  OperationHandle queueOperation(OperationType type, uint8_t phyAddress,
                                 uint8_t registerAddress,
                                 uint8_t scanEndAddress, uint16_t writeValue,
                                 OperationCallback callback, void *context,
                                 OperationResult *result);
  OperationResult validateAddress(uint8_t phyAddress,
                                  uint8_t registerAddress) const;
  int8_t findOperation(OperationHandle handle) const;
  int8_t allocateOperation() const;
  bool queueOperationIndex(uint8_t operationIndex);
  bool startNextOperation();
  bool startOperation(Operation &operation);
  bool completeActiveOperation();
  bool continueScan(Operation &operation);
  void completeOperation(Operation &operation, OperationResult result,
                         uint16_t value);
  void releaseOperation(Operation &operation);
  bool scanValueIsValid(uint16_t value) const;
  static uint8_t nextQueueIndex(uint8_t index);
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */

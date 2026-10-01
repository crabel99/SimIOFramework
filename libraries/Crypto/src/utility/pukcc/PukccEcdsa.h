#pragma once
#include "PukccEcc.h"

#ifdef CRYPTO_HARDWARE_AVAILABLE
namespace Crypto::PukccEcc {
struct EccCurveParams {
  uint16_t coordinateLength;
  uint16_t pukccLength;
  uint16_t hashLength;
  const uint8_t *prime;
  const uint8_t *a;
  const uint8_t *b;
  const uint8_t *order;
  const uint8_t *gx;
  const uint8_t *gy;
};
extern const EccCurveParams P256Curve;

class EcdsaVerifier {
public:
  using Callback = void (*)(bool success, void *context);
  // The owner must complete pukcc::selfTestAsync successfully before submission.
  bool verifyP256Async(const uint8_t publicKey[65], const uint8_t hash[32],
                       const uint8_t signature[64], Callback callback, void *context) {
    return startEcdsaVerifyAsync(P256Curve, publicKey, hash, signature, callback, context);
  }
  bool startEcdsaVerifyAsync(const EccCurveParams &curve, const uint8_t *publicKey,
                             const uint8_t *hash, const uint8_t *signature,
                             Callback callback, void *context);
  bool busy() const { return _ecdsaBusy; }
  void reset();
private:
  enum class EcdsaVerifyStep : uint8_t {
    Idle, ReductionSetup, PublicKeyValidation, Verify, Complete, Error
  };
  static void handleEcdsaService(pukcc::EventMask, uint8_t, uint16_t, void *);
  bool submitEcdsaStep();
  void finishEcdsa(bool success);
  bool clearEcdsaWorkspace();
  ReductionSetupOperation _ecdsaReductionSetup{};
  PointIsOnCurveOperation _ecdsaPublicKeyValidation{};
  EcdsaVerifyOperation _ecdsaVerify{};
  pukcc::ServiceResult _ecdsaResult{};
  Callback _ecdsaCallback = nullptr;
  void *_ecdsaCallbackContext = nullptr;
  EcdsaVerifyStep _ecdsaStep = EcdsaVerifyStep::Idle;
  bool _ecdsaBusy = false;
};
}
#endif

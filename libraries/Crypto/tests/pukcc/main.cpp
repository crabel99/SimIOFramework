#include "PukccEcdsa.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <cstdio>
using Crypto::PukccEcc::EcdsaVerifier;
using Crypto::PukccEcc::P256Curve;
namespace {
alignas(4) uint8_t ram[pukcc::CryptoRamSize];
pukcc::EventCallback eventCallback;
void *eventContext;
bool hardwareReady=true, acceptRegistration=true;
int rejectSubmission=-1, rejectFill=-1, fills=0;
uint16_t clearedLength=0;
std::vector<uint8_t> services;
int calls; bool success;
void done(bool value,void*) { ++calls; success=value; }
void complete(uint16_t status=pukcc::StatusOk) {
 auto callback=eventCallback; auto context=eventContext;
 assert(callback);
 callback(status==pukcc::StatusOk?pukcc::EventComplete:pukcc::EventError,
          services.back(),status,context);
}
void fresh() {
 memset(ram,0xAA,sizeof(ram)); eventCallback=nullptr;eventContext=nullptr;
 hardwareReady=true;acceptRegistration=true;rejectSubmission=-1;
 services.clear();calls=0;success=false;rejectFill=-1;fills=0;clearedLength=0;
}
}
bool pukcc::validCryptoRamRange(uint16_t offset,uint16_t length) { return unsigned(offset)+length<=CryptoRamUsableSize; }
volatile uint8_t *pukcc::cryptoRam(uint16_t offset) { return ram+offset; }
uint16_t pukcc::cryptoRamNearPointer(uint16_t offset) { return CryptoRamNearBase+offset; }
void pukcc::enableClock() {}
bool pukcc::ready() { return hardwareReady; }
bool pukcc::fillCryptoRam(uint16_t offset,uint16_t length,uint32_t value,ServiceResult &result) {
 result={};result.service=FillServiceId;
 if (!hardwareReady || fills++==rejectFill) {result.status=StatusHardwareIssue;return false;}
 assert(value==0 && offset%4==0 && length%4==0 && validCryptoRamRange(offset,length));
 clearedLength=length;
 memset(ram+offset,0,length);result.status=StatusOk;return true;
}
namespace Crypto {
bool registerPukccCallback(pukcc::EventCallback callback,void *context) {
 if (!acceptRegistration) return false;
 eventCallback=callback;eventContext=context;return true;
}
void clearPukccCallback() { eventCallback=nullptr;eventContext=nullptr; }
bool pukccServiceAsync(uint8_t service,pukcc::ServiceParamHeader &,pukcc::ServiceResult &) {
 const int index=services.size();services.push_back(service);return index!=rejectSubmission;
}
}
int main() {
 uint8_t key[65]={4},hash[32]={},signature[64]={};
 memcpy(key+1,P256Curve.gx,32);memcpy(key+33,P256Curve.gy,32);
 signature[31]=1;signature[63]=1;
 for (int failure=-1;failure<3;++failure) {
  fresh();EcdsaVerifier verifier;
  assert(verifier.verifyP256Async(key,hash,signature,done,nullptr));
  assert(verifier.busy() && calls==0);
  assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));
  for (int step=0;step<3;++step) {
   assert(services.size()==unsigned(step+1));
   complete(step==failure?pukcc::StatusError:pukcc::StatusOk);
   if (step==failure) break;
  }
  assert(calls==1 && success==(failure<0) && !verifier.busy());
  assert(eventCallback==nullptr);
  assert(services[0]==pukcc::RedModServiceId);
  if (services.size()>1) assert(services[1]==pukcc::ZpEcPointIsOnCurveServiceId);
  if (services.size()>2) assert(services[2]==pukcc::ZpEcDsaVerifyFastServiceId);
 }
 for(int failure=0;failure<3;++failure) {
  fresh();rejectSubmission=failure;EcdsaVerifier verifier;
  assert(verifier.verifyP256Async(key,hash,signature,done,nullptr)==(failure!=0));
  for(int step=0;step<failure;++step) complete();
  assert(calls==1 && !success && !verifier.busy() && !eventCallback);
 }
 fresh();EcdsaVerifier verifier;
 assert(!verifier.verifyP256Async(nullptr,hash,signature,done,nullptr));
 assert(!verifier.verifyP256Async(key,nullptr,signature,done,nullptr));
 assert(!verifier.verifyP256Async(key,hash,nullptr,done,nullptr));
 assert(!verifier.verifyP256Async(key,hash,signature,nullptr,nullptr));
 key[0]=2;assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));key[0]=4;
 assert(calls==0 && services.empty());
 hardwareReady=false;assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));
 hardwareReady=true;acceptRegistration=false;
 assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));
 assert(calls==0 && services.empty());
 fresh();hardwareReady=false;
 uint8_t unavailableBefore[sizeof(ram)];memcpy(unavailableBefore,ram,sizeof(ram));
 assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));
 assert(memcmp(unavailableBefore,ram,sizeof(ram))==0 && "unready PUKCC must not modify Crypto RAM");
 assert(calls==0 && services.empty() && !eventCallback);
 fresh();acceptRegistration=false;
 uint8_t before[sizeof(ram)];memcpy(before,ram,sizeof(ram));
 assert(!verifier.verifyP256Async(key,hash,signature,done,nullptr));
 assert(memcmp(before,ram,sizeof(ram))==0);
 fresh();
 for(unsigned part=0;part<2;++part) {
  uint8_t badSignature[64];memcpy(badSignature,signature,64);
  memset(badSignature+part*32,0,32);
  assert(!verifier.verifyP256Async(key,hash,badSignature,done,nullptr));
  memcpy(badSignature+part*32,P256Curve.order,32);
  assert(!verifier.verifyP256Async(key,hash,badSignature,done,nullptr));
  uint8_t badKey[65];memcpy(badKey,key,65);
  memcpy(badKey+1+part*32,P256Curve.prime,32);
  assert(!verifier.verifyP256Async(badKey,hash,signature,done,nullptr));
 }
 assert(calls==0 && services.empty());
 for (unsigned length : {48u,66u}) {
  fresh();EcdsaVerifier wideVerifier;
  uint8_t modulus[66],order[66],zero[66]={},point[66]={1};
  memset(modulus,0xFF,sizeof(modulus));memset(order,0xFF,sizeof(order));
  uint8_t wideKey[133]={4},wideSignature[132]={},wideHash[64]={};
  wideKey[1]=1;wideKey[1+length]=1;
  wideSignature[length-1]=1;wideSignature[2*length-1]=1;
  Crypto::PukccEcc::EccCurveParams curve{
   uint16_t(length),uint16_t(length==66?68:48),uint16_t(length==66?64:48),
   modulus,zero,zero,order,point,point};
  assert(wideVerifier.startEcdsaVerifyAsync(curve,wideKey,wideHash,wideSignature,done,nullptr));
  complete();complete();
  const auto lastCallback=eventCallback;auto *lastContext=eventContext;
  complete();assert(calls==1 && success && !wideVerifier.busy());
  lastCallback(pukcc::EventComplete,pukcc::ZpEcDsaVerifyFastServiceId,pukcc::StatusOk,lastContext);
  assert(calls==1);
 }
 for (int failure : {0,1}) {
  fresh();rejectFill=failure;EcdsaVerifier fillVerifier;
  const bool accepted=fillVerifier.verifyP256Async(key,hash,signature,done,nullptr);
  assert(accepted==(failure!=0));
  if (accepted) {complete();complete();complete();}
  assert(calls==(failure!=0) && !success && !fillVerifier.busy() && !eventCallback);
  if (failure==0) assert(services.empty());
  rejectFill=-1;
  assert(fillVerifier.verifyP256Async(key,hash,signature,done,nullptr));
  complete();complete();complete();
  assert(success && !fillVerifier.busy() && !eventCallback);
  assert(clearedLength>0);
  for (unsigned i=0;i<sizeof ram;++i) assert(ram[i]==(i<clearedLength ? 0 : 0xAA));
 }
 puts("PUKCC verifier sequencing/error checks passed (ROM math is not emulated)");
}

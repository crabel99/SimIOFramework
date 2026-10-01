#pragma once
#include <stdint.h>
#define _UINT32_(x) static_cast<uint32_t>(x)
#define _UINT16_(x) static_cast<uint16_t>(x)
#define _UINT8_(x) static_cast<uint8_t>(x)
#define __I volatile
#define __O volatile
#define __IO volatile
#include <component/icm.h>
#include <component/mclk.h>
#include <component/nvmctrl.h>
extern icm_registers_t testIcm;
extern mclk_registers_t testMclk;
extern nvmctrl_registers_t testNvm;
#define ICM_REGS (&testIcm)
#define MCLK_REGS (&testMclk)
#define NVMCTRL_REGS (&testNvm)
struct TestDwt { uint32_t CYCCNT; };
extern TestDwt testDwt;
#define DWT (&testDwt)
enum IRQn_Type { ICM_IRQn };
inline uint32_t __get_PRIMASK() { return 0; }
inline void __disable_irq() {}
inline void __set_PRIMASK(uint32_t) {}
inline void __DSB() {}
inline void __ISB() {}
inline void NVIC_ClearPendingIRQ(IRQn_Type) {}
inline void NVIC_EnableIRQ(IRQn_Type) {}
inline void NVIC_DisableIRQ(IRQn_Type) {}

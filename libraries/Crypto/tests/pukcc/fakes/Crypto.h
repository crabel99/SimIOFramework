#pragma once
#include <PUKCC.h>
namespace Crypto {
bool registerPukccCallback(pukcc::EventCallback, void *);
void clearPukccCallback();
bool pukccServiceAsync(uint8_t, pukcc::ServiceParamHeader &, pukcc::ServiceResult &);
}

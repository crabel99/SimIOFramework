#pragma once

#include <utility/netif/EthernetNetif.h>

// lwIP port files live under utility/lwip and must depend on EthernetNetif,
// not on GMAC or SAME5x hardware headers directly.
using EthernetLwipNetif = EthernetNetif;

// SimIO's private SAME54 board uses the public Xplained Pro pin and SERCOM map.
// Keep this forwarding file so PlatformIO can retain the SimIO_Device_M4 board
// identity while the reusable hardware implementation remains xplained_m4.
#include "../xplained_m4/variant.cpp"

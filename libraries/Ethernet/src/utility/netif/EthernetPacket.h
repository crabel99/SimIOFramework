#pragma once

#include <stdint.h>

class EthernetPacket {
public:
  virtual ~EthernetPacket() = default;

  virtual const uint8_t *data() const = 0;
  virtual uint16_t length() const = 0;
  virtual void release() = 0;
};

class EthernetPacketAllocator {
public:
  virtual ~EthernetPacketAllocator() = default;

  virtual EthernetPacket *allocateCopy(const uint8_t *frame,
                                       uint16_t length) = 0;
};

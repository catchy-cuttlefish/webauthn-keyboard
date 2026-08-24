// FIDO CTAPHID + boot-keyboard USB interfaces for the ATmega32u4.
//
// Both live in ONE PluggableUSBModule exposing two interfaces. Registering two
// separate modules would cost another object, vtable and set of registration
// hooks; on a part with ~300 bytes of flash to spare that is worth avoiding.
//
// Endpoint budget on the ATmega32u4 is EP1..EP6. With CDC enabled:
//   EP1-3 CDC, EP4 FIDO IN, EP5 FIDO OUT, EP6 keyboard IN  -> exactly full.
#pragma once

#include <Arduino.h>

#if !defined(USBCON)
#error "This sketch needs a native-USB AVR board (Leonardo / Micro / Pro Micro)."
#endif

#include <PluggableUSB.h>

#define FIDO_HID_PACKET_SIZE 64

class FidoHID_ : public PluggableUSBModule {
public:
  FidoHID_();

  // --- CTAPHID transport ---
  bool recv(uint8_t *packet);          // non-blocking, 64-byte report
  void send(const uint8_t *packet);

  // --- keyboard ---
  // Sends one 8-byte boot-protocol report: modifier byte + one keycode.
  void keyReport(uint8_t modifier, uint8_t keycode);
  // True once the host has configured the interface (SET_CONFIGURATION seen).
  bool keyboardReady() const { return kbReady; }

protected:
  int  getInterface(uint8_t *interfaceCount);
  int  getDescriptor(USBSetup &setup);
  bool setup(USBSetup &setup);

private:
  uint8_t epType[3];
  uint8_t protocol;
  uint8_t idle;
  volatile bool kbReady;
};

extern FidoHID_ FidoHID;

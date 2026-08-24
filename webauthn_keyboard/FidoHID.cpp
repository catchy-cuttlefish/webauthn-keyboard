#include "FidoHID.h"

// The AVR core keeps these in USBCore.h, which is not on the sketch include
// path. Values are UECFG0X bit patterns for the ATmega32u4.
#ifndef EP_TYPE_INTERRUPT_IN
#define EP_TYPE_INTERRUPT_IN  0xC1
#endif
#ifndef EP_TYPE_INTERRUPT_OUT
#define EP_TYPE_INTERRUPT_OUT 0xC0
#endif

#define HID_DESCRIPTOR_TYPE        0x21
#define HID_REPORT_DESCRIPTOR_TYPE 0x22

#define HID_GET_REPORT   0x01
#define HID_GET_IDLE     0x02
#define HID_GET_PROTOCOL 0x03
#define HID_SET_REPORT   0x09
#define HID_SET_IDLE     0x0A
#define HID_SET_PROTOCOL 0x0B

static const uint8_t fidoReportDescriptor[] PROGMEM = {
  0x06, 0xD0, 0xF1,       // Usage Page (FIDO Alliance, 0xF1D0)
  0x09, 0x01,             // Usage (CTAPHID)
  0xA1, 0x01,             // Collection (Application)
  0x09, 0x20,             //   Usage (Input Report Data)
  0x15, 0x00,             //   Logical Minimum (0)
  0x26, 0xFF, 0x00,       //   Logical Maximum (255)
  0x75, 0x08,             //   Report Size (8)
  0x95, 0x40,             //   Report Count (64)
  0x81, 0x02,             //   Input (Data, Var, Abs)
  0x09, 0x21,             //   Usage (Output Report Data)
  0x15, 0x00,             //   Logical Minimum (0)
  0x26, 0xFF, 0x00,       //   Logical Maximum (255)
  0x75, 0x08,             //   Report Size (8)
  0x95, 0x40,             //   Report Count (64)
  0x91, 0x02,             //   Output (Data, Var, Abs)
  0xC0                    // End Collection
};

// Standard 8-byte boot keyboard: modifiers, reserved, 6 keycodes. Boot protocol
// means it works in BIOS/bootloader/login screens, not just a running desktop.
static const uint8_t kbReportDescriptor[] PROGMEM = {
  0x05, 0x01,             // Usage Page (Generic Desktop)
  0x09, 0x06,             // Usage (Keyboard)
  0xA1, 0x01,             // Collection (Application)
  0x05, 0x07,             //   Usage Page (Keyboard/Keypad)
  0x19, 0xE0,             //   Usage Minimum (LeftControl)
  0x29, 0xE7,             //   Usage Maximum (Right GUI)
  0x15, 0x00,             //   Logical Minimum (0)
  0x25, 0x01,             //   Logical Maximum (1)
  0x75, 0x01,             //   Report Size (1)
  0x95, 0x08,             //   Report Count (8)
  0x81, 0x02,             //   Input (Data, Var, Abs)  -- modifier bits
  0x95, 0x01,             //   Report Count (1)
  0x75, 0x08,             //   Report Size (8)
  0x81, 0x03,             //   Input (Cnst, Var, Abs)  -- reserved byte
  0x95, 0x06,             //   Report Count (6)
  0x75, 0x08,             //   Report Size (8)
  0x15, 0x00,             //   Logical Minimum (0)
  0x25, 0x65,             //   Logical Maximum (101)
  0x05, 0x07,             //   Usage Page (Keyboard/Keypad)
  0x19, 0x00,             //   Usage Minimum (0)
  0x29, 0x65,             //   Usage Maximum (101)
  0x81, 0x00,             //   Input (Data, Ary, Abs)  -- keycodes
  0xC0                    // End Collection
};

typedef struct {
  uint8_t len, dtype, addr, versionL, versionH, country, desctype, descLenL, descLenH;
} FidoHIDDescDescriptor;

typedef struct {
  InterfaceDescriptor    fidoItf;
  FidoHIDDescDescriptor  fidoDesc;
  EndpointDescriptor     fidoIn;
  EndpointDescriptor     fidoOut;
  InterfaceDescriptor    kbItf;
  FidoHIDDescDescriptor  kbDesc;
  EndpointDescriptor     kbIn;
} FidoHIDDescriptor;

#define IF_FIDO ((uint8_t)(pluggedInterface))
#define IF_KB   ((uint8_t)(pluggedInterface + 1))
#define EP_KB   ((uint8_t)(pluggedEndpoint + 2))

FidoHID_::FidoHID_()
  : PluggableUSBModule(3, 2, epType), protocol(1), idle(0), kbReady(false)
{
  epType[0] = EP_TYPE_INTERRUPT_IN;   // FIDO device -> host
  epType[1] = EP_TYPE_INTERRUPT_OUT;  // FIDO host   -> device
  epType[2] = EP_TYPE_INTERRUPT_IN;   // keyboard    -> host
  PluggableUSB().plug(this);
}

int FidoHID_::getInterface(uint8_t *interfaceCount)
{
  *interfaceCount += 2;
  FidoHIDDescriptor d = {
    D_INTERFACE(IF_FIDO, 2, USB_DEVICE_CLASS_HUMAN_INTERFACE, 0x00, 0x00),
    { 9, HID_DESCRIPTOR_TYPE, 0x01, 0x01, 0x00, 0x01, HID_REPORT_DESCRIPTOR_TYPE,
      (uint8_t)(sizeof(fidoReportDescriptor) & 0xFF),
      (uint8_t)(sizeof(fidoReportDescriptor) >> 8) },
    D_ENDPOINT(USB_ENDPOINT_IN(pluggedEndpoint),      USB_ENDPOINT_TYPE_INTERRUPT, FIDO_HID_PACKET_SIZE, 0x05),
    D_ENDPOINT(USB_ENDPOINT_OUT(pluggedEndpoint + 1), USB_ENDPOINT_TYPE_INTERRUPT, FIDO_HID_PACKET_SIZE, 0x05),

    // Subclass 1 / protocol 1 = boot interface, keyboard.
    D_INTERFACE(IF_KB, 1, USB_DEVICE_CLASS_HUMAN_INTERFACE, 0x01, 0x01),
    { 9, HID_DESCRIPTOR_TYPE, 0x01, 0x01, 0x00, 0x01, HID_REPORT_DESCRIPTOR_TYPE,
      (uint8_t)(sizeof(kbReportDescriptor) & 0xFF),
      (uint8_t)(sizeof(kbReportDescriptor) >> 8) },
    D_ENDPOINT(USB_ENDPOINT_IN(EP_KB), USB_ENDPOINT_TYPE_INTERRUPT, 8, 0x0A)
  };
  return USB_SendControl(0, &d, sizeof(d));
}

int FidoHID_::getDescriptor(USBSetup &setup)
{
  if (setup.bmRequestType != REQUEST_DEVICETOHOST_STANDARD_INTERFACE) return 0;
  if (setup.wValueH != HID_REPORT_DESCRIPTOR_TYPE) return 0;

  if (setup.wIndex == (uint16_t)IF_FIDO)
    return USB_SendControl(TRANSFER_PGM, fidoReportDescriptor, sizeof(fidoReportDescriptor));
  if (setup.wIndex == (uint16_t)IF_KB) {
    // The host only fetches this once it is enumerating the keyboard, which is
    // a good proxy for "the interface is live".
    kbReady = true;
    return USB_SendControl(TRANSFER_PGM, kbReportDescriptor, sizeof(kbReportDescriptor));
  }
  return 0;
}

bool FidoHID_::setup(USBSetup &setup)
{
  if (setup.wIndex != (uint16_t)IF_FIDO && setup.wIndex != (uint16_t)IF_KB) return false;

  uint8_t r = setup.bRequest;
  uint8_t t = setup.bmRequestType;

  if (t == REQUEST_DEVICETOHOST_CLASS_INTERFACE) {
    if (r == HID_GET_PROTOCOL) { USB_SendControl(0, &protocol, 1); return true; }
    if (r == HID_GET_IDLE)     { USB_SendControl(0, &idle, 1);     return true; }
  }
  if (t == REQUEST_HOSTTODEVICE_CLASS_INTERFACE) {
    if (r == HID_SET_PROTOCOL) { protocol = setup.wValueL; return true; }
    if (r == HID_SET_IDLE)     { idle = setup.wValueL;     return true; }
    if (r == HID_SET_REPORT)   { return true; }   // e.g. host LED state; ignored
  }
  return false;
}

bool FidoHID_::recv(uint8_t *packet)
{
  uint8_t ep = pluggedEndpoint + 1;
  if (USB_Available(ep) < FIDO_HID_PACKET_SIZE) return false;
  return USB_Recv(ep, packet, FIDO_HID_PACKET_SIZE) == FIDO_HID_PACKET_SIZE;
}

void FidoHID_::send(const uint8_t *packet)
{
  // TRANSFER_RELEASE forces the bank to ship even though the payload exactly
  // fills the 64-byte endpoint.
  USB_Send(pluggedEndpoint | TRANSFER_RELEASE, packet, FIDO_HID_PACKET_SIZE);
}

void FidoHID_::keyReport(uint8_t modifier, uint8_t keycode)
{
  uint8_t r[8] = { modifier, 0, keycode, 0, 0, 0, 0, 0 };
  USB_Send(EP_KB | TRANSFER_RELEASE, r, sizeof(r));
}

FidoHID_ FidoHID;

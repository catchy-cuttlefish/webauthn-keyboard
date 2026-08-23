#!/usr/bin/env python3
"""Reboot the authenticator into the Caterina bootloader over CTAPHID, and
optionally flash a build directory.

With CDC serial disabled there is no 1200-baud touch, and a Pro Micro has no
reset button, so this is the primary way to get the board into a programmable
state. The equivalent physical gesture is holding the button for 3 s.

    tools/reboot_bootloader.py                  # just reboot, print the port
    tools/reboot_bootloader.py --upload DIR     # reboot and flash DIR

Caterina only stays resident for ~8 s, so the upload has to start promptly.
"""
import os, sys, glob, time, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaplib import Device, find_fido_hidraw, CTAPHID_BOOTLOADER

# Application PIDs vs bootloader PIDs. The bootloader re-uses the same
# /dev/ttyACM* name as the sketch, so the port name tells you nothing --
# the product ID is what distinguishes them.
BOOTLOADER_IDS = {("2341", "0036"), ("2a03", "0036"),   # Leonardo
                  ("1b4f", "9205"), ("1b4f", "9203")}   # SparkFun Pro Micro


def usb_nodes():
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        try:
            vid = open(d + "idVendor").read().strip()
            pid = open(d + "idProduct").read().strip()
        except OSError:
            continue
        yield d, vid, pid


def find_bootloader_port():
    for d, vid, pid in usb_nodes():
        if (vid, pid) not in BOOTLOADER_IDS:
            continue
        for tty in glob.glob(d + "*/tty/*"):
            return "/dev/" + os.path.basename(tty)
    return None


def main():
    upload_dir = None
    if "--upload" in sys.argv:
        i = sys.argv.index("--upload")
        upload_dir = sys.argv[i + 1]
        del sys.argv[i:i+2]

    path = sys.argv[1] if len(sys.argv) > 1 else find_fido_hidraw()
    if not path:
        sys.exit("no FIDO hidraw device found (is the board plugged in?)")

    d = Device(path)
    d.init()
    print(f"rebooting {path} into the bootloader...")
    d.send(CTAPHID_BOOTLOADER, b"")
    try:
        d.recv(timeout=2.0)
    except Exception:
        pass                                            # device may vanish first

    port = None
    for _ in range(40):
        time.sleep(0.25)
        port = find_bootloader_port()
        if port:
            break
    if not port:
        return "bootloader did not appear; hold the button for 3 s instead"

    # The tty node appears in sysfs slightly before udev finishes setting it
    # up; opening it immediately gets "butterfly_recv failed".
    time.sleep(1.0)

    print(f"bootloader on {port}")
    if not upload_dir:
        print(f"upload with:  arduino-cli upload -b arduino:avr:leonardo "
              f"-p {port} --input-dir <dir>")
        return 0

    # Deliberately NOT `arduino-cli upload`: for Leonardo-class boards it does a
    # 1200-baud touch on the port first, and Caterina reads that as "reset and
    # run the sketch", so the upload races against the bootloader exiting.
    # Talking to avrdude directly skips the touch.
    hexes = glob.glob(os.path.join(upload_dir, "*.ino.hex"))
    if not hexes:
        return f"no .ino.hex in {upload_dir}"
    avrdude = sorted(glob.glob(os.path.expanduser(
        "~/.arduino15/packages/arduino/tools/avrdude/*/bin/avrdude")))[-1]
    conf = sorted(glob.glob(os.path.expanduser(
        "~/.arduino15/packages/arduino/tools/avrdude/*/etc/avrdude.conf")))[-1]
    cmd = [avrdude, "-C", conf, "-p", "atmega32u4", "-c", "avr109",
           "-P", port, "-b", "57600", "-D", "-U", "flash:w:%s:i" % hexes[0]]
    rc = subprocess.call(cmd)
    return rc


if __name__ == "__main__":
    sys.exit(main())

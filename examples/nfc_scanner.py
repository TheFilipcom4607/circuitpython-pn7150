"""Tag scanner with NeoPixel feedback for the Challenger RP2040 NFC.

The on-board NeoPixel (GPIO14) flashes:
    amber  - scanner started
    green  - tag detected
    cyan   - tag carried an NDEF message
    red    - a read failed

Reads are non-destructive: each tag is authenticated and read at most once, in
one activation. (Mifare Classic will refuse a second authentication with a
different key in the same tap, so probing "just to see" actively breaks the
session and the NDEF read with it.)

Copy this to CIRCUITPY/code.py to run it.
"""
import board
import digitalio
import neopixel_write
from time import sleep
from pn7150 import PN7150, PN7150Error, Type3Tag, hexlify

_pixel = digitalio.DigitalInOut(board.NEOPIXEL)
_pixel.switch_to_output()

OFF = (0, 0, 0)
GREEN = (0, 40, 0)
CYAN = (0, 30, 30)
RED = (40, 0, 0)
AMBER = (35, 18, 0)


def pixel(color):
    """Set the NeoPixel. Colors are (r, g, b); the WS2812 wants GRB order."""
    r, g, b = color
    neopixel_write.neopixel_write(_pixel, bytearray((g, r, b)))


def flash(color, duration=0.12, times=1):
    for i in range(times):
        pixel(color)
        sleep(duration)
        pixel(OFF)
        if i + 1 < times:
            sleep(duration)


flash(AMBER)

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
nfc.connect()
print("PN7150 fw %s - ready, each tag reported once" % nfc.firmware_version)
print("=" * 62)
print("waiting for a tag...")

with nfc:
    for tag in nfc.scan():
        flash(GREEN)
        print()
        print("%s   %s" % (tag.type, tag.technology_name))
        print("  UID: %s" % (tag.uid_hex or "(none)"))

        try:
            if isinstance(tag, Type3Tag):
                print("  IDm: %s   PMm: %s"
                      % (hexlify(tag.idm), hexlify(tag.pmm or b"")))

            message = tag.ndef
            if message is None:
                print("  NDEF: none")
            else:
                flash(CYAN, times=2)
                for rec in message:
                    value = rec.value
                    if isinstance(value, bytes):
                        value = hexlify(value[:24]) + (
                            "... (%d bytes)" % len(rec.payload)
                            if len(rec.payload) > 24 else "")
                    print("  NDEF %-6s: %s" % (rec.kind, value))
        except PN7150Error as err:
            print("  read failed: %s: %s" % (type(err).__name__, err))
            flash(RED, times=2)

        print("waiting for a tag...")

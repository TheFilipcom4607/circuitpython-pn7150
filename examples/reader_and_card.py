"""Read tags and answer phones in one loop.

`also_poll=True` keeps the reader/writer poll loop running alongside listen
mode, so the same board reads an NTAG when you present one and answers a phone
when one taps - no reconfiguration between the two.

Copy this to CIRCUITPY/code.py to run it.
"""
import board
from pn7150 import PN7150, CardEmulator, Type4NDEFApplet

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
applet = Type4NDEFApplet("https://example.com")


def on_tag(tag):
    print("read a tag:", tag)
    if tag.ndef:
        print("  ->", tag.ndef.value)


with nfc:
    emulator = CardEmulator(nfc, also_poll=True, on_tag=on_tag)
    emulator.start()
    print("polling for tags and listening for phones")
    try:
        emulator.run(applet)
    finally:
        emulator.stop()

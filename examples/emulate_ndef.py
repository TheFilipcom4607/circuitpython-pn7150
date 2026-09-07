"""Be the tag: present this board to a phone as a Type 4 NDEF tag.

Tap an Android phone or an iPhone (XS and later, background tag reading) on
the antenna and the URL below comes up as a notification banner, exactly as
if a sticker were sitting there.

The PN7150 runs the whole ISO-DEP protocol stack itself, so nothing here has
to answer SENS_REQ, RATS or ATS; the controller hands up bare APDUs and the
Type 4 applet answers them.

NFC-A only, and one reader at a time. Copy this to CIRCUITPY/code.py to run it.
"""
import board
from pn7150 import PN7150, NDEFMessage, NDEFRecord

MESSAGE = "https://example.com"
# Anything write_ndef() accepts works here too:
#   NDEFMessage.from_text("hello", "en")
#   NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("caption")])


def read(message):
    print("a reader took:", message.value)


def written(message):
    print("a reader wrote:", message.value)


nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
with nfc:
    print("emulating", MESSAGE, "- tap a phone")
    # writable=True lets the phone (Android's NFC Tools, say) write back, and
    # on_write fires with whatever it wrote. Leave it out for a read-only tag.
    applet = nfc.emulate_ndef(MESSAGE, writable=True,
                              on_read=read, on_write=written)
    print("finished; the tag now holds", applet.message)

"""Write an NDEF message to a Type 2 tag (NTAG / Ultralight).

This MODIFIES the tag. Pages 0-3 (UID, lock bits, capability container) are
refused by the library, so the tag itself cannot be bricked by a bad page
number, but the existing NDEF content is overwritten.
"""
import board
from pn7150 import PN7150, NDEFMessage, NDEFRecord, Type2Tag

MESSAGE = NDEFMessage.from_uri("https://example.com/hello")
# Other options:
#   NDEFMessage.from_text("hello", "en")
#   NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("caption")])

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
with nfc:
    print("present a Type 2 tag to write...")
    for tag in nfc.scan():
        if not isinstance(tag, Type2Tag):
            print("%s cannot be written by this example" % tag.type)
            continue
        print("before:", tag.ndef and tag.ndef.value)
        tag.write_ndef(MESSAGE)
        print("written. verifying...")
        # Re-read from the tag rather than trusting the cache.
        tag._ndef_read = False
        print("after :", tag.ndef and tag.ndef.value)
        break

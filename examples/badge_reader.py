"""Access-control style reader: match a UID, then wait for the tag to leave.

Shows the presence API. `tag.is_present()` is cheap enough to poll, and
`tag.wait_for_removal()` blocks until the tag is lifted -- so the "door" stays
open exactly as long as the badge is held there, and one tag cannot trigger
twice without being taken away and brought back.

Copy this to CIRCUITPY/code.py to run it.
"""
import board
from pn7150 import PN7150, PN7150Error

# UIDs allowed through, as they print from tag.uid_hex.
ALLOWED = {
    "04:8c:e8:12:34:56:80": "Filip",
}

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)

with nfc:
    print("reader up (fw %s). present a badge." % nfc.firmware_version)
    # skip_repeats=False, because holding a badge on the antenna is exactly
    # what this example wants to observe.
    for tag in nfc.scan(skip_repeats=False):
        name = ALLOWED.get(tag.uid_hex)
        if name is None:
            print("denied: %s (%s)" % (tag.uid_hex, tag.type))
            continue

        print("welcome, %s -- hold the badge..." % name)
        try:
            # Returns as soon as the badge leaves, or after 10 seconds.
            if tag.wait_for_removal(timeout=10):
                print("badge lifted, closing")
            else:
                print("badge left on the reader; closing anyway")
        except PN7150Error as err:
            # Presence checks talk to the tag, so they can fail like any read.
            print("presence check failed: %s: %s" % (type(err).__name__, err))

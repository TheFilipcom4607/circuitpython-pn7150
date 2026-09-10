"""Write a tag that does something other than open a URL.

A phone acts on the record type, not on the text inside it, so the same tap
can join a Wi-Fi network, add a contact, dial a number, pair a speaker or
start HomeKit pairing. Pick one below and present a Type 2 tag (NTAG213 and
up; the Wi-Fi record needs about 90 bytes, a contact rather more).

This MODIFIES the tag - the existing NDEF content is overwritten. Copy this
to CIRCUITPY/code.py to run it.
"""
import board
from pn7150 import PN7150, NDEFMessage, Type2Tag

MESSAGE = NDEFMessage.from_wifi("HomeNet", "correcthorsebatterystaple")
# Other options:
#   NDEFMessage.from_contact("Ada Lovelace", phone="+48123456789",
#                            email="ada@example.com", title="Engineer")
#   NDEFMessage.from_tel("+48123456789")
#   NDEFMessage.from_email("ada@example.com", "Hello", "Sent by a tag")
#   NDEFMessage.from_sms("+48123456789", "on my way")
#   NDEFMessage.from_bluetooth("AA:BB:CC:DD:EE:FF", "Speaker")
#   NDEFMessage.from_homekit("518-08-361", category=HOMEKIT_LIGHTBULB,
#                            setup_id="7OSX")

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
with nfc:
    print("present a Type 2 tag to write...")
    for tag in nfc.scan():
        if not isinstance(tag, Type2Tag):
            print("%s cannot be written by this example" % tag.type)
            continue
        print("capacity:", tag.capacity, "bytes; message:",
              len(MESSAGE.to_bytes()))
        tag.write_ndef(MESSAGE)
        # Re-read from the tag rather than trusting the cache.
        tag._ndef_read = False
        print("written:", tag.ndef.records[0].kind, tag.ndef.value)
        break

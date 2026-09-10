# On-device unit tests: run every pure-logic path under CircuitPython,
# where CPython-only behaviour (int-in-bytearray, etc.) actually shows up.
import pn7150
from pn7150 import (NDEFMessage, NDEFRecord, Tag, Type2Tag, Type4NDEFApplet,
                    hexlify, TECH_NFC_A, TECH_NFC_B, TECH_NFC_F, TECH_NFC_V)

passed = failed = 0

def check(name, got, want):
    global passed, failed
    if got == want:
        passed += 1
        print("  ok   %s" % name)
    else:
        failed += 1
        print("  FAIL %s\n       got  %r\n       want %r" % (name, got, want))

def check_raises(name, fn, exc):
    global passed, failed
    try:
        fn()
    except exc:
        passed += 1
        print("  ok   %s" % name)
        return
    except Exception as e:
        failed += 1
        print("  FAIL %s raised %s not %s" % (name, type(e).__name__, exc.__name__))
        return
    failed += 1
    print("  FAIL %s did not raise" % name)

print("--- UID parsing, all four technologies ---")
class FakeNFC:
    pass
def mk(tech, params):
    return Tag(FakeNFC(), 0, 1, 2, tech, bytes(params))

t = mk(TECH_NFC_A, b"\x44\x00\x07\x9f\xa1\xd0\x00\xc7\x1b\x03\x01\x00")
check("NFC-A uid", t.uid_hex, "9f:a1:d0:00:c7:1b:03")
check("NFC-A sens_res", hexlify(t.sens_res), "44:00")
check("NFC-A sel_res", t.sel_res, 0x00)

t = mk(TECH_NFC_B, b"\x0b\x50\x11\x22\x33\x44\x00\x00\x00\x00\x00\x00")
check("NFC-B nfcid0", t.uid_hex, "11:22:33:44")

# NFC-F params are BITRATE, SENSF_RES_LEN, SENSF_RES(= IDm x8 + PMm x8).
# NCI strips the 0x01 response code, so the field is 16 bytes, not 17.
t = mk(TECH_NFC_F, b"\x01\x10" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
                   + b"\xf1\x00\x00\x00\x00\x00\x00\xff")
check("NFC-F IDm", t.uid_hex, "01:02:03:04:05:06:07:08")
check("NFC-F PMm", hexlify(t.pmm), "f1:00:00:00:00:00:00:ff")
check("NFC-F bitrate byte", t.bitrate, 1)

# Verbatim rf_params captured from a real FeliCa card. This is the regression
# test for the off-by-one that made every CHECK time out.
REAL = bytes([0x01, 0x10, 0x01, 0x01, 0x03, 0x12, 0x23, 0x1b, 0x50, 0x27,
              0x01, 0x36, 0x42, 0x82, 0x47, 0x45, 0x9a, 0xff,
              0x02, 0x01, 0x01, 0x00])
t = mk(TECH_NFC_F, REAL)
check("real card IDm", t.uid_hex, "01:01:03:12:23:1b:50:27")
check("real card PMm", hexlify(t.pmm), "01:36:42:82:47:45:9a:ff")

t = mk(TECH_NFC_V, b"\x00\x00\x84\x9a\x25\x66\x08\x01\x04\xe0")
check("NFC-V uid (LSB->MSB)", t.uid_hex, "e0:04:01:08:66:25:9a:84")
check("NFC-V dsfid", t.dsfid, 0x00)

t = mk(TECH_NFC_A, b"\x44")          # deliberately truncated
check("short params do not crash", t.uid, b"")

print("--- NDEF records ---")
m = NDEFMessage.from_uri("https://thefilip.com")
check("uri encode", hexlify(m.to_bytes()),
      "d1:01:0d:55:04:74:68:65:66:69:6c:69:70:2e:63:6f:6d")
check("uri round trip", NDEFMessage.from_bytes(m.to_bytes()).uri,
      "https://thefilip.com")
check("prefix picked", NDEFRecord.uri("https://www.example.com").payload[0], 2)
check("no prefix", NDEFRecord.uri("cheese").payload[0], 0)
check("tel prefix", NDEFRecord.uri("tel:+123").payload[0], 5)

r = NDEFRecord.text("hallå", "no")
msg = NDEFMessage([r])
back = NDEFMessage.from_bytes(msg.to_bytes())
check("text round trip", back.text, "hallå")
check("text language", back.records[0].language, "no")

multi = NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("two")])
back = NDEFMessage.from_bytes(multi.to_bytes())
check("multi record count", len(back), 2)
check("multi uri", back.uri, "https://a.co")
check("multi text", back.text, "two")

big = NDEFRecord.mime("application/octet-stream", bytes(300))
back = NDEFMessage.from_bytes(NDEFMessage([big]).to_bytes())
check("long record (non-short header)", len(back.records[0].payload), 300)
check("mime kind", back.records[0].kind, "mime")

print("--- TLV handling ---")
real = b"\x01\x03\xa0\x0c\x34\x03\x11\xd1\x01\x0d\x55\x04thefilip.com\xfe"
check("real tag TLV", pn7150._ndef_from_tlv(real).uri, "https://thefilip.com")
check("no NDEF present", pn7150._ndef_from_tlv(b"\x00\x00\xfe"), None)
long_tlv = pn7150._ndef_to_tlv(NDEFMessage([big]))
check("3-byte length form emitted", long_tlv[1], 0xFF)
check("3-byte length round trip",
      len(pn7150._ndef_from_tlv(long_tlv).records[0].payload), 300)
check_raises("truncated TLV raises NDEFError",
             lambda: pn7150._ndef_from_tlv(b"\x03\x20\xd1\x01"), pn7150.NDEFError)

print("--- status splitting (sizes measured on hardware) ---")
# T2T READ: 16 data + status
body, st = pn7150._split_status(bytes(range(16)) + b"\x00")
check("t2t 17->16 data", len(body), 16)
check("t2t status", st, 0)
# MIFARE read: 0x10 prefix + 16 data + status
body, _ = pn7150._split_status(b"\x10" + bytes(range(16)) + b"\x00")
check("mfc 18->17 (prefix kept for caller)", len(body), 17)
# ISO15693: flags + 4 data + status
body, _ = pn7150._split_status(b"\x00\xe1\x40\x27\x01\x00")
check("t5t 6->5", hexlify(body), "00:e1:40:27:01")
check_raises("non-zero status raises",
             lambda: pn7150._split_status(bytes(16) + b"\x03"),
             pn7150.CommandError)
check_raises("empty response raises",
             lambda: pn7150._split_status(b""), pn7150.CommandError)

print("--- guard rails ---")
class FakeT2(Type2Tag):
    def __init__(self):
        Tag.__init__(self, FakeNFC(), 0, 1, 2, TECH_NFC_A, b"\x44\x00\x04\x01\x02\x03\x04\x01\x00")
check_raises("refuses to write page 0", lambda: FakeT2().write(0, b"\x00\x00\x00\x00"), ValueError)
check_raises("refuses wrong page size", lambda: FakeT2().write(4, b"\x00"), ValueError)

print("--- Type 3 / FeliCa (synthetic card) ---")
IDM = b"\x01\x02\x03\x04\x05\x06\x07\x08"
NDEF_BYTES = NDEFMessage.from_uri("https://thefilip.com").to_bytes()
# Attribute Information Block: Ver 1.0, Nbr 4, Nbw 1, Nmaxb 13, RW, Ln = len
ATTR = (bytes([0x10, 0x04, 0x01, 0x00, 0x0D, 0, 0, 0, 0, 0x00, 0x01,
               (len(NDEF_BYTES) >> 16) & 0xFF,
               (len(NDEF_BYTES) >> 8) & 0xFF,
               len(NDEF_BYTES) & 0xFF]) + b"\x01\x23")
BLOCKS = [ATTR]
_pad = NDEF_BYTES + b"\x00" * (-len(NDEF_BYTES) % 16)
for _i in range(0, len(_pad), 16):
    BLOCKS.append(_pad[_i:_i + 16])

class FakeFelica(pn7150.Type3Tag):
    def __init__(self):
        # BITRATE(1) SENSF_RES_LEN(1) then SENSF_RES = IDm x8 + PMm x8.
        # Built to match a real card, not to match the parser.
        params = bytes([0x01, 0x10]) + IDM + b"\xf1\x00\x00\x00\x00\x00\x00\xff"
        pn7150.Tag.__init__(self, FakeNFC(), 0, 1, 3, TECH_NFC_F, params)
        self.sent = []
    def transceive(self, data, timeout=0.5):
        self.sent.append(bytes(data))
        block = data[15]
        body = BLOCKS[block] if block < len(BLOCKS) else bytes(16)
        return (bytes([0x1D, 0x07]) + IDM + bytes([0x00, 0x00, 0x01])
                + body + b"\x00")

f = FakeFelica()
check("felica idm from SENSF_RES", hexlify(f.idm), "01:02:03:04:05:06:07:08")
blk = f.check(0)
check("CHECK command frame", hexlify(f.sent[0]),
      "10:06:01:02:03:04:05:06:07:08:01:0b:00:01:80:00")
check("CHECK returns 16 bytes", len(blk), 16)

a = f.attributes()
check("attr version", a["version"], "1.0")
check("attr max_blocks", a["max_blocks"], 13)
check("attr writable", a["writable"], True)
check("attr ndef_length", a["ndef_length"], len(NDEF_BYTES))

f2 = FakeFelica()
check("felica NDEF (no TLV wrapper)", f2.read_ndef().uri, "https://thefilip.com")
check("read only the blocks needed", len(f2.sent), 1 + len(BLOCKS) - 1)

class BadFelica(FakeFelica):
    def transceive(self, data, timeout=0.5):
        r = FakeFelica.transceive(self, data, timeout)
        return r[:10] + b"\xff\xa2" + r[12:]   # SF1/SF2 = error
check_raises("FeliCa error flags raise",
             lambda: BadFelica().check(0), pn7150.CommandError)

print("--- NCI status codes (NCI 1.0 table 94) ---")
check("0xA0 is DISCOVERY_ALREADY_STARTED",
      pn7150.STATUS_NAMES.get(0xA0), "DISCOVERY_ALREADY_STARTED")
check("0xB0 is RF_TRANSMISSION_ERROR",
      pn7150.STATUS_NAMES.get(0xB0), "RF_TRANSMISSION_ERROR")
check("0xB2 is RF_TIMEOUT_ERROR",
      pn7150.STATUS_NAMES.get(0xB2), "RF_TIMEOUT_ERROR")
check("felica SF2 0xA6 decoded",
      pn7150._felica_error(0xA6), "service not present on this card")

print("--- regressions (these all shipped broken once) ---")
# A formatted but empty tag holds `03 00 FE`. That is an empty message, not a
# malformed one, and finding it should cost one read, not a whole memory dump.
check("empty TLV reads as none", pn7150._ndef_from_tlv(b"\x03\x00\xfe" + bytes(10)), None)
_reads = []
def _blank_read(page):
    _reads.append(page)
    image = b"\x03\x00\xfe" + bytes(501)
    return image[(page - 4) * 4:(page - 4) * 4 + 16]
check("blank tag stops at terminator", pn7150._read_ndef_area(_blank_read, 4, 4, 504), None)
check("...in one read", len(_reads), 1)

# 0xFE is a TLV terminator only between TLVs. Inside a binary payload it is
# ordinary data, and scanning for it truncated any message that contained one.
check("tlv end: need more", pn7150._ndef_tlv_end(b"\x03"), pn7150.TLV_NEED_MORE)
check("tlv end: terminator", pn7150._ndef_tlv_end(b"\xfe"), pn7150.TLV_NO_NDEF)
check("tlv end: real tag", pn7150._ndef_tlv_end(b"\x01\x03\xa0\x0c\x34\x03\x11"), 24)
check("tlv end: 3-byte form", pn7150._ndef_tlv_end(b"\x03\xff\x01\x00"), 4 + 256)

_payload = bytes([0xFE if i in (30, 31) else i % 251 for i in range(200)])
_tlv = pn7150._ndef_to_tlv(NDEFMessage([NDEFRecord.mime("application/cbor", _payload)]))
_image = _tlv + bytes(512)
_blocks = {}
_off, _blk = 0, 4
while _off < len(_image):
    if _blk % 4 == 3:
        _blk += 1
        continue
    _blocks[_blk] = _image[_off:_off + 16]
    _off += 16
    _blk += 1

class FakeMifare(pn7150.MifareClassicTag):
    def __init__(self):
        Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_MIFARE, TECH_NFC_A,
                     b"\x44\x00\x04\x01\x02\x03\x04\x01\x08")
    def authenticate(self, sector, key=None, key_b=False):
        return True
    def read_block(self, block):
        return _blocks.get(block, bytes(16))

check("0xFE in a payload is not a terminator",
      FakeMifare().read_ndef().records[0].payload, _payload)

mfc = pn7150.MifareClassicTag
check("4K sector of block 128", mfc.sector_of(128), 32)
check("4K sector of block 144", mfc.sector_of(144), 33)
check("4K first block of sector 33", mfc.first_block_of(33), 144)
check("4K trailer is block 143", mfc.is_trailer(143), True)
check("4K block 142 is data", mfc.is_trailer(142), False)

# Writing past the declared capacity lands in the lock bytes and config pages.
class BoundedT2(Type2Tag):
    def __init__(self):
        Tag.__init__(self, FakeNFC(), 0, 1, 2, TECH_NFC_A,
                     b"\x44\x00\x04\x01\x02\x03\x04\x01\x00")
        self.sent = []
    def read(self, page):
        if page == 3:
            return b"\xe1\x10\x06\x00" + bytes(12)   # MLEN 6 -> 48 bytes
        return bytes(16)
    def transceive(self, data, timeout=0.5):
        self.sent.append(bytes(data))
        return b"\x00"

check("capacity from CC", BoundedT2().capacity, 48)
check("last data page", BoundedT2().last_data_page, 15)
_t = BoundedT2()
check_raises("refuses a message larger than the tag",
             lambda: _t.write_ndef(NDEFMessage([NDEFRecord.mime("application/x", bytes(400))])),
             pn7150.NDEFError)
check("nothing was written first", _t.sent, [])
check_raises("refuses the first config page",
             lambda: BoundedT2().write(16, b"\x00\x00\x00\x00"), ValueError)
check_raises("force never lifts the lower bound",
             lambda: BoundedT2().write(0, b"\x00\x00\x00\x00", True), ValueError)
check("force lifts the upper bound",
      BoundedT2().write(40, b"\x00\x00\x00\x00", True), True)

check_raises("oversized NCI payload is a clear error",
             lambda: Tag(FakeNFC(), 0, 1, 2, TECH_NFC_A, b"\x44\x00\x00",
                         max_payload=32).transceive(bytes(33)), ValueError)

# CircuitPython native exceptions have no Python-level __init__, so a subclass
# that calls PN7150Error.__init__(self, msg) raises AttributeError here while
# passing on CPython. This check exists because that shipped once.
_e = pn7150.CommandError("boom", 0x02)
check("CommandError keeps its message", str(_e), "boom")
check("CommandError carries status", _e.status, 0x02)
check("CommandError status defaults", pn7150.CommandError("plain").status, None)
try:
    raise pn7150.CommandError("thrown", 0xB2)
except pn7150.PN7150Error as _caught:
    check("status survives raise/catch", _caught.status, 0xB2)
try:
    pn7150._split_status(bytes(4) + b"\x02", "read")
    check("split_status raises", False, True)
except pn7150.CommandError as _e2:
    check("split_status status is 0x02", _e2.status, 0x02)
check("transient status is retried", pn7150._is_transient(
    pn7150.CommandError("x", 0x02)), True)
check("refusal is not retried", pn7150._is_transient(
    pn7150.CommandError("x", 0x03)), False)

print("--- Wi-Fi, contacts, Bluetooth, HomeKit ---")
_wifi = NDEFMessage.from_wifi("HomeNet", "correcthorse")
check("wifi mime type", _wifi.records[0].type, b"application/vnd.wfa.wsc")
check("wifi kind", _wifi.records[0].kind, "wifi")
_wifi_back = NDEFMessage.from_bytes(_wifi.to_bytes()).wifi
check("wifi ssid", _wifi_back["ssid"], "HomeNet")
check("wifi password", _wifi_back["password"], "correcthorse")
check("wifi defaults to wpa2", _wifi_back["authentication"], pn7150.WIFI_WPA2_PSK)
check("no mac attribute unless asked for", _wifi_back["mac"], None)
check_raises("wifi refuses an open network with a password",
             lambda: NDEFRecord.wifi("HomeNet", "correcthorse",
                                     authentication=pn7150.WIFI_OPEN),
             pn7150.NDEFError)
check("wifi security name", _wifi_back["security"], "wpa2")
check("open network has no key",
      NDEFMessage.from_wifi("Guest").wifi["password"], "")
check_raises("wifi refuses a short passphrase",
             lambda: NDEFRecord.wifi("HomeNet", "short"), pn7150.NDEFError)

_card = NDEFMessage.from_contact("Ada Lovelace", phone="+48123456789",
                                 email="ada@example.com", note="one;two")
check("contact kind", _card.records[0].kind, "contact")
_card_back = NDEFMessage.from_bytes(_card.to_bytes()).contact
check("contact name", _card_back["name"], "Ada Lovelace")
check("contact phones", _card_back["phone"], ["+48123456789"])
check("contact emails", _card_back["email"], ["ada@example.com"])
check("contact unescapes", _card_back["note"], "one;two")

_bt = NDEFMessage.from_bluetooth("AA:BB:CC:DD:EE:FF", "Speaker",
                                 class_of_device=0x240404)
check("bluetooth address is little endian on the wire",
      _bt.records[0].payload[2:8], b"\xff\xee\xdd\xcc\xbb\xaa")
_bt_back = NDEFMessage.from_bytes(_bt.to_bytes()).bluetooth
check("bluetooth address", _bt_back["address"], "aa:bb:cc:dd:ee:ff")
check("bluetooth name", _bt_back["name"], "Speaker")
check("bluetooth class of device", _bt_back["class_of_device"], 0x240404)
_ble = NDEFRecord.bluetooth_le("AA:BB:CC:DD:EE:FF", address_type=1,
                               name="Tag")
check("ble kind", _ble.kind, "bluetooth_le")
check("ble address type", _ble.value["address_type"], "random")
check("ble role", _ble.value["role"], "peripheral")
_hs = NDEFMessage.handover_select(
    [NDEFRecord.bluetooth("AA:BB:CC:DD:EE:FF", "Speaker")])
check("handover select record", _hs.records[0].type, b"Hs")
check("handover carrier is still found",
      NDEFMessage.from_bytes(_hs.to_bytes()).bluetooth["name"], "Speaker")

_hk = NDEFRecord.homekit("518-08-361", category=pn7150.HOMEKIT_LIGHTBULB,
                         setup_id="7OSX")
check("homekit uri", _hk.value, "X-HM://0052VG2ND7OSX")
_hk_back = NDEFMessage.from_bytes(NDEFMessage([_hk]).to_bytes()).homekit
check("homekit setup code", _hk_back["setup_code"], "518-08-361")
check("homekit category", _hk_back["category"], pn7150.HOMEKIT_LIGHTBULB)
check("homekit setup id", _hk_back["setup_id"], "7OSX")
check_raises("homekit refuses a short code",
             lambda: NDEFRecord.homekit("12345"), pn7150.NDEFError)

# Byte-identical to circuitpython-st25dv, which was tapped against a Pixel 10
# and an iPhone 16 Pro; that run only carries over while these hold.
check("wifi bytes match the tested driver",
      NDEFRecord.wifi("Guest Wi-Fi", "correct horse").payload,
      b"\x10\x0e\x001\x10&\x00\x01\x01\x10E\x00\x0bGuest Wi-Fi"
      b"\x10\x03\x00\x02\x00 \x10\x0f\x00\x02\x00\x08"
      b"\x10'\x00\rcorrect horse")
check("bluetooth bytes match the tested driver",
      NDEFRecord.bluetooth("a4:c1:38:01:02:03", "Speaker",
                           class_of_device=0x240404).payload,
      b"\x16\x00\x03\x02\x018\xc1\xa4\x08\tSpeaker\x04\r\x04\x04$")

_tel = NDEFMessage.from_tel("+48123456789")
check("tel uses prefix code 5", _tel.records[0].payload[0], 5)
check("phone number", NDEFMessage.from_bytes(_tel.to_bytes()).phone,
      "+48123456789")
check("sms body is percent encoded", NDEFRecord.sms("+1555", "a b").value,
      "sms:+1555?body=a%20b")
check("first(kind) finds a record",
      NDEFMessage([NDEFRecord.text("x"), _hk]).first("uri"),
      "X-HM://0052VG2ND7OSX")
check("mailto with a subject", NDEFRecord.email("a@b.co", "Hej").value,
      "mailto:a@b.co?subject=Hej")
_mail = NDEFMessage.from_email("ada@example.com", "Hej", "one & two")
_mail_back = NDEFMessage.from_bytes(_mail.to_bytes()).email
check("email address", _mail_back["address"], "ada@example.com")
check("email subject", _mail_back["subject"], "Hej")
check("email body is percent-decoded", _mail_back["body"], "one & two")
check("a plus in an address is not a space",
      NDEFMessage.from_email("ada+tags@e.co").email["address"],
      "ada+tags@e.co")
check("no mailto record, no email",
      NDEFMessage.from_uri("https://a.co").email, None)

print("--- new API ---")
_ext = NDEFRecord.external("example.com:widget", b"\x01\x02")
_back = NDEFMessage.from_bytes(NDEFMessage([_ext]).to_bytes())
check("external kind", _back.records[0].kind, "external")
check("external type", _back.records[0].type, b"example.com:widget")
check("external value", _back.records[0].value, b"\x01\x02")

check("records compare by value",
      NDEFRecord.uri("https://a.co") == NDEFRecord.uri("https://a.co"), True)
check("unequal records differ",
      NDEFRecord.uri("https://a.co") != NDEFRecord.uri("https://b.co"), True)
_multi = NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("x", "sv")])
check("message survives a round trip intact",
      NDEFMessage.from_bytes(_multi.to_bytes()) == _multi, True)
check("message vs non-message", NDEFMessage.from_text("hi") == "hi", False)

class RefusingTag(Type2Tag):
    def __init__(self):
        Tag.__init__(self, FakeNFC(), 0, 1, 2, TECH_NFC_A, b"\x44\x00\x00")
    def transceive(self, data, timeout=0.5):
        raise pn7150.CommandError("refused")

class GoneTag(RefusingTag):
    def transceive(self, data, timeout=0.5):
        raise pn7150.TagLostError("gone")

check("a refusal still proves presence", RefusingTag().is_present(), True)
check("a lost tag is absent", GoneTag().is_present(), False)

class FakeT5(pn7150.Type5Tag):
    CC = {0: b"\xe1\x40\x27\x01"}
    def __init__(self):
        Tag.__init__(self, FakeNFC(), 0, 1, 6, TECH_NFC_V, b"\x00\x00" + bytes(8))
    def read_block(self, block):
        if block not in self.CC:
            raise pn7150.CommandError("no block %d" % block, 0x03)
        return self.CC[block]

class FakeT5Long(FakeT5):
    CC = {0: b"\xe2\x40\x00\x01", 1: b"\x00\x00\x03\x20"}
check_raises("Type 5 refuses to overwrite the CC",
             lambda: FakeT5().write_block(0, b"\x00\x00\x00\x00"), ValueError)
check_raises("Type 5 block is exactly 4 bytes",
             lambda: FakeT5().write_block(1, b"\x00\x00"), ValueError)
# An 8-byte CC (byte 2 == 0) puts a 16-bit MLEN in bytes 6-7 and moves the
# T5T area to block 2. Parsing it as the short form reads half the CC as TLV.
check("short CC size", FakeT5().cc_size, 4)
check("short CC capacity", FakeT5().capacity, 312)
check("short CC first data block", FakeT5().first_data_block, 1)
check("long CC size", FakeT5Long().cc_size, 8)
check("long CC capacity", FakeT5Long().capacity, 0x0320 * 8)
check("long CC first data block", FakeT5Long().first_data_block, 2)
check_raises("long CC protects block 1",
             lambda: FakeT5Long().write_block(1, b"\x00\x00\x00\x00"), ValueError)

print("--- Mifare Classic writing ---")
_sent = []
_mem = {}
class FakeWritableMFC(pn7150.MifareClassicTag):
    def __init__(self, sak=0x08):
        Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_MIFARE, TECH_NFC_A,
                     bytes([0x04, 0x00, 0x04, 1, 2, 3, 4, 0x01, sak]))
        self._pending = None
    def authenticate(self, sector, key=None, key_b=False):
        return True
    def read_block(self, block):
        return _mem.get(block, bytes(16))
    def transceive(self, data, timeout=0.5):
        data = bytes(data)
        _sent.append(data)
        if len(data) == 3 and data[1] == 0xA0:
            self._pending = data[2]
            return b"\x00\x00\x00"
        if len(data) == 17 and data[0] == 0x10:
            _mem[self._pending] = data[1:]
            return b"\x00\x00"
        return b"\x00"

# NXP's reference does the write in two exchanges: the command is acked
# before the 16 data bytes are sent.
_t = FakeWritableMFC()
_t.write_block(4, bytes(range(16)))
check("mfc write phase 1 frame", hexlify(_sent[0]), "10:a0:04")
check("mfc write phase 2 frame", hexlify(_sent[1]),
      "10:" + hexlify(bytes(range(16))))
check("mfc write landed", _mem[4], bytes(range(16)))

check_raises("mfc refuses the manufacturer block",
             lambda: FakeWritableMFC().write_block(0, bytes(16)), ValueError)
check_raises("mfc refuses a sector trailer",
             lambda: FakeWritableMFC().write_block(3, bytes(16)), ValueError)
check_raises("mfc refuses a trailer high up too",
             lambda: FakeWritableMFC().write_block(63, bytes(16)), ValueError)
check("mfc trailer write needs force",
      FakeWritableMFC().write_block(7, bytes(16), True), True)
check_raises("mfc block is exactly 16 bytes",
             lambda: FakeWritableMFC().write_block(4, bytes(4)), ValueError)

check("mfc ndef blocks skip MAD and trailers",
      FakeWritableMFC().ndef_blocks()[:4], [4, 5, 6, 8])
check("mfc 1K ndef capacity", FakeWritableMFC().ndef_capacity, 45 * 16)
check("mfc 4K skips MAD2",
      64 in FakeWritableMFC(0x18).ndef_blocks(), False)

_sent = []
_mem = {}
_msg = NDEFMessage([NDEFRecord.uri("https://example.com"),
                    NDEFRecord.text("hello", "en")])
_t2 = FakeWritableMFC()
_t2.write_ndef(_msg)
check("mfc write_ndef round trips", _t2.read_ndef() == _msg, True)
check_raises("mfc refuses an oversized message",
             lambda: FakeWritableMFC().write_ndef(NDEFMessage(
                 [NDEFRecord.mime("application/x", bytes(45 * 16))])),
             pn7150.NDEFError)

print("--- Type 4 card emulation applet ---")
SEL_APP = b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00"
SEL_APP_V1 = b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x00"
SEL_CC = b"\x00\xa4\x00\x0c\x02\xe1\x03"
SEL_NDEF = b"\x00\xa4\x00\x0c\x02\xe1\x04"
_msg4 = NDEFMessage([NDEFRecord.uri("https://example.com"),
                     NDEFRecord.text("hello", "en")])

def applet(**kw):
    a = Type4NDEFApplet(_msg4, **kw)
    a.process(SEL_APP)
    return a

check("t4 selects the v2.0 aid", Type4NDEFApplet(None).process(SEL_APP),
      b"\x90\x00")
check("t4 selects the v1.0 aid", Type4NDEFApplet(None).process(SEL_APP_V1),
      b"\x90\x00")
check("t4 refuses an unknown aid",
      Type4NDEFApplet(None).process(b"\x00\xa4\x04\x00\x02\xa0\x00\x00"),
      b"\x6a\x82")
check("t4 refuses a file before the app",
      Type4NDEFApplet(None).process(SEL_CC), b"\x69\x86")
check("t4 refuses an unknown file",
      applet().process(b"\x00\xa4\x00\x0c\x02\xe1\x05"), b"\x6a\x82")
check("t4 cc is 15 bytes", len(applet().capability_container), 15)
check("t4 cc says read only", applet().capability_container[14], 0xFF)
check("t4 cc says writable",
      applet(writable=True).capability_container[14], 0x00)
check("t4 cc carries the declared size",
      hexlify(applet(max_size=512).capability_container[11:13]), "02:00")

_a = applet()
_a.process(SEL_CC)
check("t4 reads the cc", _a.process(b"\x00\xb0\x00\x00\x0f"),
      _a.capability_container + b"\x90\x00")
check("t4 read past eof", _a.process(b"\x00\xb0\x00\x0f\x01"), b"\x6b\x00")

_a = applet()
_a.process(SEL_NDEF)
_len4 = len(_msg4.to_bytes())
check("t4 nlen matches the message",
      _a.process(b"\x00\xb0\x00\x00\x02")[:2],
      bytes([(_len4 >> 8) & 0xFF, _len4 & 0xFF]))
check("t4 ndef file round trips",
      NDEFMessage.from_bytes(_a.process(b"\x00\xb0\x00\x02\x00")[:-2]),
      _msg4)
check("t4 update binary needs writable",
      _a.process(b"\x00\xd6\x00\x00\x02\x00\x00"), b"\x69\x86")
check("t4 unknown instruction",
      _a.process(b"\x00\xca\x00\x00\x00"), b"\x6d\x00")
check("t4 foreign class byte",
      _a.process(b"\x80\xb0\x00\x00\x02"), b"\x6e\x00")
check("t4 truncated apdu", _a.process(b"\x00\xa4\x04"), b"\x67\x00")
_a.reset()
check("t4 reset forgets the selection",
      _a.process(b"\x00\xb0\x00\x00\x02"), b"\x69\x86")

_written = []
_w = Type4NDEFApplet(None, writable=True, on_write=_written.append)
_w.process(SEL_APP)
_w.process(SEL_NDEF)
_payload = _msg4.to_bytes()
_w.process(b"\x00\xd6\x00\x00\x02\x00\x00")
_w.process(bytes([0x00, 0xD6, 0x00, 0x02, len(_payload)]) + _payload)
check("t4 publishes nothing before nlen", _written, [])
_w.process(bytes([0x00, 0xD6, 0x00, 0x00, 0x02,
                  len(_payload) >> 8, len(_payload) & 0xFF]))
check("t4 write round trips", _w.message, _msg4)
check("t4 on_write fired once", len(_written), 1)
check_raises("t4 refuses a message the cc cannot hold",
             lambda: Type4NDEFApplet(
                 NDEFMessage([NDEFRecord.mime("application/x", bytes(64))]),
                 max_size=32),
             pn7150.NDEFError)

print()
print("%d passed, %d failed" % (passed, failed))

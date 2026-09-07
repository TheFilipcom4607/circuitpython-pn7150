# On-device unit tests: run every pure-logic path under CircuitPython,
# where CPython-only behaviour (int-in-bytearray, etc.) actually shows up.
import pn7150
from pn7150 import (NDEFMessage, NDEFRecord, Tag, Type2Tag, hexlify,
                    TECH_NFC_A, TECH_NFC_B, TECH_NFC_F, TECH_NFC_V)

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

print()
print("%d passed, %d failed" % (passed, failed))

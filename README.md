# circuitpython-pn7150

A single-file CircuitPython driver for the NXP **PN7150** NFC controller, with
NDEF decoding and encoding built in. Written for the
[iLabs Challenger RP2040 NFC](https://ilabs.se/product/challenger-rp2040-nfc/)
but not tied to it — any board with I2C plus two GPIOs will do.

Reads NTAG/Ultralight, Mifare Classic, DESFire/ISO-DEP, ISO15693 and FeliCa;
decodes and writes NDEF; and reports UIDs for all four RF technologies.

## Install

Copy `pn7150.py` into `CIRCUITPY/lib/`. No other dependencies — it imports only
core modules (`busio`, `digitalio`, `supervisor`, `micropython`, `time`).

```bash
cp pn7150.py /Volumes/CIRCUITPY/lib/
```

Examples are in [`examples/`](examples): `nfc_scanner.py` is a scanner with
NeoPixel feedback, `example_write_tag.py` writes NDEF to an NTAG.

## Why not ElectronicCats_CircuitPython_PN7150

That library works, and this one owes it the NCI bring-up sequence. But it
stops at "a tag was seen":

| | ElectronicCats | this |
|---|---|---|
| UID for NFC-A | yes | yes |
| UID for NFC-B / F / V | `None` | yes |
| Tag type as text | raw ints | `tag.type` |
| NDEF decoding | none | URI, text, MIME, external; multi-record |
| NDEF encoding / writing | none | `tag.write_ndef(...)` |
| Type 2 read/write | raw `tag_cmd` only | `read`/`write`/`read_memory` |
| Type 4 (DESFire) | none | APDUs + full NDEF flow |
| Mifare Classic | none | authenticate + block reads |
| ISO15693 | none | block reads + NDEF |
| FeliCa / Type 3 | none | CHECK, attribute block, NDEF |
| Errors | bare `assert` | `PN7150Error` hierarchy |
| Timeouts | blocks forever | every wait takes `timeout=` |
| Repeat suppression | none | tag reported once until removed |

## API

### `PN7150(scl, sda, irq, ven, i2c=None, address=0x28, frequency=100000, debug=False)`

Pass four pins and it builds its own 100 kHz bus, or pass `i2c=` to share one.
`PN7150.from_board(board)` works on any board defining `NFC_*` pins.

* `connect()` — reset and initialise. Sets `firmware_version`, `build_number`.
* `scan(timeout=None, skip_repeats=True)` — generator yielding `Tag` objects.
* `wait_for_tag(timeout=None)` — one tag, or `None` on timeout.
* `start_discovery(technologies=...)` / `stop_discovery()` / `resume_discovery()`
* `debug = True` — print every NCI frame in both directions.

Narrow the poll loop when you only care about one family:

```python
from pn7150 import TECH_NFC_A
nfc.start_discovery([TECH_NFC_A])
```

### `Tag`

* `uid` / `uid_hex` — works for all four technologies
* `type` — e.g. `"Type 2 (NTAG/Ultralight)"`
* `technology_name`, `sens_res`, `sel_res`, `dsfid`
* `ndef` — an `NDEFMessage` or `None`, read lazily and cached
* `dump()` — everything, multi-line
* `transceive(data)` — raw command to the tag

Subclasses are chosen automatically: `Type2Tag`, `Type4Tag`,
`MifareClassicTag`, `Type5Tag`, `Type3Tag`.

```python
if isinstance(tag, Type2Tag):
    tag.write_ndef(NDEFMessage.from_uri("https://example.com"))
elif isinstance(tag, MifareClassicTag):
    tag.authenticate(1, KEY_NDEF)
    print(tag.read_block(4))
elif isinstance(tag, Type4Tag):
    data, sw = tag.apdu(b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00")
elif isinstance(tag, Type5Tag):
    print(tag.capability_container)
elif isinstance(tag, Type3Tag):
    print(tag.idm, tag.pmm, tag.has_ndef_service())
```

### NDEF

```python
msg = NDEFMessage.from_uri("https://example.com")
msg = NDEFMessage.from_text("hello", "en")
msg = NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("caption")])

msg.uri, msg.text, msg.value      # first matching record
for rec in msg:
    rec.kind      # "uri" | "text" | "mime" | "external" | "unknown"
    rec.value     # str for uri/text, bytes otherwise
    rec.language  # text records only
```

All 36 URI prefix codes are handled, so `tel:+48…` and `https://…` both
round-trip to their short form on the tag.

### Errors

`PN7150Error` is the base. `NotConnectedError`, `CommandError`, `TagLostError`,
`TagTimeoutError`, `NotSupportedError`, `NDEFError`. Reading `tag.ndef` never
raises — it returns `None` if the tag holds no NDEF or the read fails.

## Hardware notes

Frame layouts, measured rather than assumed (they differ per RF interface, and
each ends with a status byte):

| Interface | Raw response | Layout |
|---|---|---|
| Type 2 READ | 17 bytes | 16 data + status |
| Mifare read | 18 bytes | `0x10` prefix + 16 data + status |
| ISO15693 read | 6 bytes | flags + 4 data + status |

Other things worth knowing, all learned the hard way:

* **Run the bus at 100 kHz.** On boards without external pull-ups, 400 kHz
  times out. This is the default here.
* **Never read past the end of tag memory** — the tag stops answering for the
  rest of the session. `read_ndef()` bounds itself by the capability container.
* **A Type 5 tag's block 0 is the CC, not TLV data.** Parsing from block 0
  makes a formatted tag look empty.
* **Deactivating a tag to sleep leaves the controller in `W4_HOST_SELECT`**,
  which is not a polling state. It must then go to idle and re-issue
  `RF_DISCOVER`, or the reader goes permanently blind.
* A DESFire UID beginning `0x08` is a *random* ID (ISO 14443-3), regenerated on
  every activation, so such cards cannot be recognised across taps.
* **Authenticate once per tap.** Mifare Classic refuses a second authentication
  with a different key inside one activation; trying it fails with status
  `0x03` *and* poisons the session, so an NDEF read that already succeeded will
  start failing. Lift the tag and re-present it to change keys.
* NFC-F activation parameters are the odd one out: `<bit rate> <len> <SENSF_RES>`,
  and NCI strips the leading `0x01` response code, so the field is 16 or 18
  bytes of `IDm(8) + PMm(8)`. Treating byte 0 as a length, or expecting the
  response code, yields an IDm that is silently ignored by the card.
* NCI status codes: discovery errors are `0xAx` (`0xA0` =
  DISCOVERY_ALREADY_STARTED), RF interface errors `0xBx`. Confusing the two
  turns a benign "already polling" into a fatal error.
* A FeliCa card without an NDEF service answers CHECK with SF2 `0xA6`. That is
  the normal answer from transit and payment cards, not a fault.

## Verified on hardware

Against a Challenger RP2040 NFC with tags emulated by a Flipper Zero:

| Tag | Result |
|---|---|
| NTAG/Ultralight | `https://thefilip.com` |
| Mifare Classic 1K | `tel:+48...` (auth + NDEF) |
| Mifare Classic (foreign keys) | clean `CommandError`, status `0x03` |
| ISO15693 | `https://3dtag.org/s/...` + a CBOR MIME record |
| DESFire | identified; no NDEF application present |
| FeliCa (transit card) | IDm/PMm read, CHECK answered, NDEF service correctly reported absent |

A final 22-tag run across all four technologies produced no read failures.

The one path not proven against real hardware is reading NDEF *from* a FeliCa
card — no FeliCa carrying NDEF was available, so `Type3Tag.read_ndef()` is
verified only against a synthetic card. Writing NDEF (`Type2Tag.write_ndef`)
is likewise implemented and guarded but untested on a physical tag.

`test_pn7150.py` holds 51 assertions that run **on the board**, since
CPython-only constructs (`0xFE in bytearray`, `[::-1]`) pass a desktop syntax
check and then fail on CircuitPython. Copy it to `code.py` to run them.

## License and credits

MIT, see [LICENSE](LICENSE).

This is an independent implementation, but it would have taken far longer
without prior art:

* [ElectronicCats_CircuitPython_PN7150](https://github.com/ElectronicCats/ElectronicCats_CircuitPython_PN7150)
  (MIT) — the NCI bring-up sequence (`CORE_RESET` / `CORE_INIT` / proprietary
  activation) and the I2C framing follow the approach it established.
* [ElectronicCats-PN7150](https://github.com/ElectronicCats/ElectronicCats-PN7150)
  (Arduino, containing NXP reference code) — consulted to confirm the on-the-wire
  frame layouts for Mifare authentication, Type 4 NDEF APDUs and the FeliCa
  CHECK command. No code was copied; those layouts are defined by the NFC Forum
  and JIS X 6319-4 specifications, and every frame here was verified against
  real tags.

Where this driver and NXP's reference disagree, the disagreement is
deliberate and noted in the source — for example the reference computes the
Type 3 NDEF length as `(b[24] << 16) + (b[25] << 16) + b[26]`, shifting the
middle byte by 16 instead of 8, which corrupts any message over 255 bytes.

# circuitpython-pn7150

[![tests](https://github.com/TheFilipcom4607/circuitpython-pn7150/actions/workflows/ci.yml/badge.svg)](https://github.com/TheFilipcom4607/circuitpython-pn7150/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/TheFilipcom4607/circuitpython-pn7150?sort=semver)](https://github.com/TheFilipcom4607/circuitpython-pn7150/releases/latest)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A single-file CircuitPython driver for the NXP **PN7150** NFC controller, with
NDEF decoding and encoding built in. Written for the
[iLabs Challenger RP2040 NFC](https://ilabs.se/product/challenger-rp2040-nfc/)
but not tied to it — any board with I2C plus two GPIOs will do.

Reads NTAG/Ultralight, Mifare Classic, DESFire/ISO-DEP, ISO15693 and FeliCa;
decodes and writes NDEF; and reports UIDs for all four RF technologies. NDEF
here is more than URLs: Wi-Fi credentials, contacts, phone numbers, Bluetooth
pairing and HomeKit setup are built and parsed too, in the encodings phones
act on. It also goes the other way — `nfc.emulate_ndef("https://…")` makes the
board itself look like a Type 4 tag, so tapping a phone on it opens a URL.

```python
import board
from pn7150 import PN7150

nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
with nfc:
    for tag in nfc.scan():
        print(tag.type, tag.uid_hex)
        if tag.ndef:
            print("  ->", tag.ndef.value)
```

```
Type 2 (NTAG/Ultralight) 04:8c:e8:12:34:56:80
  -> https://thefilip.com
```

**Contents:** [Install](#install) · [Examples](#examples) ·
[Wiring](#wiring) ·
[Why not ElectronicCats](#why-not-electroniccats_circuitpython_pn7150) ·
[API](#api) · [NDEF](#ndef) ·
[Wi-Fi, contacts and the rest](#wi-fi-contacts-and-the-rest) ·
[Card emulation](#card-emulation) ·
[Hardware notes](#hardware-notes) · [Troubleshooting](#troubleshooting) ·
[Known limitations](#known-limitations) ·
[Verified on hardware](#verified-on-hardware) ·
[Tests and tooling](#tests-and-tooling) ·
[Releasing](#releasing) · [License and credits](#license-and-credits)

## Install

This library is in the
[CircuitPython Community Bundle](https://github.com/adafruit/CircuitPython_Community_Bundle),
which [circup](https://github.com/adafruit/circup) reads by default, so
installing it is one command with nothing to add first:

```bash
circup install pn7150
```

Or by hand — every release attaches a bare
[`pn7150.mpy`](https://github.com/TheFilipcom4607/circuitpython-pn7150/releases/latest).
Download it and drop it in `lib/`:

```bash
cp pn7150.mpy /Volumes/CIRCUITPY/lib/
```

That file is built for CircuitPython 9.x and 10.x alike, which currently emit
the same `.mpy` format. The release also carries the per-version bundle zips
`circuitpython-pn7150-9.x-mpy-<version>.zip` and `-10.x-`, which is what
`circup` pulls; take one of those if a future CircuitPython splits the formats
and the bare file stops matching your board.

Copying `pn7150.py` from this repo instead works and is the easiest thing to
edit in place, but prefer the `.mpy` on a RAM-tight board: the source is 141 kB
that CircuitPython has to compile into RAM at import, where `pn7150.mpy` is
38 kB and loads with no compile step at all. On an RP2040 that difference
decides whether the driver and a large `code.py` fit together.

Either way there are no dependencies — it imports only core modules (`busio`,
`digitalio`, `supervisor`, `micropython`, `time`). Compiled builds are published
for CircuitPython 9.x and 10.x; the source runs on either.

`circup bundle-add TheFilipcom4607/circuitpython-pn7150` still works and points
`circup` straight at this repo's releases, which is how to get a version before
it reaches the bundle.

### Examples

Copy any of these to `CIRCUITPY/code.py`:

| Example | What it does |
|---|---|
| [`nfc_scanner.py`](examples/nfc_scanner.py) | scans, prints and decodes every tag, with NeoPixel feedback |
| [`example_write_tag.py`](examples/example_write_tag.py) | writes an NDEF message to an NTAG |
| [`write_wifi_tag.py`](examples/write_wifi_tag.py) | writes a tag that joins a Wi-Fi network on tap |
| [`badge_reader.py`](examples/badge_reader.py) | matches a UID, then waits for the badge to be lifted |
| [`emulate_ndef.py`](examples/emulate_ndef.py) | *is* a Type 4 tag — tap a phone, a URL comes up |
| [`reader_and_card.py`](examples/reader_and_card.py) | reads tags and answers phones in one loop |

### Wiring

On the Challenger RP2040 NFC everything is already routed, so
`PN7150.from_board(board)` is enough. On any other board:

| PN7150 | Connect to | Notes |
|---|---|---|
| VDD | 3.3 V | not 5 V |
| GND | GND | |
| SCL | any I2C SCL pin | 4.7 kΩ pull-up to 3.3 V if the board has none |
| SDA | any I2C SDA pin | same |
| IRQ | any GPIO | the PN7150 drives this high when a frame is waiting |
| VEN | any GPIO | active high; the driver pulses it to reset the chip |

```python
nfc = PN7150(board.GP5, board.GP4, irq=board.GP7, ven=board.GP6)
```

The `DWL_REQ` pin selects firmware-download mode. Leave it low or unconnected.

## Why not ElectronicCats_CircuitPython_PN7150

That library works, and this one owes it the NCI bring-up sequence. But it
stops at "a tag was seen":

| | ElectronicCats | this |
|---|---|---|
| UID for NFC-A | yes | yes |
| UID for NFC-B / F / V | `None` | yes |
| Tag type as text | raw ints | `tag.type` |
| NDEF decoding | none | URI, text, MIME, external; multi-record |
| Wi-Fi / contact / Bluetooth / HomeKit records | none | built and parsed |
| NDEF encoding / writing | none | `tag.write_ndef(...)` |
| Type 2 read/write | raw `tag_cmd` only | `read`/`write`/`read_memory` |
| Type 4 (DESFire) | none | APDUs + full NDEF flow |
| Mifare Classic | none | authenticate, block read *and* write, NDEF |
| ISO15693 | none | block reads + NDEF |
| FeliCa / Type 3 | none | CHECK, attribute block, NDEF |
| Card emulation | none | Type 4 tag: `nfc.emulate_ndef("https://…")` |
| Type 4 / Type 5 NDEF writing | none | `write_ndef()` (unverified, see below) |
| Presence / removal | none | `is_present()`, `wait_for_removal()` |
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
* `protocol_preference` — which protocol wins when one card offers several;
  `candidates` lists what the last multi-protocol discovery saw
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
* `dump()` — everything, multi-line (touches `ndef`, so it blocks; `repr()` does not)
* `transceive(data)` — raw command to the tag
* `is_present()` — cheap poll: is the tag still on the antenna?
* `wait_for_removal(timeout=None)` — block until it is lifted

`is_present()` counts a refusal as present: a card that answers "access denied"
is still a card in the field. Call it *before* finishing with the tag —
`scan()` puts each tag to sleep on the way round the loop, and a sleeping tag
reports absent. Pass `skip_repeats=False` when you mean to hold one there.

Subclasses are chosen automatically: `Type2Tag`, `Type4Tag`,
`MifareClassicTag`, `Type5Tag`, `Type3Tag`.

Writes are bounded by whatever capacity the tag declares in its capability
container, so a message that does not fit raises `NDEFError` instead of running
off the end of user memory into the lock bytes and config pages:

```python
if isinstance(tag, Type2Tag):
    tag.write_ndef(NDEFMessage.from_uri("https://example.com"))
    tag.write(8, b"\x00\x00\x00\x00")   # ValueError past the last data page
elif isinstance(tag, MifareClassicTag):
    tag.authenticate(1, KEY_NDEF)
    print(tag.read_block(4))
    tag.write_block(4, bytes(16))        # sector trailers refused
elif isinstance(tag, Type4Tag):
    data, sw = tag.apdu(b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00")
elif isinstance(tag, Type5Tag):
    print(tag.capability_container, tag.capacity)
elif isinstance(tag, Type3Tag):
    print(tag.idm, tag.pmm, tag.has_ndef_service())
```

### NDEF

```python
msg = NDEFMessage.from_uri("https://example.com")
msg = NDEFMessage.from_text("hello", "en")
msg = NDEFMessage([NDEFRecord.uri("https://a.co"), NDEFRecord.text("caption")])
msg = NDEFMessage([NDEFRecord.mime("application/cbor", data),
                   NDEFRecord.external("example.com:widget", b"\x01")])

msg.uri, msg.text, msg.value      # first matching record
for rec in msg:
    rec.kind      # "uri" | "text" | "wifi" | "contact" | "bluetooth"
                  # | "bluetooth_le" | "handover" | "mime" | "external"
                  # | "unknown"
    rec.value     # str for uri/text, dict for wifi/contact/bluetooth,
                  # bytes otherwise
    rec.language  # text records only
```

Records and messages compare by value, so a round trip can be asserted
directly: `NDEFMessage.from_bytes(msg.to_bytes()) == msg`.

All 36 URI prefix codes are handled, so `tel:+48…` and `https://…` both
round-trip to their short form on the tag.

### Wi-Fi, contacts and the rest

A phone acts on the record *type*, not on the text inside it. A `text/vcard`
record offers to add a contact, `application/vnd.wfa.wsc` offers to join a
network, a `tel:` URI opens the dialler, an `X-HM://` URI starts HomeKit
pairing. Each of those is one call, and each goes on a tag or out of the
emulator exactly like a URL does:

```python
tag.write_ndef(NDEFMessage.from_wifi("HomeNet", "correcthorsebatterystaple"))
nfc.emulate_ndef(NDEFMessage.from_contact("Ada Lovelace",
                                          phone="+48123456789",
                                          email="ada@example.com"))
```

| Built with | Record on the tag | Tapping a phone offers |
|---|---|---|
| `from_wifi(ssid, password)` | `application/vnd.wfa.wsc` | join the network |
| `from_contact(name, phone=…, email=…)` | `text/vcard` | add the contact |
| `from_tel(number)` | `tel:` URI | dial it |
| `from_sms(number, message)` | `sms:` URI | send the message |
| `from_email(address, subject, body)` | `mailto:` URI | write the mail |
| `from_bluetooth(address, name)` | `…bluetooth.ep.oob` | pair the device |
| `from_bluetooth_le(address, name=…)` | `…bluetooth.le.oob` | nothing, on the phones tried |
| `from_homekit(code, category=…, setup_id=…)` | `X-HM://` URI | carry an accessory's setup code |

What a phone does with a record is the platform's decision, not this driver's,
and it varies — see
[what a phone does with a credential record](#what-a-phone-does-with-a-credential-record)
for a Pixel 10 and an iPhone 16 Pro, record by record. Two to know up front:
**Wi-Fi and contact records are an Android feature**, ignored by iOS, and
**HomeKit does not make the board an accessory** — `from_homekit()` carries
the setup code printed under an accessory's QR code, and iOS pairs with a
device that answers back, which a tag is not.

Every one of them parses back, so a tag written by a phone reads here too.
The decoded values are plain dicts, with `None` for anything the tag left out:

```python
tag.ndef.wifi       # {"ssid": "HomeNet", "password": "…", "security": "wpa2",
                    #  "authentication": 32, "encryption": 8, "mac": None}
tag.ndef.contact    # {"name": "Ada Lovelace", "phone": [...], "email": [...],
                    #  "organization": …, "title": …, "url": …, "address": …,
                    #  "note": …, "text": "BEGIN:VCARD…"}
tag.ndef.bluetooth  # {"address": "a4:c1:38:01:02:03", "name": "Speaker",
                    #  "class_of_device": 0x240404, "low_energy": False,
                    #  "address_type": None, "role": None}
tag.ndef.homekit    # {"setup_code": "518-08-361", "category": 5, "flags": 2,
                    #  "setup_id": "7OSX", "version": 0, "uri": "X-HM://…"}
tag.ndef.email      # {"address": "ada@example.com", "subject": "Hello",
                    #  "body": "Sent by a tag"}
tag.ndef.phone      # "+48123456789"
```

`message.first(kind)` is the general form; `.uri`, `.text`, `.wifi`,
`.contact`, `.bluetooth`, `.bluetooth_le`, `.phone`, `.email` and `.homekit`
are shortcuts for the common ones.

Decoding never raises on a malformed payload — a truncated credential comes
back as a dict of `None`s, so a scanner loop cannot be killed by a bad tag.
Building one does raise `NDEFError` on input no reader would accept: a WPA
passphrase under 8 characters, a secured network with no password, an open one
*with* a password, an SSID over 32 bytes, an address that is not six hex
bytes, a contact with no name, a HomeKit code that is not 8 digits.

Wi-Fi defaults to WPA2 Personal with AES when a password is given and to an
open network when it is not; pass `authentication=` and `encryption=` (the
`WIFI_*` and `WIFI_ENC_*` constants) for anything else, and `mac=` to pin the
credential to one access point. HomeKit takes the setup code with or without
dashes, or a whole `X-HM://` URI to pass through, plus the `HOMEKIT_*`
category constants.

The names here match
[circuitpython-st25dv](https://github.com/TheFilipcom4607/circuitpython-st25dv)
deliberately, constants, decoded keys and all, so record code moves between
the two drivers unchanged.

Bluetooth records go on the tag bare, which is what a Pixel 10 paired from.
Readers that want the NFC Forum framing instead take a handover message:

```python
speaker = NDEFRecord.bluetooth("AA:BB:CC:DD:EE:FF", "Speaker")
tag.write_ndef(NDEFMessage.handover_select([speaker]))
```

That builds the `Hs` record listing each carrier by record id, followed by the
carrier records themselves. `msg.bluetooth` finds the device either way.

All of it together adds about 9 kB to the compiled `.mpy`, in two sections of
`pn7150.py` under the `Wi-Fi, contacts, radios` banners plus the constructors
on `NDEFRecord` and `NDEFMessage`.

### Card emulation

The board can *be* the tag. The PN7150 runs the whole ISO-DEP stack in
firmware — it answers SENS_REQ, SDD, SEL, RATS, ATS and PPS itself and hands
the host bare APDUs — so presenting a Type 4 NDEF tag to a phone is one call:

```python
nfc.emulate_ndef("https://example.com")        # blocks; tap a phone
```

Tap an Android phone or an iPhone (XS and later, background tag reading) and
the URL comes up as a notification banner. `message` takes an `NDEFMessage` or
a string, coerced exactly as `write_ndef()` coerces one.

```python
applet = nfc.emulate_ndef(NDEFMessage.from_text("hello"),
                          timeout=30,          # give up after 30s of quiet
                          writable=True,       # let the phone write back
                          on_read=lambda m: print("read", m.value),
                          on_write=lambda m: print("wrote", m.value))
print(applet.message)                          # whatever it now holds
```

Two lower layers are public, so you are not stuck with NDEF:

* `CardEmulator(nfc, nfcid1=None, sel_info=SEL_INFO_ISO_DEP, hist_bytes=b"",
  also_poll=False, on_tag=None)` — a raw APDU session.
  `start()` / `stop()`, `wait_for_reader(timeout)`, `next_apdu(timeout)`,
  `respond(r_apdu)`, `run(handler, timeout)`, and the `field_present` /
  `reader_active` properties. `next_apdu()` returns `None` when the reader
  leaves; `last_event` says whether that was a deactivation or a timeout.
* `Type4NDEFApplet(message, max_size=1024, writable=False, on_read=None,
  on_write=None)` — `process(c_apdu) -> r_apdu`, a pure function of bytes with
  no I/O at all, so the whole Type 4 state machine is testable on the desktop.

`also_poll=True` keeps the reader/writer poll loop running alongside listen
mode, so one loop both reads tags and answers phones:

```python
emulator = CardEmulator(nfc, also_poll=True, on_tag=lambda tag: print(tag))
emulator.start()
emulator.run(Type4NDEFApplet("https://example.com"))
```

`nfcid1=` sets the UID the emulated card shows (4, 7 or 10 bytes; a leading
`0x08` is the NFC Forum's "this UID is random" prefix). Left out, the
controller's own default is used.

See [`examples/emulate_ndef.py`](examples/emulate_ndef.py) and
[`examples/reader_and_card.py`](examples/reader_and_card.py).

### Errors

`PN7150Error` is the base. `NotConnectedError`, `CommandError`, `TagLostError`,
`TagTimeoutError`, `NotSupportedError`, `NDEFError`. Reading `tag.ndef` never
raises — it returns `None` if the tag holds no NDEF or the read fails.

`CommandError.status` carries the NCI status byte when there was one, so a
caller can tell a transient RF glitch (`TRANSIENT_STATUSES`, retried
automatically on reads) from a refusal like `0x03`.

The predicates answer rather than raise: `has_ndef_service()` and
`select_ndef_application()` return `False` for a card that stays silent.

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
* **`0xFE` terminates a TLV area only between TLVs.** Inside a binary payload
  it is ordinary data, so a read that stops at the first `0xFE` truncates any
  message containing one. The declared TLV length is the only safe bound.
* **Never write past the capacity the CC declares.** On an NTAG the next pages
  are the dynamic lock bytes, AUTH0 and the password — a stray write there can
  lock a tag read-only for good. `write()` refuses them unless `force=True`.
* Mifare Classic 4K is not 1K with more blocks: sectors 0–31 hold 4 blocks,
  32–39 hold 16, and block 64 is MAD2 rather than data.
* **A card that offers two protocols is not activated automatically.** When one
  target matches several protocols — `SAK 0x28` advertises both ISO-DEP and
  Mifare Classic, which is what MIFARE Plus SL1 and the UID-changeable "magic"
  clones report — the NFCC sends one `RF_DISCOVER_NTF` per candidate and waits
  in `W4_HOST_SELECT` for an `RF_DISCOVER_SELECT`. Ignoring those notifications
  hangs the read *and* leaves the controller in a non-polling state, so every
  later tag is invisible too. `protocol_preference` decides which one is taken.
* **`CORE_INTERFACE_ERROR_NTF` (`60 08`) is the answer, not noise.** Cards that
  ignore an APDU make the NFCC report `RF_TIMEOUT_ERROR` immediately; treating
  that as an uninteresting notification means waiting out the caller's whole
  timeout and then reporting something vaguer than what the chip already said.
  Payload is `<status> <conn id>`; `60 07` carries `<status>` alone.
* **A Type 5 CC is 4 bytes or 8.** Once the T5T area passes 2040 bytes, MLEN no
  longer fits in one byte: byte 2 is zeroed, a 16-bit MLEN moves to bytes 6–7,
  and the NDEF area therefore starts at block 2 rather than block 1. Assuming
  the short form reads half the CC as TLV data and writes over the CC itself.
* **Transient RF errors are normal.** `RF_FRAME_CORRUPTED` mid-read is what a
  tag held at the edge of the field produces; abandoning the read on the first
  one loses the whole message. Reads retry (`READ_ATTEMPTS`) on the four
  transient statuses, while a flat refusal (`0x03`) still fails at once.
* Not every tag answers `READ` of page 3 with four pages — one here returns a
  single byte — so a capability container must never be indexed unchecked.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `TagTimeoutError` from `connect()` | Bus too fast, or no I2C pull-ups. The driver defaults to 100 kHz; check the wiring table above. |
| `connect()` works, no tag is ever seen | IRQ and VEN swapped, or VEN wired to a pin that idles high. |
| Reader goes blind after the first tag | Something called `stop_discovery()` without `start_discovery()`. `resume_discovery()` handles the `W4_HOST_SELECT` dance for you. |
| `CommandError ... status 0x03` on Mifare | Wrong key, or a *second* authentication in one tap. Lift the tag and re-present it. |
| The same tag is reported over and over | `skip_repeats=False`. That is the deliberate setting for `badge_reader.py`. |
| `tag.ndef` is `None` on a tag you know holds data | Turn on `debug=True` and look at the frames; for Mifare, the data may live under a key other than `KEY_NDEF`. |
| A phone never notices the emulated tag | `LA_SEL_INFO` did not take, so the SAK does not advertise ISO-DEP and the phone never sends RATS. `debug=True`: the bring-up must contain `20 02 04 01 32 01 20`. |
| The emulated tag works for one tap, then nothing | Something sent `RF_DEACTIVATE(Sleep)` in a listen state, which the PN7150 refuses (UM10936 §9.1). Recovery is idle then `RF_DISCOVER`; `CardEmulator` does that itself. |
| A phone sees the tag but reads nothing | The applet answered `6A82`/`6986`. `Type4NDEFApplet.process()` runs on the desktop — replay the C-APDUs from `debug=True` against it. |
| With `also_poll=True`, phones stop being noticed | A tag is sitting in the field. Polling wins every round while it is there, so listen mode never gets a turn and the phone sees a permanent reader field — an iPhone offers Apple Pay instead of showing a banner. Move the tag away; vicinity (ISO15693) cards reach much further than you would expect. |

## Known limitations

* **No tag formatting.** `MifareClassicTag.write_ndef()` fills in a card that
  is *already* NDEF-formatted; it will not create the MAD or set the NDEF key,
  because that means writing sector trailers and a trailer with the wrong
  access bits locks its sector permanently. Sector trailers are refused unless
  you pass `force=True`.
* **No NCI segmentation on the reader path.** `Tag.transceive()` carries at
  most 255 bytes in one packet and raises `ValueError` past that. The card
  emulation path *does* segment and reassemble, because the controller
  segments whatever it likes there (UM10936 §2.3.4).
* Pages 0–3 of a Type 2 tag are never written, so a factory-blank tag with no
  capability container is not made NDEF-ready.
* **No Mifare MAD parsing.** `read_ndef()` walks the sectors under the NFC
  Forum key rather than consulting the application directory.
* **Card emulation is NFC-A and Type 4 only.** One reader at a time, no
  FeliCa/Type 3 emulation, and no peer-to-peer. NFC-B listen would mean the
  whole `LB_*` configuration block for nothing: iPhone Core NFC and Android
  both poll ISO 14443 type A to read a tag, and UM10936 Table 8 records
  `LB_H_INFO_RESP` as unsupported anyway.
* **An emulated tag is not persistent.** It exists while `emulate_ndef()` or
  `CardEmulator.run()` is running; there is no offline card mode.
* **`also_poll=True` gives the reader priority.** A tag left in the field is
  re-read every round and card emulation never gets a turn, so a phone tapped
  at the same time is ignored. Measured: one ISO15693 card in range produced
  318 consecutive reads and not one served APDU. Nothing in the console says
  this is what is happening.
* **`wait_for_tag()` busy-waits on the IRQ pin**, so it does not cooperate with
  `asyncio`. Poll with a short `timeout=` if you need to share the CPU.

## Verified on hardware

A Challenger RP2040 NFC against 20 tags spanning all four RF technologies,
some real and some emulated by a Flipper Zero, with every NCI frame logged:

| Tag | Result |
|---|---|
| NTAG213 (144 B) | `https://thefilip.com`; CC, capacity and page bounds correct |
| NTAG215 (496 B) | text record `"Lorem ipsum"` |
| Mifare Classic 1K | `KEY_NDEF` auth + NDEF read |
| Mifare Classic ×4 | clean `CommandError` `0x03` under a key the card does not use |
| Mifare Classic (`SAK 0x28`) | multi-protocol; selected and activated as Mifare |
| ISO15693 (312 B) | `https://3dtag.org/…` + a CBOR MIME record, 303 bytes, 2 records |
| ISO15693 (unformatted) | no magic number, reported as capacity 0, no NDEF |
| ISO-DEP ×6 | no NDEF application, reported cleanly and immediately |
| DESFire (random UID) | identified, `0x08` prefix flagged as regenerated per tap |
| FeliCa (transit) | IDm/PMm read, NDEF service correctly reported absent |

`is_present()` and `wait_for_removal()` were exercised on every one of them.

Writing was then verified end to end against an NTAG215 and a MIFARE Classic
1K, each time by saving the tag's existing message, writing, reading back,
comparing, and restoring the original:

| Write path | Result |
|---|---|
| `Type2Tag.write_ndef()` | single and multi-record round trips; both guards fire |
| `MifareClassicTag.write_block()` | two-phase write, read back, restored |
| `MifareClassicTag.write_ndef()` | round trip and restore under `KEY_NDEF` |

Five bugs were found by that run and are fixed, each with a regression test
built from the captured frames: multi-protocol targets hanging the reader, a
single corrupted frame destroying a 303-byte message, `has_ndef_service()` and
`select_ndef_application()` raising instead of answering, and the controller's
own error notifications being ignored.

Card emulation was then taken to a phone, on CircuitPython 10.3.0 with the
`.mpy` installed — an iPhone reading, a Flipper Zero standing in for an NTAG,
and a DESFire hotel key for the ISO-DEP probe:

| Path | Result |
|---|---|
| `emulate_ndef()`, first tap | the iPhone showed the `https://thefilip.com` banner, and all 7 APDUs were answered; nothing returned `6A82` or `6986` |
| A second tap, no power cycle | the full exchange again — the deactivate-to-idle-then-`RF_DISCOVER` recovery holds |
| `also_poll=True` | `24 APDUs served, 89 tags read` in one loop, phone and tag alternating, no errors |
| `writable=True`, read half | `on_read` fired; the CC advertises write access `00`, as against `FF` when read-only |
| `writable=True`, write half | **unverified** — see below |
| The on-device suite | `35/16/28/18/13/22 passed, 0 failed` — all 132, including the 22 emulation assertions |

### Not proven on hardware

Implemented and guarded, but no suitable tag was available. Treat these as the
parts most likely to still have a bug:

| Path | Why untested |
|---|---|
| A phone *writing* to the emulated tag | iOS's NFC Tools never gets as far as `UPDATE BINARY`; needs an Android device |
| `Type4Tag.write_ndef()`, `update_binary()` | no writable Type 4 tag |
| `Type5Tag.write_block()`, `write_ndef()` | no writable ISO15693 tag |
| 8-byte Type 5 capability container | no tag over 2040 bytes; unit-tested only |
| Mifare Classic 4K geometry | no 4K card; the sector maths is unit-tested |
| `Type3Tag.read_ndef()` | no FeliCa carrying NDEF; synthetic card only |
| Wi-Fi, contact, Bluetooth and HomeKit records | no phone has been tapped on one *from this driver* — but see below, where the bytes have been |

### What a phone does with a credential record

The record builders emit bytes identical to
[circuitpython-st25dv](https://github.com/TheFilipcom4607/circuitpython-st25dv),
a sibling driver by the same author, whose records were tapped against a
Pixel 10 and an iPhone 16 Pro. `tests/test_records.py` pins that equality
against literals taken from it, so the run below stops carrying over the
moment a payload here drifts. What has *not* been checked from this driver is
the RF path: these records reaching a phone through the PN7150, whether off a
tag it wrote or out of `emulate_ndef()`.

| Record | Pixel 10 | iPhone 16 Pro |
|---|---|---|
| URL | opens it | opens it |
| `tel:` | dialler, prefilled | inconclusive |
| `sms:` | composer, body and punctuation intact | inconclusive |
| `mailto:` | composer, subject and body intact | inconclusive |
| Contact vCard | saves it, every field | ignored; Apple does not take vCard from a tag |
| Wi-Fi | offers to join, names the network | ignored; Wi-Fi over NFC is Android only |
| Bluetooth | offers to pair, names the device | inconclusive |
| Bluetooth LE | nothing, though the bytes are well formed | inconclusive |
| HomeKit `X-HM://` | not applicable | untested |

Bluetooth LE is a real negative rather than an artefact: fresh content, on a
phone that had just handled classic Bluetooth correctly.

**Both phones deduplicate.** Re-presenting content a phone has already read is
the fastest way to get a false negative — on the iPhone it eventually
suppressed even a plain URL, which is why several rows read inconclusive
rather than failed. Use unique content for every single tap.

Card emulation has now met a phone; the results are in the table above. What
it was checked against first, in
[`tests/test_emulation.py`](tests/test_emulation.py), is a fake NFCC on the I2C
stub: `connect()`, the listen bring-up, activation, a whole tap's worth of
APDUs with the responses segmented and credit-gated, deactivation, and a second
tap afterwards — all through the driver's real transport. The reader half of
this driver plays the phone, so the C-APDUs are not invented. That simulation
predicted the real trace closely: a real iPhone differs only in reading `NLEN`
twice and in sometimes probing with a short tap before committing to a full
read. The one item left on the hardware list is a phone *writing* to the tag.

### A confirmed bug in the Type 4 *reader*

Found while reading the two sides against each other, and since measured on
hardware. Nothing has been changed yet. [`Type4Tag.apdu()`](pn7150.py) runs its
response through `_split_status()`, which strips a trailing NCI status byte.
That byte is real for the Frame and TAG-CMD interfaces — the measured table
above covers Type 2, MIFARE and ISO15693, all of which use those — but NCI puts
the bare APDU on the **ISO-DEP** interface, and both AOSP `rw_t4t.c` and
`ce_t4t.c` read SW1/SW2 as the last two payload bytes with nothing stripped.
With the extra strip, a card answering `90 00` is one byte short of an APDU and
`select_ndef_application()` returns `False` — which is exactly the hardware
result recorded above: *"ISO-DEP ×6 | no NDEF application"*.

A DESFire hotel key settled it. An APDU with a deliberately invalid class byte,
sent over the ISO-DEP interface, came back as a **2-byte** payload:

```
activated: Type 4 (ISO-DEP/DESFire)  NFC-A  UID 4f:36:49:cf
raw NCI data payload: 2 bytes: 6d:00
select_ndef_application(): False
```

Two bytes is the status word with nothing after it, so ISO-DEP appends no status
byte and the strip eats SW2. (The card answered `6D00`, *instruction* not
supported, rather than the `6E00` the probe assumed; either way a status word.)

The fix is not in this pass: it is a reader bug, it touches nothing in card
emulation, and `test_iso_dep_response_without_a_status_byte` currently pins the
wrong behaviour, so that test has to change with it.

## Tests and tooling

`test_pn7150.py` holds 173 assertions and is written to run **on the board** —
copy it to `code.py`. That matters because CPython-only constructs
(`0xFE in bytearray`, `[::-1]`) pass a desktop syntax check and then fail on
CircuitPython.

The same file also runs on the desktop. `tests/stubs/` supplies just enough of
`busio`, `digitalio`, `supervisor` and `micropython` for the pure-logic paths,
`tests/test_device_suite.py` executes the on-device suite under them,
`tests/test_regressions.py` pins the bugs that have been fixed so far,
`tests/test_records.py` pins the Wi-Fi, contact, Bluetooth and HomeKit byte
layouts against the encodings phones expect and against the sibling driver
that was tapped on a phone, and `tests/test_emulation.py` runs
the card-emulation half — the applet against this driver's own Type 4 reader,
and whole taps over a simulated NFCC. CI runs all of them on every push:

```bash
pip install -e ".[dev]" && pytest
```

A green desktop run is necessary, not sufficient — the on-device run is still
the one that counts. `CommandError.__init__` calling `PN7150Error.__init__`
shipped once and passed every desktop test: CircuitPython's native exception
types expose no Python-level `__init__`, so only the board caught it.

### Building the `.mpy`

On a RAM-tight board the driver's source plus a large script may not fit —
CircuitPython compiles source into RAM at import, and on an RP2040 the two
together overflow it. Installing the `.mpy` is the real fix for the driver
half: it is already compiled, so importing it costs no compiler RAM at all.

Build that `.mpy` with **CircuitPython's** `mpy-cross`, not the `mpy-cross` on
PyPI — that one is MicroPython's, and the two formats diverged: CircuitPython
writes magic `43` (`C`) where MicroPython writes `4D` (`M`), and the board
rejects the wrong one at import with `ValueError: MicroPython .mpy file; use
CircuitPython mpy-cross`. It is a one-byte difference in an otherwise identical
file, so it is easy to ship by accident. Adafruit publishes no prebuilt
mpy-cross for CircuitPython 10.x on macOS; build it from the tag matching the
firmware on the board:

```bash
git clone --depth 1 --branch 10.3.0 https://github.com/adafruit/circuitpython
pip install huffman                       # a build dependency of mpy-cross
make -C circuitpython/mpy-cross
circuitpython/mpy-cross/build/mpy-cross -o pn7150.mpy -s pn7150.py pn7150.py
```

The release workflow does this correctly on its own; this only matters when
building by hand between releases.

### Running the suite on the board

That leaves the test suite, which is still source. `split_tests.py` packs it
into parts that each fit, since the whole thing no longer does:

```bash
python tools/split_tests.py test_pn7150.py build/    # suite -> 7 runnable parts
```

`tools/run_on_board.py` then drives those parts from the host: it copies a
script to `code.py`, reloads the board and captures the console, so the output
lands in your terminal rather than in a serial monitor you have to watch.

```bash
pip install pyserial
python tools/run_on_board.py --list                  # drive, port, lib/ contents
for f in build/*.py; do python tools/run_on_board.py "$f" --timeout 90; done
```

It exits non-zero if the sentinel never arrives or if `FAIL`/`Traceback`
appears, so it can be run unattended.

The 132 assertions that existed then pass on a Challenger RP2040 NFC that way,
the six parts of that run reporting `35`, `16`, `28`, `18`, `13` and `22`
passed with none failed — the last of those being the card-emulation set. The
41 Wi-Fi, contact, Bluetooth, HomeKit and mailto assertions added since are
their own part and have not been through a board run yet.

`tools/minify.py` predates the `.mpy` build and is now near-redundant for the
driver — it is an `ast.unparse` round trip dropping docstrings and comments,
and the stripped module passes the identical test suite, but mpy-cross discards
docstrings too, so minifying first saves only ~310 bytes of the 38 kB `.mpy`.
It is still worth a run if you are shipping `pn7150.py` as source:

```bash
python tools/minify.py pn7150.py build/pn7150.py     # ~40% smaller
```

## Releasing

`.github/workflows/release_gh.yml` builds the bundle zips and attaches them to
a published GitHub release, using Adafruit's `circuitpython-build-tools`. The
tag is the only source of truth for the version: `__version__` in `pn7150.py`
and `version` in `pyproject.toml` both read `0.0.0+auto.0` in a checkout, and
the build rewrites that literal to the tag.

To cut a release, push a plain semver tag (no `v` prefix — `circup` parses it
as a version), then publish a GitHub release for that tag. The tag alone does
nothing; the workflow fires on the release being *published*:

```bash
git tag 1.5.0 && git push origin 1.5.0
```

The workflow then attaches six assets:

```
pn7150.mpy                                  the module on its own, to drop in lib/
circuitpython-pn7150-py-1.5.0.zip           source, lib/pn7150.py
circuitpython-pn7150-9.x-mpy-1.5.0.zip      compiled for CircuitPython 9.x
circuitpython-pn7150-10.x-mpy-1.5.0.zip     compiled for CircuitPython 10.x
circuitpython-pn7150-examples-1.5.0.zip     examples/
circuitpython-pn7150-1.5.0.json             bundle metadata for circup
```

The bare `pn7150.mpy` is this repo's own addition, for people installing by
hand; the zips and the json come from Adafruit's build tools. Their names are
what `circup bundle-add TheFilipcom4607/circuitpython-pn7150` expects, and they
are derived from the repository name — renaming the repo breaks that path until
the next release.

Those build tools also stamp each release with a
`z-build_tools_version-<version>.ignore` marker naming the toolchain that cut
it. Nothing downstream reads it — the Community Bundle builds from the tagged
source, `circup` wants the zips and the json — so a last step in the workflow
deletes it and the release page stays clean. The earlier releases have had
theirs removed by hand.

Releases reach `circup` users through the
[Community Bundle](https://github.com/adafruit/CircuitPython_Community_Bundle),
which carries this library as a submodule and rebuilds nightly, so a new tag
shows up in `circup install pn7150` a day later without anything to do here.

`requirements.txt` must exist at the repo root even though the driver has no
dependencies — Adafruit's `actions-ci/install.sh` runs `pip install -r
requirements.txt` with no existence check, and the build dies at that step
without it.

Two things to know. GitHub runs release-triggered workflows from the copy of
the file on the default branch, so the workflow must be on `main` before a
release will build anything. A release build checks out the *tag*, not `main`,
so a fix to the build has to be in a new tag — re-running a failed release
job against an old tag rebuilds the old tree. And the 9.x and 10.x builds are currently
byte-identical, since both toolchains emit mpy v6.3; they are shipped
separately because that is what `circup` looks for, and because that will not
stay true forever.

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

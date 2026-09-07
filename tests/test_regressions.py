"""Regression tests for bugs found by reading the driver against real layouts.

Each test here failed before the fix it names.
"""
import pytest

import pn7150
from pn7150 import (NDEFError, NDEFMessage, NDEFRecord, Tag, TECH_NFC_A,
                    TECH_NFC_V, KEY_NDEF)


class FakeNFC:
    """Stands in for the driver; tags built on it never touch a bus."""


NFC_A_PARAMS = b"\x44\x00\x04\x01\x02\x03\x04\x01\x00"


# -- an empty but formatted tag is empty, not malformed ---------------------

def test_empty_ndef_tlv_reads_as_none():
    """`03 00 FE` is a valid empty message; it used to raise NDEFError."""
    assert pn7150._ndef_from_tlv(b"\x03\x00\xfe" + bytes(10)) is None


def test_blank_tag_stops_at_the_terminator():
    """A blank NTAG215 used to be read to the end of its 504 bytes."""
    image = b"\x03\x00\xfe" + bytes(501)
    reads = []

    def read(page):
        reads.append(page)
        offset = (page - 4) * 4
        return image[offset:offset + 16]

    assert pn7150._read_ndef_area(read, 4, 4, 504) is None
    assert len(reads) == 1, "read %d pages to find an empty tag" % len(reads)


# -- 0xFE is data, not always a terminator ----------------------------------

def _mifare_with(payload):
    """A fake 1K holding one MIME record, laid out over real block numbers."""
    tlv = pn7150._ndef_to_tlv(
        NDEFMessage([NDEFRecord.mime("application/cbor", payload)]))
    image = tlv + bytes(512)
    blocks, offset, block = {}, 0, 4
    while offset < len(image):
        if block % 4 == 3:
            block += 1
            continue
        blocks[block] = image[offset:offset + 16]
        offset += 16
        block += 1

    class FakeMifare(pn7150.MifareClassicTag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_MIFARE,
                         TECH_NFC_A, b"\x44\x00\x04\x01\x02\x03\x04\x01\x08")

        def authenticate(self, sector, key=KEY_NDEF, key_b=False):
            return True

        def read_block(self, block):
            return blocks.get(block, bytes(16))

    return FakeMifare()


def test_mifare_payload_containing_fe_is_not_truncated():
    """0xFE inside a binary payload used to end the read and lose the message."""
    payload = bytes([0xFE if i in (30, 31) else i % 251 for i in range(200)])
    message = _mifare_with(payload).read_ndef()
    assert message is not None
    assert message.records[0].payload == payload


def test_mifare_reads_only_the_blocks_it_needs():
    tag = _mifare_with(bytes(16))
    reads = []
    inner = tag.read_block
    tag.read_block = lambda b: (reads.append(b), inner(b))[1]
    tag.read_ndef()
    assert len(reads) <= 6, "read %d blocks for a 16-byte payload" % len(reads)


def test_mifare_4k_sector_geometry():
    """Sectors 32-39 of a 4K card hold 16 blocks, not 4."""
    mfc = pn7150.MifareClassicTag
    assert mfc.sector_of(0) == 0
    assert mfc.sector_of(63) == 15
    assert mfc.sector_of(128) == 32
    assert mfc.sector_of(143) == 32
    assert mfc.sector_of(144) == 33
    assert mfc.first_block_of(32) == 128
    assert mfc.first_block_of(33) == 144
    assert mfc.is_trailer(3) and mfc.is_trailer(143)
    assert not mfc.is_trailer(4) and not mfc.is_trailer(142)


def test_mifare_4k_skips_mad2_and_reauthenticates_per_sector():
    """Sector 16 of a 4K card is MAD2, and each sector needs its own auth."""
    payload = bytes(700)                      # spills well past sector 16
    tlv = pn7150._ndef_to_tlv(
        NDEFMessage([NDEFRecord.mime("application/octet-stream", payload)]))
    mfc = pn7150.MifareClassicTag

    # Lay the TLV over every data block a 4K NDEF card actually uses.
    data_blocks = [b for b in range(4, 256)
                   if not mfc.is_trailer(b) and mfc.sector_of(b) != 16]
    image = tlv + bytes(4096)
    blocks = {b: image[i * 16:i * 16 + 16] for i, b in enumerate(data_blocks)}

    authed, reads = [], []

    class Fake4K(pn7150.MifareClassicTag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_MIFARE,
                         TECH_NFC_A, b"\x44\x00\x04\x01\x02\x03\x04\x01\x18")

        def authenticate(self, sector, key=KEY_NDEF, key_b=False):
            authed.append(sector)
            return True

        def read_block(self, block):
            reads.append(block)
            return blocks.get(block, bytes(16))

    tag = Fake4K()
    assert tag.block_count == 256
    message = tag.read_ndef()
    assert message is not None
    assert message.records[0].payload == payload
    assert 16 not in [mfc.sector_of(b) for b in reads], "read MAD2 as NDEF data"
    assert not any(mfc.is_trailer(b) for b in reads), "read a sector trailer"
    assert authed == sorted(set(authed)), "re-authenticated a sector twice"


# -- writes must not run off the end of user memory -------------------------

class FakeType2(pn7150.Type2Tag):
    """A tag whose capability container declares 48 usable bytes."""

    def __init__(self, mlen=6):
        Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_T2T,
                     TECH_NFC_A, NFC_A_PARAMS)
        self.mlen = mlen
        self.written = []

    def read(self, page):
        if page == 3:
            return bytes([0xE1, 0x10, self.mlen, 0x00]) + bytes(12)
        return bytes(16)

    def write(self, page, data, force=False):
        pn7150.Type2Tag.write(self, page, data, force)

    def transceive(self, data, timeout=0.5):
        self.written.append(bytes(data))
        return b"\x00"


def test_write_ndef_refuses_a_message_larger_than_the_tag():
    """This used to write 436 bytes onto a 48-byte tag, into its config pages."""
    tag = FakeType2()
    big = NDEFMessage([NDEFRecord.mime("application/octet-stream", bytes(400))])
    with pytest.raises(NDEFError):
        tag.write_ndef(big)
    assert tag.written == [], "wrote to the tag before noticing it would not fit"


def test_write_refuses_pages_past_user_memory():
    tag = FakeType2()
    assert tag.capacity == 48
    assert tag.last_data_page == 15
    tag.write(15, b"\x00\x00\x00\x00")            # last usable page: fine
    with pytest.raises(ValueError):
        tag.write(16, b"\x00\x00\x00\x00")        # first config page
    with pytest.raises(ValueError):
        tag.write(3, b"\x00\x00\x00\x00")


def test_force_lifts_the_upper_bound_but_never_the_lower_one():
    tag = FakeType2()
    tag.write(40, b"\x00\x00\x00\x00", force=True)
    with pytest.raises(ValueError):
        tag.write(0, b"\x00\x00\x00\x00", force=True)


def test_write_ndef_fits_exactly():
    """A message that exactly fills the tag is allowed."""
    tag = FakeType2(mlen=6)
    payload = bytes(48 - 2 - 1 - 3 - len("application/x"))
    message = NDEFMessage([NDEFRecord.mime("application/x", payload)])
    assert len(pn7150._ndef_to_tlv(message)) == 48
    tag.write_ndef(message)
    assert len(tag.written) == 12


def test_capacity_is_read_once():
    tag = FakeType2()
    reads = []
    inner = tag.read
    tag.read = lambda p: (reads.append(p), inner(p))[1]
    tag.write_ndef(NDEFMessage.from_uri("https://a.co"))
    assert reads.count(3) == 1, "read the capability container %d times" % reads.count(3)


# -- NCI packet limits ------------------------------------------------------

def test_oversized_payload_raises_a_useful_error():
    """Used to fail with `ValueError: bytes must be in range(0, 256)`."""
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    with pytest.raises(ValueError) as info:
        nfc._exchange(bytes(300))
    assert "segmentation" in str(info.value)


def test_transceive_respects_the_negotiated_payload_size():
    tag = Tag(FakeNFC(), 0, 1, 2, TECH_NFC_A, NFC_A_PARAMS, max_payload=32)
    with pytest.raises(ValueError):
        tag.transceive(bytes(33))


# -- new API ----------------------------------------------------------------

def test_external_record_round_trips():
    record = NDEFRecord.external("example.com:widget", b"\x01\x02")
    back = NDEFMessage.from_bytes(NDEFMessage([record]).to_bytes())
    assert back.records[0].kind == "external"
    assert back.records[0].type == b"example.com:widget"
    assert back.records[0].value == b"\x01\x02"


def test_records_and_messages_compare_by_value():
    assert NDEFRecord.uri("https://a.co") == NDEFRecord.uri("https://a.co")
    assert NDEFRecord.uri("https://a.co") != NDEFRecord.uri("https://b.co")
    assert NDEFMessage.from_text("hi") == NDEFMessage.from_text("hi")
    assert NDEFMessage.from_text("hi") != NDEFMessage.from_text("ho")
    assert NDEFMessage.from_text("hi") != "hi"


def test_round_trip_equality_survives_encoding():
    message = NDEFMessage([NDEFRecord.uri("https://a.co"),
                           NDEFRecord.text("caption", "sv")])
    assert NDEFMessage.from_bytes(message.to_bytes()) == message


def test_is_present_treats_a_refusal_as_present():
    """A card that answers with an error is still a card in the field."""
    class Refusing(pn7150.Type2Tag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_T2T,
                         TECH_NFC_A, NFC_A_PARAMS)

        def transceive(self, data, timeout=0.5):
            raise pn7150.CommandError("refused")

    class Gone(Refusing):
        def transceive(self, data, timeout=0.5):
            raise pn7150.TagLostError("gone")

    assert Refusing().is_present() is True
    assert Gone().is_present() is False


def test_type5_write_block_refuses_the_capability_container():
    tag = _type5_with({0: b"\xe1\x40\x27\x01"})
    with pytest.raises(ValueError):
        tag.write_block(0, b"\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        tag.write_block(1, b"\x00\x00")          # wrong size


# -- multi-protocol targets (RF_DISCOVER_NTF) -------------------------------

# Captured from a card advertising both ISO-DEP and MIFARE (real SAK 0x28):
# the NFCC lists candidates and waits in W4_HOST_SELECT instead of activating.
DISCOVER_NTF_ISO_DEP = bytes.fromhex("61030e010400090400 04b2ce2d2201 20 02".replace(" ", ""))
DISCOVER_NTF_MIFARE = bytes.fromhex("61030e028000090400 04b2ce2d2201 08 00".replace(" ", ""))


def test_parse_discover_ntf():
    assert pn7150._parse_discover_ntf(DISCOVER_NTF_ISO_DEP) == (
        1, pn7150.PROTOCOL_ISO_DEP, pn7150.TECH_NFC_A,
        bytes.fromhex("040004b2ce2d220120"))
    assert pn7150._parse_discover_ntf(DISCOVER_NTF_MIFARE) == (
        2, pn7150.PROTOCOL_MIFARE, pn7150.TECH_NFC_A,
        bytes.fromhex("040004b2ce2d220108"))
    assert pn7150._parse_discover_ntf(b"\x61\x03\x02\x01") is None


def _driver_with_frames(frames):
    """A PN7150 whose _read_frame replays `frames` and records what is sent."""
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    nfc._connected = True
    nfc._discovering = True
    nfc._mapped = True
    sent = []
    queue = list(frames)

    def read_frame(timeout):
        return queue.pop(0) if queue else None

    def write_frame(data):
        sent.append(bytes(data))
        # The NFCC acknowledges RF_DISCOVER_SELECT, then activates.
        if data[:2] == b"\x21\x04":
            queue.append(b"\x41\x04\x01\x00")
            queue.append(ACTIVATED_MIFARE)

    nfc._read_frame = read_frame
    nfc._write_frame = write_frame
    return nfc, sent


# RF_INTF_ACTIVATED_NTF for the MIFARE view of that same card.
ACTIVATED_MIFARE = (b"\x61\x05\x14\x02\x80\x80\x00\xff\x01\x09"
                    + bytes.fromhex("040004b2ce2d220108"))


def test_multi_protocol_card_is_selected_and_activated():
    """Used to hang forever: the driver ignored RF_DISCOVER_NTF entirely."""
    nfc, sent = _driver_with_frames([DISCOVER_NTF_ISO_DEP, DISCOVER_NTF_MIFARE])
    tag = nfc.wait_for_tag(timeout=5)

    selects = [f for f in sent if f[:2] == b"\x21\x04"]
    assert len(selects) == 1, "sent %d RF_DISCOVER_SELECT commands" % len(selects)
    # MIFARE (discovery id 2) is preferred over ISO-DEP, on the Tag interface.
    assert selects[0] == bytes([0x21, 0x04, 0x03, 2,
                                pn7150.PROTOCOL_MIFARE, pn7150.INTERFACE_TAG])
    assert isinstance(tag, pn7150.MifareClassicTag)
    assert tag.uid_hex == "b2:ce:2d:22"
    assert len(nfc.candidates) == 2


def test_protocol_preference_is_configurable():
    nfc, sent = _driver_with_frames([DISCOVER_NTF_ISO_DEP, DISCOVER_NTF_MIFARE])
    nfc.protocol_preference = (pn7150.PROTOCOL_ISO_DEP, pn7150.PROTOCOL_MIFARE)
    nfc.wait_for_tag(timeout=5)
    selects = [f for f in sent if f[:2] == b"\x21\x04"]
    assert selects[0][3] == 1, "did not honour the ISO-DEP preference"
    assert selects[0][4] == pn7150.PROTOCOL_ISO_DEP


def test_single_candidate_still_gets_selected():
    """One RF_DISCOVER_NTF marked 'last' is still a W4_HOST_SELECT state."""
    nfc, sent = _driver_with_frames([DISCOVER_NTF_MIFARE])
    tag = nfc.wait_for_tag(timeout=5)
    assert [f for f in sent if f[:2] == b"\x21\x04"]
    assert isinstance(tag, pn7150.MifareClassicTag)


def test_failed_selection_returns_to_polling():
    """If every candidate is refused, do not sit in W4_HOST_SELECT."""
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    nfc._connected = True
    nfc._discovering = True
    nfc._mapped = True          # as it is after a real connect()
    sent = []
    queue = [DISCOVER_NTF_ISO_DEP, DISCOVER_NTF_MIFARE]

    def read_frame(timeout):
        return queue.pop(0) if queue else None

    def write_frame(data):
        sent.append(bytes(data))
        if data[:2] == b"\x21\x04":
            queue.append(b"\x41\x04\x01\x03")       # STATUS_FAILED
        elif data[0] == 0x21:
            queue.append(bytes([0x41, data[1], 0x01, 0x00]))

    nfc._read_frame = read_frame
    nfc._write_frame = write_frame
    assert nfc.wait_for_tag(timeout=2) is None
    assert any(f[:2] == b"\x21\x06" for f in sent), "never deactivated to idle"
    assert any(f[:2] == b"\x21\x03" for f in sent), "never restarted discovery"


# -- transient RF errors ----------------------------------------------------

def test_command_error_carries_the_status():
    try:
        pn7150._split_status(bytes(4) + b"\x02", "read")
    except pn7150.CommandError as err:
        assert err.status == 0x02
        assert "RF_FRAME_CORRUPTED" in str(err)
    else:
        raise AssertionError("did not raise")


def test_a_glitched_block_is_retried():
    """One corrupted frame used to throw away the whole message."""
    calls = []

    def flaky(block):
        calls.append(block)
        if block == 3 and calls.count(3) == 1:
            raise pn7150.CommandError("read of block 3 failed", 0x02)
        return bytes([block] * 4)

    assert pn7150._read_retrying(flaky, 3) == bytes([3] * 4)
    assert calls.count(3) == 2, "did not retry the glitched block"


def test_a_refusal_is_not_retried():
    """Status 0x03 means the tag said no; repeating it just wastes time."""
    calls = []

    def refusing(block):
        calls.append(block)
        raise pn7150.CommandError("refused", 0x03)

    with pytest.raises(pn7150.CommandError):
        pn7150._read_retrying(refusing, 1)
    assert len(calls) == 1


def test_ndef_survives_a_glitch_mid_message():
    """Reproduces SCAN 14: RF_FRAME_CORRUPTED at block 44 of a 303-byte NDEF."""
    message = NDEFMessage([NDEFRecord.uri("https://3dtag.org/s/7f062f57b9"),
                           NDEFRecord.mime("application/cbor", bytes(250))])
    image = pn7150._ndef_to_tlv(message) + bytes(64)
    glitched = []

    def read_block(block):
        if block == 44 and 44 not in glitched:
            glitched.append(44)
            raise pn7150.CommandError("read of block 44 failed", 0x02)
        return image[(block - 1) * 4:(block - 1) * 4 + 4]

    got = pn7150._read_ndef_area(read_block, 1, 1, 312)
    assert got == message, "lost the message to a single corrupted frame"


def test_felica_without_a_service_reports_false_even_on_silence():
    """A card that never answers CHECK used to raise TagTimeoutError."""
    class Silent(pn7150.Type3Tag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_T3T,
                         pn7150.TECH_NFC_F,
                         b"\x01\x10" + bytes(range(16)))

        def transceive(self, data, timeout=0.5):
            raise pn7150.TagTimeoutError("tag did not answer in 0.50s")

    assert Silent().has_ndef_service() is False


# -- short / absent capability containers -----------------------------------

@pytest.mark.parametrize("cc_bytes", [b"", b"\x00", b"\xe1", b"\xe1\x10"])
def test_short_cc_read_does_not_crash(cc_bytes):
    """One surveyed tag answered READ page 3 with a single byte; an empty
    payload used to raise IndexError straight out of capacity()."""
    class Stubborn(pn7150.Type2Tag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_T2T,
                         TECH_NFC_A, NFC_A_PARAMS)

        def read(self, page):
            return cc_bytes

    tag = Stubborn()
    assert tag.capacity == pn7150.Type2Tag.DEFAULT_CAPACITY
    assert tag.last_data_page == 3 + pn7150.Type2Tag.DEFAULT_CAPACITY // 4


# -- NCI error notifications ------------------------------------------------

def test_interface_error_ntf_fails_fast_with_the_real_status():
    """Captured from a hotel card: the NFCC said RF_TIMEOUT, the driver waited
    out its own 1.5s and then reported a vague 'tag did not answer'."""
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    frames = [b"\x60\x06\x03\x01\x00\x01",        # CONN_CREDITS, ignore
              b"\x60\x08\x02\xb2\x00"]             # INTERFACE_ERROR, 0xB2
    nfc._read_frame = lambda t: frames.pop(0) if frames else None
    nfc._write_frame = lambda d: None
    with pytest.raises(pn7150.CommandError) as info:
        nfc._exchange(b"\x00\xa4\x04\x00", timeout=30)
    assert info.value.status == 0xB2
    assert "RF_TIMEOUT_ERROR" in str(info.value)


def test_generic_error_ntf_is_also_reported():
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    frames = [b"\x60\x07\x01\xb1"]
    nfc._read_frame = lambda t: frames.pop(0) if frames else None
    nfc._write_frame = lambda d: None
    with pytest.raises(pn7150.CommandError) as info:
        nfc._exchange(b"\x30\x00", timeout=30)
    assert info.value.status == 0xB1


def test_select_ndef_application_returns_false_when_the_card_is_silent():
    """Used to propagate TagTimeoutError out of a predicate."""
    class Silent(pn7150.Type4Tag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 2, pn7150.PROTOCOL_ISO_DEP,
                         TECH_NFC_A, NFC_A_PARAMS)

        def transceive(self, data, timeout=0.5):
            raise pn7150.TagTimeoutError("tag did not answer in 1.50s")

    assert Silent().select_ndef_application() is False
    assert Silent().read_ndef() is None


# -- Type 5 capability container, both forms --------------------------------

def _type5_with(blocks):
    class FakeType5(pn7150.Type5Tag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_T5T,
                         TECH_NFC_V, b"\x00\x00" + bytes(8))

        def read_block(self, block):
            if block not in blocks:
                raise pn7150.CommandError("no block %d" % block, 0x03)
            return blocks[block]

    return FakeType5()


def test_short_capability_container():
    """The 4-byte form: MLEN in byte 2, data from block 1."""
    tag = _type5_with({0: b"\xe1\x40\x27\x01"})
    assert tag.cc_size == 4
    assert tag.capacity == 0x27 * 8 == 312
    assert tag.first_data_block == 1
    assert tag.formatted is True


def test_long_capability_container():
    """Byte 2 == 0 means an 8-byte CC with a 16-bit MLEN in bytes 6-7, and the
    T5T area then starts at block 2. Parsing it as the short form reads half
    the CC as TLV data and reports a capacity of zero."""
    tag = _type5_with({0: b"\xe2\x40\x00\x01", 1: b"\x00\x00\x03\x20"})
    assert tag.cc_size == 8
    assert tag.capacity == 0x0320 * 8 == 6400
    assert tag.first_data_block == 2
    assert tag.formatted is True


def test_long_cc_reads_ndef_from_block_two():
    message = NDEFMessage.from_uri("https://example.com")
    image = pn7150._ndef_to_tlv(message) + bytes(64)
    blocks = {0: b"\xe2\x40\x00\x01", 1: b"\x00\x00\x00\x08"}
    for i in range(16):
        blocks[2 + i] = image[i * 4:i * 4 + 4]
    assert _type5_with(blocks).read_ndef() == message


def test_long_cc_write_refuses_both_cc_blocks():
    tag = _type5_with({0: b"\xe2\x40\x00\x01", 1: b"\x00\x00\x03\x20"})
    for block in (0, 1):
        with pytest.raises(ValueError):
            tag.write_block(block, b"\x00\x00\x00\x00")


def test_unformatted_type5_has_no_capacity():
    """The CC seen on one of the surveyed tags: 04 08 c6 f3, no magic number."""
    tag = _type5_with({0: b"\x04\x08\xc6\xf3"})
    assert tag.formatted is False
    assert tag.capacity == 0


# -- Mifare Classic writing -------------------------------------------------

def _writable_mifare(sak=0x08):
    """A fake card that records the exact frames a write produces."""
    sent = []
    memory = {}

    class Fake(pn7150.MifareClassicTag):
        def __init__(self):
            Tag.__init__(self, FakeNFC(), 0, 1, pn7150.PROTOCOL_MIFARE,
                         TECH_NFC_A,
                         bytes([0x04, 0x00, 0x04, 1, 2, 3, 4, 0x01, sak]))
            self._pending = None

        def authenticate(self, sector, key=KEY_NDEF, key_b=False):
            sent.append(("auth", sector))
            return True

        def read_block(self, block):
            return memory.get(block, bytes(16))

        def transceive(self, data, timeout=0.5):
            data = bytes(data)
            sent.append(data)
            if len(data) == 3 and data[1] == 0xA0:
                self._pending = data[2]
                return b"\x00\x00\x00"
            if len(data) == 17 and data[0] == 0x10:
                memory[self._pending] = data[1:]
                return b"\x00\x00"
            return b"\x00"

    return Fake(), sent, memory


def test_mifare_write_is_two_phases():
    """NXP's reference sends `10 A0 <blk>`, waits for the ack, then `10 <16>`."""
    tag, sent, memory = _writable_mifare()
    payload = bytes(range(16))
    tag.write_block(4, payload)
    frames = [f for f in sent if isinstance(f, bytes)]
    assert frames[0] == bytes([0x10, 0xA0, 4])
    assert frames[1] == bytes([0x10]) + payload
    assert memory[4] == payload


def test_mifare_write_refuses_the_manufacturer_block():
    tag, _, _ = _writable_mifare()
    with pytest.raises(ValueError):
        tag.write_block(0, bytes(16))


def test_mifare_write_refuses_sector_trailers():
    """Wrong access bits in a trailer lock the sector permanently."""
    tag, sent, _ = _writable_mifare()
    for trailer in (3, 7, 63):
        with pytest.raises(ValueError) as info:
            tag.write_block(trailer, bytes(16))
        assert "trailer" in str(info.value)
    assert not [f for f in sent if isinstance(f, bytes)], "sent a frame anyway"
    tag.write_block(7, bytes(16), force=True)          # explicit opt-in


def test_mifare_write_block_size_is_checked():
    tag, _, _ = _writable_mifare()
    with pytest.raises(ValueError):
        tag.write_block(4, bytes(4))


def test_mifare_ndef_blocks_skip_mad_and_trailers():
    tag, _, _ = _writable_mifare()
    blocks = tag.ndef_blocks()
    assert 0 not in blocks and 3 not in blocks and 63 not in blocks
    assert blocks[0] == 4
    assert len(blocks) == 45            # 15 sectors x 3 data blocks
    assert tag.ndef_capacity == 45 * 16

    big, _, _ = _writable_mifare(sak=0x18)
    assert 64 not in big.ndef_blocks(), "MAD2 counted as NDEF space"
    assert 66 not in big.ndef_blocks()


def test_mifare_write_ndef_round_trips_through_the_same_blocks():
    """read_ndef and write_ndef must agree on which blocks hold the message."""
    tag, sent, _ = _writable_mifare()
    message = NDEFMessage([NDEFRecord.uri("https://example.com"),
                           NDEFRecord.text("hello", "en")])
    tag.write_ndef(message)
    assert tag.read_ndef() == message
    assert all(b != 3 and b != 0 for b in
               [f[2] for f in sent if isinstance(f, bytes) and len(f) == 3])


def test_mifare_write_ndef_refuses_an_oversized_message():
    tag, sent, _ = _writable_mifare()
    too_big = NDEFMessage([NDEFRecord.mime("application/x",
                                           bytes(tag.ndef_capacity))])
    with pytest.raises(NDEFError):
        tag.write_ndef(too_big)
    assert not [f for f in sent if isinstance(f, bytes)], "wrote before checking"


# -- TLV span helper --------------------------------------------------------

@pytest.mark.parametrize("data, expected", [
    (b"", pn7150.TLV_NEED_MORE),
    (b"\x03", pn7150.TLV_NEED_MORE),
    (b"\xfe", pn7150.TLV_NO_NDEF),
    (b"\x00\x00\xfe", pn7150.TLV_NO_NDEF),
    (b"\x03\x00\xfe", pn7150.TLV_NO_NDEF),
    (b"\x03\x05\x01\x02\x03", 7),
    (b"\x01\x03\xa0\x0c\x34\x03\x11", 24),
    (b"\x03\xff\x01\x00", 4 + 256),   # 3-byte length form: 4 header bytes
    (b"\x03\xff\x01", pn7150.TLV_NEED_MORE),
])
def test_ndef_tlv_end(data, expected):
    assert pn7150._ndef_tlv_end(data) == expected

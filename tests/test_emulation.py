"""Type 4 card emulation: the applet, the NCI session, and the two halves of
this driver checked against each other.

The loopback tests are the interesting ones. The reader implementation
(:class:`~pn7150.Type4Tag`) and the card implementation
(:class:`~pn7150.Type4NDEFApplet`) were written from the same spec but share no
code, so piping one straight into the other exercises both without hardware.
"""
import pytest

import pn7150
from pn7150 import (CardEmulator, NDEFMessage, NDEFRecord, Type4NDEFApplet,
                    Type4Tag, TECH_NFC_A, TECH_NFC_A_LISTEN)


# -- the reader talking to the applet, with no bus in between ---------------

class LoopbackTag(Type4Tag):
    """A Type4Tag whose transceive() is an applet instead of a card.

    ``status_byte`` decides whether the fake RF interface appends the trailing
    NCI status byte that :func:`pn7150._split_status` strips. The Frame and
    TAG-CMD interfaces really do append one -- that is measured -- but NCI puts
    the bare APDU on the ISO-DEP interface, so on real hardware this should be
    ``False``. It defaults to ``True`` here because that is what the reader
    currently assumes; see ``test_iso_dep_response_without_a_status_byte``.
    """

    def __init__(self, applet, status_byte=True):
        Type4Tag.__init__(self, None, 0, pn7150.INTERFACE_ISO_DEP,
                          pn7150.PROTOCOL_ISO_DEP, TECH_NFC_A, b"", 255)
        self.applet = applet
        self.status_byte = status_byte
        self.log = []

    def transceive(self, data, timeout=0.5):
        self.log.append(bytes(data))
        r_apdu = self.applet.process(bytes(data))
        return r_apdu + b"\x00" if self.status_byte else r_apdu


MESSAGE = NDEFMessage([NDEFRecord.uri("https://example.com"),
                       NDEFRecord.text("hello", "en")])


def test_the_reader_reads_what_the_applet_serves():
    tag = LoopbackTag(Type4NDEFApplet(MESSAGE))
    assert tag.read_ndef() == MESSAGE


def test_a_string_is_coerced_the_same_way_write_ndef_coerces_one():
    tag = LoopbackTag(Type4NDEFApplet("https://example.com"))
    assert tag.read_ndef().uri == "https://example.com"
    tag = LoopbackTag(Type4NDEFApplet("just some words"))
    assert tag.read_ndef().text == "just some words"


def test_an_empty_applet_reads_as_no_message():
    assert LoopbackTag(Type4NDEFApplet(None)).read_ndef() is None


def test_a_message_longer_than_one_read_is_reassembled():
    """The reader chunks READ BINARY at 0xF0 bytes; the applet honours Le."""
    big = NDEFMessage([NDEFRecord.mime("application/octet-stream",
                                       bytes(range(256)) * 2)])
    tag = LoopbackTag(Type4NDEFApplet(big, max_size=2048))
    assert tag.read_ndef() == big
    reads = [c for c in tag.log if c[1] == 0xB0]
    assert len(reads) > 3, "a 500-byte message came back in one READ BINARY"


def test_the_reader_writes_what_the_applet_then_serves():
    applet = Type4NDEFApplet(NDEFMessage.from_text("before"), writable=True)
    tag = LoopbackTag(applet)
    new = NDEFMessage([NDEFRecord.uri("https://thefilip.com"),
                       NDEFRecord.text("after")])
    assert tag.write_ndef(new) is True
    assert applet.message == new
    assert LoopbackTag(applet).read_ndef() == new


def test_the_reader_refuses_a_read_only_applet():
    tag = LoopbackTag(Type4NDEFApplet(NDEFMessage.from_text("x")))
    with pytest.raises(pn7150.NotSupportedError):
        tag.write_ndef(NDEFMessage.from_text("y"))


def test_the_reader_honours_the_capability_container_size():
    applet = Type4NDEFApplet(None, max_size=32, writable=True)
    tag = LoopbackTag(applet)
    with pytest.raises(pn7150.NDEFError):
        tag.write_ndef(NDEFMessage([NDEFRecord.mime("application/x",
                                                    bytes(64))]))


def test_on_write_fires_once_the_message_is_complete():
    seen = []
    applet = Type4NDEFApplet(None, writable=True, on_write=seen.append)
    LoopbackTag(applet).write_ndef(MESSAGE)
    assert seen == [MESSAGE]


def test_on_read_fires_when_the_reader_reaches_the_end():
    seen = []
    applet = Type4NDEFApplet(MESSAGE, on_read=seen.append)
    LoopbackTag(applet).read_ndef()
    assert seen == [MESSAGE]


def test_iso_dep_response_without_a_status_byte():
    """Pins the suspected pre-existing reader bug, so the fix has a test.

    NCI hands the bare APDU up on the ISO-DEP interface -- AOSP's rw_t4t.c and
    ce_t4t.c both read SW1/SW2 as the last two payload bytes with nothing
    stripped -- but Type4Tag.apdu() runs the response through _split_status()
    anyway. A card answering `90 00` is then read as payload `90` with a
    trailing status of 0x00, which is one byte short of an APDU, so
    select_ndef_application() reports no NDEF application.

    That is exactly the hardware result recorded in the README ("ISO-DEP x6 |
    no NDEF application"). Confirm it in one tap with debug=True before
    changing Type4Tag: a 2-byte payload after SELECT means no status byte.
    """
    tag = LoopbackTag(Type4NDEFApplet(MESSAGE), status_byte=False)
    assert tag.select_ndef_application() is False
    assert tag.read_ndef() is None
    # The applet is fine; the reader threw the answer away.
    assert tag.applet.process(tag.log[0]) == b"\x90\x00"


# -- applet edge cases ------------------------------------------------------

SELECT_NDEF_APP = b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00"
SELECT_NDEF_APP_V1 = b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x00"
SELECT_CC = b"\x00\xa4\x00\x0c\x02\xe1\x03"
SELECT_NDEF_FILE = b"\x00\xa4\x00\x0c\x02\xe1\x04"


def selected(**kwargs):
    applet = Type4NDEFApplet(MESSAGE, **kwargs)
    assert applet.process(SELECT_NDEF_APP) == b"\x90\x00"
    return applet


def test_both_ndef_aids_are_accepted():
    assert Type4NDEFApplet(MESSAGE).process(SELECT_NDEF_APP) == b"\x90\x00"
    assert Type4NDEFApplet(MESSAGE).process(SELECT_NDEF_APP_V1) == b"\x90\x00"


def test_an_unknown_aid_is_refused():
    other = b"\x00\xa4\x04\x00\x07\xa0\x00\x00\x03\x06\x03\x00\x00"
    assert Type4NDEFApplet(MESSAGE).process(other) == b"\x6a\x82"


def test_selecting_a_file_before_the_application_is_refused():
    assert Type4NDEFApplet(MESSAGE).process(SELECT_CC) == b"\x69\x86"


def test_an_unknown_file_is_refused():
    applet = selected()
    assert applet.process(b"\x00\xa4\x00\x0c\x02\xe1\x05") == b"\x6a\x82"


def test_reading_past_the_end_of_a_file():
    applet = selected()
    applet.process(SELECT_CC)
    assert applet.process(b"\x00\xb0\x00\x0f\x01") == b"\x6b\x00"
    assert applet.process(b"\x00\xb0\x00\x0e\x01")[-2:] == b"\x90\x00"


def test_reading_before_anything_is_selected():
    applet = selected()
    assert applet.process(b"\x00\xb0\x00\x00\x02") == b"\x69\x86"


def test_le_zero_means_256():
    applet = Type4NDEFApplet(NDEFMessage([NDEFRecord.mime(
        "application/x", bytes(300))]), max_size=512)
    applet.process(SELECT_NDEF_APP)
    applet.process(SELECT_NDEF_FILE)
    assert len(applet.process(b"\x00\xb0\x00\x00\x00")) == 256 + 2


def test_update_binary_on_a_read_only_tag():
    applet = selected()
    applet.process(SELECT_NDEF_FILE)
    assert applet.process(b"\x00\xd6\x00\x00\x02\x00\x00") == b"\x69\x86"


def test_update_binary_past_the_declared_size():
    applet = selected(max_size=32, writable=True)
    applet.process(SELECT_NDEF_FILE)
    assert applet.process(b"\x00\xd6\x00\x20\x02\x01\x02") == b"\x6b\x00"


def test_an_unknown_instruction():
    assert Type4NDEFApplet(MESSAGE).process(b"\x00\xca\x00\x00\x00") == b"\x6d\x00"


def test_a_foreign_class_byte():
    assert Type4NDEFApplet(MESSAGE).process(b"\x80\xb0\x00\x00\x02") == b"\x6e\x00"


def test_a_truncated_apdu():
    assert Type4NDEFApplet(MESSAGE).process(b"\x00\xa4\x04") == b"\x67\x00"
    assert Type4NDEFApplet(MESSAGE).process(b"\x00\xa4\x04\x00\x07\xd2") \
        == b"\x67\x00"


def test_a_message_that_does_not_fit_the_declared_size():
    with pytest.raises(pn7150.NDEFError):
        Type4NDEFApplet(NDEFMessage([NDEFRecord.mime("application/x",
                                                     bytes(64))]),
                        max_size=32)


def test_the_capability_container_says_read_only_or_writable():
    # CCLEN, mapping version 2.0, MLe, MLc, then the NDEF File Control TLV.
    assert Type4NDEFApplet(None).capability_container == \
        bytes.fromhex("000f2000ff00ff0406e10404 0000ff".replace(" ", ""))
    assert Type4NDEFApplet(None, writable=True).capability_container[-1] == 0x00
    assert Type4NDEFApplet(None, max_size=0x0400).capability_container[11:13] \
        == b"\x04\x00"
    assert len(Type4NDEFApplet(None).capability_container) == 15


def test_reset_forgets_the_selection():
    applet = selected()
    applet.process(SELECT_CC)
    applet.reset()
    assert applet.process(b"\x00\xb0\x00\x00\x02") == b"\x69\x86"


def test_a_partial_write_publishes_nothing_until_nlen_lands():
    published = []
    applet = Type4NDEFApplet(None, writable=True, on_write=published.append)
    applet.process(SELECT_NDEF_APP)
    applet.process(SELECT_NDEF_FILE)
    payload = MESSAGE.to_bytes()
    assert applet.process(b"\x00\xd6\x00\x00\x02\x00\x00") == b"\x90\x00"
    assert applet.process(bytes([0x00, 0xD6, 0x00, 0x02, len(payload)])
                          + payload) == b"\x90\x00"
    assert published == [], "published before NLEN was written"
    assert applet.process(bytes([0x00, 0xD6, 0x00, 0x00, 0x02,
                                 len(payload) >> 8, len(payload) & 0xFF])) \
        == b"\x90\x00"
    assert published == [MESSAGE]


# -- the NCI session --------------------------------------------------------

def fake_bus(nfc, queue=None):
    """Replace a driver's transport with a replayed queue of frames.

    Every command gets a plausible success response put at the *front* of the
    queue, so notifications staged ahead of time stay behind the answers to the
    bring-up commands rather than being mistaken for them.
    """
    sent = []
    queue = [] if queue is None else queue

    def write_frame(data):
        data = bytes(data)
        sent.append(data)
        if data[0] == 0x20:                       # CORE_*_CMD
            queue.insert(0, bytes([0x40, data[1], 0x02, 0x00, 0x00]))
        elif data[0] == 0x21:                     # RF_*_CMD
            queue.insert(0, bytes([0x41, data[1], 0x01, 0x00]))

    nfc._read_frame = lambda timeout: queue.pop(0) if queue else None
    nfc._write_frame = write_frame
    nfc._drain = lambda: None
    return sent, queue


def connected_driver(queue=None):
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    nfc._connected = True
    sent, queue = fake_bus(nfc, queue)
    return nfc, sent, queue


def emulator_with_frames(frames, **kwargs):
    """A CardEmulator over a driver whose bus replays `frames`."""
    nfc, sent, queue = connected_driver(list(frames))
    return CardEmulator(nfc, **kwargs), sent, queue


ACTIVATED_LISTEN = bytes([0x61, 0x05, 0x0A, 0x01, pn7150.INTERFACE_ISO_DEP,
                          pn7150.PROTOCOL_ISO_DEP, TECH_NFC_A_LISTEN,
                          0xFF, 0x01, 0x02, 0x00, 0x00])
DEACTIVATED = b"\x61\x06\x02\x00\x00"
FIELD_ON = b"\x61\x07\x01\x01"
FIELD_OFF = b"\x61\x07\x01\x00"
CREDIT = b"\x60\x06\x03\x01\x00\x01"


def data_packet(payload, pbf=False):
    return bytes([0x10 if pbf else 0x00, 0x00, len(payload)]) + bytes(payload)


def test_the_bring_up_sequence_is_exactly_what_the_manual_asks_for():
    emu, sent, _ = emulator_with_frames([])
    emu.start()
    assert sent == [
        bytes.fromhex("210004010402 02".replace(" ", "")),   # map: ISO-DEP listen
        bytes.fromhex("2002040132 0120".replace(" ", "")),   # LA_SEL_INFO
        bytes.fromhex("2002040180 0101".replace(" ", "")),   # RF_FIELD_INFO
        bytes.fromhex("2101070001010300 0104".replace(" ", "")),  # routing
        bytes.fromhex("210303018001"),                       # RF_DISCOVER
    ]
    assert emu.routing_status == 0x00


def test_an_nfcid1_is_configured_when_one_is_given():
    emu, sent, _ = emulator_with_frames([], nfcid1=b"\x08\x01\x02\x03")
    emu.start()
    assert sent[2] == bytes.fromhex("20020701330408010203")


def test_a_bad_nfcid1_length_is_refused_up_front():
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    with pytest.raises(ValueError):
        CardEmulator(nfc, nfcid1=b"\x01\x02")


def test_also_poll_maps_both_directions_and_discovers_both():
    emu, sent, _ = emulator_with_frames([], also_poll=True)
    emu.start()
    assert sent[0] == (b"\x21\x00\x13\x06\x01\x01\x01\x02\x01\x01\x03\x01\x01"
                       b"\x04\x01\x02\x80\x01\x80\x04\x02\x02")
    discover = sent[-1]
    assert discover[:4] == b"\x21\x03\x0b\x05"
    assert discover[-2:] == bytes([TECH_NFC_A_LISTEN, 0x01])


def test_a_rejected_listen_route_is_not_fatal():
    nfc, _, queue = connected_driver()
    inner = nfc._write_frame

    def write_frame(data):
        inner(data)
        if bytes(data)[:2] == b"\x21\x01":
            queue[0] = b"\x41\x01\x01\x03"            # STATUS_FAILED

    nfc._write_frame = write_frame
    emu = CardEmulator(nfc)
    assert emu.start() is True
    assert emu.routing_status == 0x03


def test_a_rejected_config_parameter_names_itself():
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    nfc._connected = True
    nfc._write_frame = lambda data: None
    nfc._read_frame = lambda timeout: b"\x40\x02\x03\x09\x01\x32"
    with pytest.raises(pn7150.CommandError) as err:
        nfc.set_config([(pn7150.CFG_LA_SEL_INFO, b"\x20")])
    assert "0x32" in str(err.value)


def test_activation_seeds_the_credit_and_payload_size():
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(FIELD_ON)
    queue.append(ACTIVATED_LISTEN)
    assert emu.wait_for_reader(timeout=2) is True
    assert emu.field_present is True
    assert emu.reader_active is True
    assert emu._nfc._credits == 1
    assert emu._nfc._max_payload == 0xFF


def test_a_segmented_c_apdu_is_reassembled():
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    queue.append(data_packet(SELECT_NDEF_APP[:5], pbf=True))
    queue.append(data_packet(SELECT_NDEF_APP[5:]))
    assert emu.next_apdu(timeout=2) == SELECT_NDEF_APP


def test_a_long_response_is_segmented_and_waits_for_credits():
    emu, sent, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    assert emu.wait_for_reader(timeout=2) is True
    emu._nfc._max_payload = 8                    # force several packets
    queue.append(CREDIT)
    queue.append(CREDIT)
    queue.append(CREDIT)
    payload = bytes(range(30))
    assert emu.respond(payload) is True
    packets = [f for f in sent if f[0] & 0xE0 == 0x00]
    assert [f[0] for f in packets] == [0x10, 0x10, 0x10, 0x00]
    assert b"".join(f[3:] for f in packets) == payload
    assert all(len(f) - 3 <= 8 for f in packets)


def test_a_response_that_fits_goes_out_in_one_packet():
    emu, sent, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    emu.respond(b"\x90\x00")
    assert [f for f in sent if f[0] & 0xE0 == 0x00] == [b"\x00\x00\x02\x90\x00"]


def test_no_credit_means_a_timeout_not_a_silent_drop():
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    emu._nfc._max_payload = 4
    emu._nfc._credits = 1
    with pytest.raises(pn7150.TagTimeoutError):
        emu._nfc._send_data(bytes(16), timeout=0.05)


def test_deactivation_re_discovers_instead_of_sleeping():
    """UM10936 §9.1: RF_DEACTIVATE(Sleep) is refused in the listen states."""
    emu, sent, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    del sent[:]
    queue.append(DEACTIVATED)
    assert emu.next_apdu(timeout=2) is None
    assert emu.last_event == "deactivated"
    assert emu.reader_active is False
    assert b"\x21\x06\x01\x01" not in sent, "sent RF_DEACTIVATE(Sleep)"
    assert b"\x21\x06\x01\x00" in sent, "never dropped to idle"
    assert sent[-1] == bytes.fromhex("210303018001"), "never re-discovered"


def test_a_second_reader_is_served_after_the_first_leaves():
    """The listen-mode twin of the W4_HOST_SELECT trap: going blind after one
    tap looks exactly like a freeze."""
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    queue.append(data_packet(SELECT_NDEF_APP))
    assert emu.next_apdu(timeout=2) == SELECT_NDEF_APP
    queue.append(DEACTIVATED)
    assert emu.next_apdu(timeout=2) is None
    queue.append(ACTIVATED_LISTEN)
    queue.append(data_packet(SELECT_CC))
    assert emu.next_apdu(timeout=2) == SELECT_CC


def test_a_deactivation_met_while_writing_is_not_lost():
    """_drain() runs before every write; a deactivation swallowed there used
    to leave the session waiting forever for an APDU that never comes."""
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    emu._nfc._handle_control(DEACTIVATED)         # as _drain() would
    assert emu.next_apdu(timeout=0.3) is None
    assert emu.last_event == "deactivated"


def test_run_drives_the_applet_and_survives_a_tap():
    applet = Type4NDEFApplet(MESSAGE)
    emu, sent, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    for command in (SELECT_NDEF_APP, SELECT_CC, b"\x00\xb0\x00\x00\x0f"):
        queue.append(data_packet(command))
        queue.append(CREDIT)
    queue.append(DEACTIVATED)
    assert emu.run(applet, timeout=0.3) == 3
    answers = [f[3:] for f in sent if f[0] & 0xE0 == 0x00]
    assert answers[0] == b"\x90\x00"
    assert answers[2] == applet.capability_container + b"\x90\x00"
    # The deactivation reset the applet, so nothing is selected any more.
    assert applet.process(b"\x00\xb0\x00\x00\x02") == b"\x69\x86"


def test_stop_returns_the_controller_to_idle():
    emu, sent, _ = emulator_with_frames([])
    emu.start()
    del sent[:]
    assert emu.stop() is True
    assert sent == [b"\x21\x06\x01\x00"]
    assert emu.stop() is False


def test_emulate_ndef_wires_the_applet_to_a_session():
    nfc, sent, _ = connected_driver([ACTIVATED_LISTEN,
                                     data_packet(SELECT_NDEF_APP), CREDIT])
    applet = nfc.emulate_ndef("https://example.com", timeout=0.2)
    assert applet.message.uri == "https://example.com"
    assert b"\x00\x00\x02\x90\x00" in sent           # answered the SELECT
    assert sent[-1] == b"\x21\x06\x01\x00"           # and then stopped


# -- the interface map switches between reader and card ---------------------

def test_switching_from_reader_to_card_re_maps_from_idle():
    nfc, sent, _ = connected_driver()
    nfc.start_discovery()
    assert sent[0] == pn7150._DISCOVER_MAP_RW
    nfc.start_discovery()                      # unchanged: no second map
    assert len([f for f in sent if f[:2] == b"\x21\x00"]) == 1

    del sent[:]
    CardEmulator(nfc).start()
    assert sent[0] == b"\x21\x06\x01\x00", "re-mapped without dropping to idle"
    assert sent[1] == pn7150._DISCOVER_MAP_CE


# -- the whole thing over a simulated bus -----------------------------------
#
# The tests above stub _read_frame/_write_frame. These do not: they put a fake
# NFCC on the I2C stub and let connect(), _raw_read(), _drain(), _read_data()
# and _send_data() run for real, so the transport is covered too.

class FakeNFCC:
    """A PN7150 at the I2C level.

    Answers the bring-up commands, activates on :meth:`tap`, then plays the
    reader's side: one C-APDU at a time, each sent only after the host's answer
    to the previous one has arrived in full, with a credit in between - which
    is exactly the ordering the one credit of UM10936 Table 5 forces.
    """

    def __init__(self, script=(), max_payload=255, segment_in=None):
        self.script = list(script)
        self.max_payload = max_payload
        self.segment_in = segment_in
        self.out = []                 # frames waiting for the host to read
        self.sent = []                # command frames the host wrote
        self.apdus = []               # complete R-APDUs the host answered with
        self.rx_packets = []          # payload size of every data packet in
        self.credits_given = 0
        self.activated = False
        self._rx = bytearray()
        self._current = None
        self._locked = False

    # -- the bus ---------------------------------------------------------

    def try_lock(self):
        if self._locked:
            return False
        self._locked = True
        return True

    def unlock(self):
        self._locked = False

    def deinit(self):
        pass

    def readfrom_into(self, address, buf, start=0, end=None):
        if start == 0:
            if not self.out:
                raise OSError("nothing to read")
            self._current = self.out.pop(0)
            buf[0:3] = self._current[:3]
        else:
            buf[start:end] = self._current[start:end]

    def writeto(self, address, buf):
        frame = bytes(buf)
        if frame[0] & 0xE0 == 0x00:
            return self._host_data(frame)
        self.sent.append(frame)
        self._host_command(frame)

    # -- the controller --------------------------------------------------

    def _host_command(self, frame):
        gid, oid = frame[0], frame[1]
        if gid == 0x20 and oid == 0x00:                       # CORE_RESET
            self.out.append(b"\x40\x00\x03\x00\x11\x01")
        elif gid == 0x20 and oid == 0x01:                     # CORE_INIT
            self.out.append(b"\x40\x01\x11\x00" + bytes(4) + b"\x00"
                            + bytes(8) + b"\x01\x02\x03")
        elif gid == 0x2F and oid == 0x02:                     # proprietary act
            self.out.append(b"\x4f\x02\x05\x00\x01\x02\x03\x04")
        elif gid == 0x20:
            self.out.append(bytes([0x40, oid, 0x02, 0x00, 0x00]))
        else:
            self.out.append(bytes([0x41, oid, 0x01, 0x00]))
            if oid == 0x06 and self.activated:                # RF_DEACTIVATE
                self.activated = False

    def _host_data(self, frame):
        self._rx += frame[3:]
        self.rx_packets.append(len(frame) - 3)
        # A credit comes back per *packet*, not per message: that is what makes
        # a segmented answer able to send its second half at all.
        self.credits_given += 1
        self.out.append(b"\x60\x06\x03\x01\x00\x01")           # CONN_CREDITS
        if frame[0] & 0x10:                                   # more to come
            return
        self.apdus.append(bytes(self._rx))
        self._rx = bytearray()
        self._next_command()

    # -- the reader ------------------------------------------------------

    def tap(self):
        """A phone arrives: field on, then this card gets activated."""
        self.activated = True
        self.out.append(b"\x61\x07\x01\x01")
        self.out.append(bytes([0x61, 0x05, 0x0A, 0x01,
                               pn7150.INTERFACE_ISO_DEP,
                               pn7150.PROTOCOL_ISO_DEP, TECH_NFC_A_LISTEN,
                               self.max_payload, 0x01, 0x02, 0x00, 0x00]))
        self._next_command()

    def _next_command(self):
        if not self.script:
            if self.activated:
                self.activated = False
                self.out.append(b"\x61\x06\x02\x00\x00")       # RF_DEACTIVATE
                self.out.append(b"\x61\x07\x01\x00")           # field off
            return
        c_apdu = self.script.pop(0)
        size = self.segment_in or len(c_apdu) or 1
        for i in range(0, len(c_apdu), size):
            chunk = c_apdu[i:i + size]
            last = i + size >= len(c_apdu)
            self.out.append(bytes([0x00 if last else 0x10, 0x00, len(chunk)])
                            + chunk)


class ReplayTag(Type4Tag):
    """A reader whose card is a recording of what the emulator answered."""

    def __init__(self, answers):
        Type4Tag.__init__(self, None, 0, pn7150.INTERFACE_ISO_DEP,
                          pn7150.PROTOCOL_ISO_DEP, TECH_NFC_A, b"", 255)
        self.answers = list(answers)
        self.log = []

    def transceive(self, data, timeout=0.5):
        self.log.append(bytes(data))
        return self.answers.pop(0) + b"\x00"


def driver_over(nfcc):
    nfc = pn7150.PN7150(scl="scl", sda="sda", irq="irq", ven="ven")
    nfc._i2c = nfcc
    nfc._irq = FakeIRQ(nfcc)
    return nfc


class FakeIRQ:
    def __init__(self, nfcc):
        self.nfcc = nfcc

    @property
    def value(self):
        return bool(self.nfcc.out)

    def deinit(self):
        pass


def reader_script(applet):
    """The exact C-APDUs this driver's own reader sends to read a Type 4 tag."""
    tag = LoopbackTag(applet)
    tag.read_ndef()
    return tag.log


@pytest.mark.parametrize("max_payload,segment_in", [(255, None), (32, 5)])
def test_a_whole_tap_over_a_simulated_bus(max_payload, segment_in):
    """connect(), listen bring-up, a phone reading the tag, and recovery."""
    big = NDEFMessage([NDEFRecord.uri("https://thefilip.com"),
                       NDEFRecord.text("x" * 200, "en")])
    script = reader_script(Type4NDEFApplet(big, max_size=2048))
    nfcc = FakeNFCC(script, max_payload=max_payload, segment_in=segment_in)
    nfc = driver_over(nfcc)
    assert nfc.connect() is True
    assert nfc.firmware_version == "01.02.03"

    applet = Type4NDEFApplet(big, max_size=2048)
    emulator = CardEmulator(nfc)
    emulator.start()
    nfcc.tap()
    served = emulator.run(applet, timeout=0.3)

    assert served == len(script), \
        "answered %d of %d commands" % (served, len(script))
    assert nfcc.script == [], "the reader never got through its script"
    # Every answer went out inside the payload size the controller negotiated,
    # and the controller was asked for a credit before each packet.
    assert max(nfcc.rx_packets) <= max_payload
    assert nfcc.credits_given == len(nfcc.rx_packets)
    if max_payload < 255:
        assert len(nfcc.rx_packets) > len(nfcc.apdus), "nothing was segmented"
    # And the recording reads back as the message that was served.
    replay = ReplayTag(nfcc.apdus)
    assert replay.read_ndef() == big
    assert replay.log == script
    # The tap ended, and the emulator went back to listening rather than
    # trying RF_DEACTIVATE(Sleep), which listen mode refuses.
    assert emulator.reader_active is False
    assert emulator.field_present is False
    assert b"\x21\x06\x01\x01" not in nfcc.sent
    assert nfcc.sent[-1] == bytes.fromhex("210303018001")


def test_two_taps_in_a_row_over_a_simulated_bus():
    """Tapping a second phone without a power cycle must still work."""
    applet = Type4NDEFApplet(MESSAGE)
    script = reader_script(Type4NDEFApplet(MESSAGE))
    nfcc = FakeNFCC(list(script), max_payload=32)
    nfc = driver_over(nfcc)
    nfc.connect()
    emulator = CardEmulator(nfc)
    emulator.start()

    nfcc.tap()
    assert emulator.run(applet, timeout=0.3) == len(script)
    first = list(nfcc.apdus)

    del nfcc.apdus[:]
    nfcc.script = list(script)
    nfcc.tap()
    assert emulator.run(applet, timeout=0.3) == len(script)
    assert nfcc.apdus == first, "the second tap answered differently"
    assert ReplayTag(nfcc.apdus).read_ndef() == MESSAGE


def test_a_phone_writing_over_a_simulated_bus():
    """writable=True, driven by this driver's own Type 4 write flow."""
    new = NDEFMessage([NDEFRecord.uri("https://written.example"),
                       NDEFRecord.text("by the phone")])
    rehearsal = Type4NDEFApplet(None, writable=True)
    writer = LoopbackTag(rehearsal)
    writer.write_ndef(new)

    written = []
    applet = Type4NDEFApplet(None, writable=True, on_write=written.append)
    nfcc = FakeNFCC(writer.log, max_payload=64)
    nfc = driver_over(nfcc)
    nfc.connect()
    emulator = CardEmulator(nfc)
    emulator.start()
    nfcc.tap()
    emulator.run(applet, timeout=0.3)

    assert written == [new]
    assert applet.message == new
    assert all(r.endswith(b"\x90\x00") for r in nfcc.apdus)


def test_one_loop_reads_a_tag_and_answers_a_phone():
    """also_poll: the poll half finds an NTAG, the listen half serves a phone,
    and neither leaves the controller in a state that stops the other."""
    applet = Type4NDEFApplet(MESSAGE)
    script = reader_script(Type4NDEFApplet(MESSAGE))
    nfcc = FakeNFCC(list(script))
    nfc = driver_over(nfcc)
    nfc.connect()
    seen = []
    emulator = CardEmulator(nfc, also_poll=True, on_tag=seen.append)
    emulator.start()

    # A Type 2 tag lands in the poll half of the loop.
    nfcc.out.append(b"\x61\x05\x14\x01\x01\x02\x00\xff\x01\x09"
                    + bytes.fromhex("440007049fa1d0c71b0300"))
    assert emulator.next_apdu(timeout=0.3) is None
    assert len(seen) == 1 and isinstance(seen[0], pn7150.Type2Tag)
    assert seen[0].uid_hex == "04:9f:a1:d0:c7:1b:03"

    # ...and then a phone taps, on the same loop, with no re-configuration.
    del nfcc.sent[:]
    nfcc.tap()
    assert emulator.run(applet, timeout=0.3) == len(script)
    assert ReplayTag(nfcc.apdus).read_ndef() == MESSAGE
    assert not [f for f in nfcc.sent if f[:2] == b"\x21\x00"], "re-mapped"


def test_an_activation_swallowed_by_drain_still_starts_the_session():
    """_drain() runs before every command write and has no events list to
    append to. If an activation met there were lost, the reader's first C-APDU
    would arrive with nobody listening."""
    emu, _, queue = emulator_with_frames([])
    emu.start()
    emu._nfc._handle_control(ACTIVATED_LISTEN)     # as _drain() would
    assert emu.reader_active is False              # not claimed yet
    queue.append(data_packet(SELECT_NDEF_APP))
    assert emu.next_apdu(timeout=2) == SELECT_NDEF_APP
    assert emu.reader_active is True


def test_wait_for_reader_also_claims_a_drained_activation():
    emu, _, _ = emulator_with_frames([])
    emu.start()
    emu._nfc._handle_control(ACTIVATED_LISTEN)
    assert emu.wait_for_reader(timeout=0.3) is True


def test_a_reader_arriving_during_teardown_is_not_dropped():
    """Deactivate and re-activate both swallowed by one _drain(): the new
    session must survive, not be restarted out from under the reader."""
    emu, sent, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    del sent[:]
    emu._nfc._handle_control(DEACTIVATED)
    emu._nfc._handle_control(ACTIVATED_LISTEN)
    assert emu.next_apdu(timeout=0.3) is None      # the first session ended
    assert emu.last_event == "deactivated"
    assert not [f for f in sent if f[:2] == b"\x21\x03"], "re-discovered"
    queue.append(data_packet(SELECT_CC))
    assert emu.next_apdu(timeout=2) == SELECT_CC   # the second one is live


def test_a_segmented_apdu_split_across_two_reads_is_still_reassembled():
    """_read_data() returns every 100ms while next_apdu() waits; a reader slow
    between segments must not turn one C-APDU into two."""
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    queue.append(data_packet(SELECT_NDEF_APP[:6], pbf=True))
    assert emu._nfc._read_data(0.05) is None       # the tail has not arrived
    assert bytes(emu._nfc._rx_partial) == SELECT_NDEF_APP[:6]
    queue.append(data_packet(SELECT_NDEF_APP[6:]))
    assert emu.next_apdu(timeout=2) == SELECT_NDEF_APP


def test_a_deactivation_mid_message_throws_the_half_away():
    emu, _, queue = emulator_with_frames([])
    emu.start()
    queue.append(ACTIVATED_LISTEN)
    emu.wait_for_reader(timeout=2)
    queue.append(data_packet(b"\x00\xa4\x04", pbf=True))
    queue.append(DEACTIVATED)
    assert emu.next_apdu(timeout=2) is None
    assert bytes(emu._nfc._rx_partial) == b""

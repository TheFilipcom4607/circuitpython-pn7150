# SPDX-License-Identifier: MIT
"""
`pn7150` - a friendlier CircuitPython driver for the NXP PN7150 NFC controller.

Quick start::

    import board
    from pn7150 import PN7150

    nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)
    with nfc:
        for tag in nfc.scan():
            print(tag)
            if tag.ndef:
                print("  ->", tag.ndef.value)

Design notes
------------
* Everything raises a subclass of :class:`PN7150Error` instead of asserting.
* :class:`Tag` objects know their own type and expose ``uid``/``ndef`` directly;
  tag-type specifics live in subclasses you rarely need to name yourself.
* NDEF is parsed *and* built, so writing a URL to a tag is one call.
* The bus defaults to 100 kHz. On boards without external I2C pull-ups (the
  iLabs Challenger RP2040 NFC among them) 400 kHz will not work.
"""

from time import sleep
from micropython import const
from supervisor import ticks_ms
from digitalio import DigitalInOut, Pull
import busio

__version__ = "1.0.0"

_TICKS_PERIOD = const(1 << 29)

# ---------------------------------------------------------------- exceptions


class PN7150Error(Exception):
    """Base class for every error this driver raises."""


class NotConnectedError(PN7150Error):
    """The controller has not completed :meth:`PN7150.connect` yet."""


class CommandError(PN7150Error):
    """The controller rejected a command or answered unexpectedly."""


class TagLostError(PN7150Error):
    """The tag left the field during an exchange."""


class TagTimeoutError(PN7150Error):
    """No answer within the timeout.

    (Not an ``OSError`` subclass: CircuitPython rejects multiple inheritance
    from two builtin types with different instance layouts.)"""


class NotSupportedError(PN7150Error):
    """The operation is not available for this tag technology."""


class NDEFError(PN7150Error):
    """The NDEF data on the tag is malformed."""


# ----------------------------------------------------------------- constants

# NCI RF protocols
PROTOCOL_UNDETERMINED = const(0x00)
PROTOCOL_T1T = const(0x01)
PROTOCOL_T2T = const(0x02)
PROTOCOL_T3T = const(0x03)
PROTOCOL_ISO_DEP = const(0x04)
PROTOCOL_NFC_DEP = const(0x05)
PROTOCOL_T5T = const(0x06)
PROTOCOL_MIFARE = const(0x80)

PROTOCOL_NAMES = {
    PROTOCOL_UNDETERMINED: "Undetermined",
    PROTOCOL_T1T: "Type 1 (Topaz/Jewel)",
    PROTOCOL_T2T: "Type 2 (NTAG/Ultralight)",
    PROTOCOL_T3T: "Type 3 (FeliCa)",
    PROTOCOL_ISO_DEP: "Type 4 (ISO-DEP/DESFire)",
    PROTOCOL_NFC_DEP: "NFC-DEP (peer to peer)",
    PROTOCOL_T5T: "Type 5 (ISO15693)",
    PROTOCOL_MIFARE: "MIFARE Classic",
}

# NCI RF technology and mode (poll modes only; this driver is reader/writer)
TECH_NFC_A = const(0x00)
TECH_NFC_B = const(0x01)
TECH_NFC_F = const(0x02)
TECH_NFC_V = const(0x06)

TECH_NAMES = {
    TECH_NFC_A: "NFC-A",
    TECH_NFC_B: "NFC-B",
    TECH_NFC_F: "NFC-F",
    0x03: "NFC-A (active)",
    0x05: "NFC-F (active)",
    TECH_NFC_V: "NFC-V",
}

# NCI RF interfaces
INTERFACE_FRAME = const(0x01)
INTERFACE_ISO_DEP = const(0x02)
INTERFACE_NFC_DEP = const(0x03)
INTERFACE_TAG = const(0x80)

INTERFACE_NAMES = {
    0x00: "NFCEE Direct",
    INTERFACE_FRAME: "Frame",
    INTERFACE_ISO_DEP: "ISO-DEP",
    INTERFACE_NFC_DEP: "NFC-DEP",
    INTERFACE_TAG: "Tag/MIFARE",
}

STATUS_NAMES = {
    0x00: "OK",
    0x01: "REJECTED",
    0x02: "RF_FRAME_CORRUPTED",
    0x03: "FAILED",
    0x04: "NOT_INITIALIZED",
    0x05: "SYNTAX_ERROR",
    0x06: "SEMANTIC_ERROR",
    0x09: "INVALID_PARAM",
    0x0A: "MESSAGE_SIZE_EXCEEDED",
    # Discovery errors are 0xAx, RF interface errors 0xBx (NCI 1.0 table 94).
    0xA0: "DISCOVERY_ALREADY_STARTED",
    0xA1: "DISCOVERY_TARGET_ACTIVATION_FAILED",
    0xA2: "DISCOVERY_TEAR_DOWN",
    0xB0: "RF_TRANSMISSION_ERROR",
    0xB1: "RF_PROTOCOL_ERROR",
    0xB2: "RF_TIMEOUT_ERROR",
    0xB3: "RF_UNEXPECTED_DATA",
}

STATUS_DISCOVERY_ALREADY_STARTED = const(0xA0)

# Mifare Classic well-known keys
KEY_DEFAULT = b"\xff\xff\xff\xff\xff\xff"
KEY_NDEF = b"\xd3\xf7\xd3\xf7\xd3\xf7"

# Embedded key slots the PN7150 knows about (used by the 3-byte AUTH form)
_MFC_KEY_SLOT_DEFAULT = const(0x00)
_MFC_KEY_SLOT_NDEF = const(0x01)


def hexlify(data, sep=":"):
    """``b'\\x01\\x02'`` -> ``'01:02'``. Handy for printing UIDs."""
    return sep.join("%02x" % b for b in data)


# ---------------------------------------------------------------------- NDEF

TNF_EMPTY = const(0x00)
TNF_WELL_KNOWN = const(0x01)
TNF_MIME = const(0x02)
TNF_ABSOLUTE_URI = const(0x03)
TNF_EXTERNAL = const(0x04)
TNF_UNKNOWN = const(0x05)
TNF_UNCHANGED = const(0x06)

# NFC Forum URI Record Type Definition, table 3.
_URI_PREFIXES = (
    "", "http://www.", "https://www.", "http://", "https://", "tel:",
    "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://",
    "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:",
    "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:",
    "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
    "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
    "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
)


class NDEFRecord:
    """A single NDEF record.

    The useful bits are :attr:`kind` (``"uri"``, ``"text"``, ``"mime"``,
    ``"external"`` or ``"unknown"``) and :attr:`value`, which is already
    decoded: a ``str`` for URI and text records, ``bytes`` otherwise.
    """

    def __init__(self, tnf, rtype, payload, rid=b""):
        self.tnf = tnf
        self.type = rtype
        self.payload = payload
        self.id = rid

    @property
    def kind(self):
        if self.tnf == TNF_WELL_KNOWN and self.type == b"U":
            return "uri"
        if self.tnf == TNF_WELL_KNOWN and self.type == b"T":
            return "text"
        if self.tnf == TNF_MIME:
            return "mime"
        if self.tnf == TNF_ABSOLUTE_URI:
            return "uri"
        if self.tnf == TNF_EXTERNAL:
            return "external"
        return "unknown"

    @property
    def value(self):
        """The decoded contents: ``str`` for uri/text, else raw ``bytes``."""
        kind = self.kind
        if kind == "uri":
            if self.tnf == TNF_ABSOLUTE_URI:
                return _to_str(self.payload)
            if not self.payload:
                return ""
            code = self.payload[0]
            prefix = _URI_PREFIXES[code] if code < len(_URI_PREFIXES) else ""
            return prefix + _to_str(self.payload[1:])
        if kind == "text":
            if not self.payload:
                return ""
            lang_len = self.payload[0] & 0x3F
            return _to_str(self.payload[1 + lang_len:])
        return self.payload

    @property
    def language(self):
        """Language code of a text record, else ``None``."""
        if self.kind != "text" or not self.payload:
            return None
        lang_len = self.payload[0] & 0x3F
        return _to_str(self.payload[1:1 + lang_len])

    def __repr__(self):
        val = self.value
        if isinstance(val, bytes):
            val = hexlify(val[:12]) + ("..." if len(val) > 12 else "")
        return "<NDEFRecord %s %r>" % (self.kind, val)

    def to_bytes(self, first=True, last=True):
        """Encode this record. ``first``/``last`` set the MB/ME flags."""
        flags = self.tnf & 0x07
        if first:
            flags |= 0x80
        if last:
            flags |= 0x40
        if self.id:
            flags |= 0x08
        short = len(self.payload) < 256
        if short:
            flags |= 0x10
        out = bytearray([flags, len(self.type)])
        if short:
            out.append(len(self.payload))
        else:
            n = len(self.payload)
            out += bytes([(n >> 24) & 0xFF, (n >> 16) & 0xFF,
                          (n >> 8) & 0xFF, n & 0xFF])
        if self.id:
            out.append(len(self.id))
        out += self.type
        out += self.id
        out += self.payload
        return bytes(out)

    # -- constructors ----------------------------------------------------

    @classmethod
    def uri(cls, uri):
        """Build a URI record, choosing the shortest prefix code."""
        best_i, best_p = 0, ""
        for i, pre in enumerate(_URI_PREFIXES):
            if pre and uri.startswith(pre) and len(pre) > len(best_p):
                best_i, best_p = i, pre
        return cls(TNF_WELL_KNOWN, b"U",
                   bytes([best_i]) + uri[len(best_p):].encode("utf-8"))

    @classmethod
    def text(cls, text, language="en"):
        """Build a UTF-8 text record."""
        lang = language.encode("utf-8")
        return cls(TNF_WELL_KNOWN, b"T",
                   bytes([len(lang) & 0x3F]) + lang + text.encode("utf-8"))

    @classmethod
    def mime(cls, mime_type, data):
        """Build a MIME record, e.g. ``mime("image/png", data)``."""
        return cls(TNF_MIME, mime_type.encode("utf-8"), bytes(data))


class NDEFMessage:
    """A list of :class:`NDEFRecord`, with shortcuts for the common case."""

    def __init__(self, records=None):
        self.records = list(records) if records else []

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        return iter(self.records)

    def __getitem__(self, i):
        return self.records[i]

    @property
    def value(self):
        """Decoded value of the first record, or ``None`` if empty."""
        return self.records[0].value if self.records else None

    @property
    def uri(self):
        """First URI record's value, or ``None``."""
        for rec in self.records:
            if rec.kind == "uri":
                return rec.value
        return None

    @property
    def text(self):
        """First text record's value, or ``None``."""
        for rec in self.records:
            if rec.kind == "text":
                return rec.value
        return None

    def __repr__(self):
        return "<NDEFMessage %r>" % (self.records,)

    def to_bytes(self):
        """Encode the whole message."""
        out = bytearray()
        n = len(self.records)
        for i, rec in enumerate(self.records):
            out += rec.to_bytes(first=(i == 0), last=(i == n - 1))
        return bytes(out)

    @classmethod
    def from_uri(cls, uri):
        return cls([NDEFRecord.uri(uri)])

    @classmethod
    def from_text(cls, text, language="en"):
        return cls([NDEFRecord.text(text, language)])

    @classmethod
    def from_bytes(cls, data):
        """Parse a raw NDEF message (no TLV wrapper)."""
        records = []
        i = 0
        data = bytes(data)
        while i < len(data):
            flags = data[i]
            tnf = flags & 0x07
            short = bool(flags & 0x10)
            has_id = bool(flags & 0x08)
            i += 1
            if i >= len(data):
                break
            type_len = data[i]
            i += 1
            if short:
                if i >= len(data):
                    break
                payload_len = data[i]
                i += 1
            else:
                if i + 4 > len(data):
                    break
                payload_len = (data[i] << 24) | (data[i + 1] << 16) | \
                              (data[i + 2] << 8) | data[i + 3]
                i += 4
            id_len = 0
            if has_id:
                if i >= len(data):
                    break
                id_len = data[i]
                i += 1
            rtype = data[i:i + type_len]
            i += type_len
            rid = data[i:i + id_len]
            i += id_len
            payload = data[i:i + payload_len]
            i += payload_len
            if tnf != TNF_EMPTY:
                records.append(NDEFRecord(tnf, rtype, payload, rid))
            if flags & 0x40:      # ME - message end
                break
        if not records:
            raise NDEFError("no NDEF records found")
        return cls(records)


def _to_str(data):
    try:
        return str(data, "utf-8")
    except (UnicodeError, ValueError):
        return "".join(chr(c) if 32 <= c < 127 else "." for c in data)


def _ndef_from_tlv(data):
    """Walk a Type 2/Type 5 TLV area and return the NDEF message inside."""
    i = 0
    data = bytes(data)
    while i < len(data):
        tag = data[i]
        if tag == 0x00:                      # NULL TLV, skip
            i += 1
            continue
        if tag == 0xFE:                      # terminator
            return None
        if i + 1 >= len(data):
            return None
        length = data[i + 1]
        i += 2
        if length == 0xFF:                   # 3-byte length form
            if i + 2 > len(data):
                return None
            length = (data[i] << 8) | data[i + 1]
            i += 2
        value = data[i:i + length]
        if tag == 0x03:                      # NDEF message TLV
            if len(value) < length:
                raise NDEFError(
                    "NDEF message truncated: TLV says %d bytes, read %d "
                    "(read more pages)" % (length, len(value)))
            return NDEFMessage.from_bytes(value)
        i += length
    return None


def _ndef_to_tlv(message):
    """Wrap an NDEF message in a Type 2 TLV block, with terminator."""
    payload = message.to_bytes()
    if len(payload) < 0xFF:
        head = bytes([0x03, len(payload)])
    else:
        head = bytes([0x03, 0xFF, (len(payload) >> 8) & 0xFF, len(payload) & 0xFF])
    return head + payload + b"\xfe"


# ----------------------------------------------------------------- tag types


class Tag:
    """A tag currently in the field.

    Instances come from :meth:`PN7150.scan` or :meth:`PN7150.read_tag`; the
    right subclass is chosen for you from the activated protocol.
    """

    def __init__(self, nfc, disc_id, interface, protocol, tech, params):
        self._nfc = nfc
        self.discovery_id = disc_id
        self.interface = interface
        self.protocol = protocol
        self.technology = tech
        self.rf_params = params
        self.sens_res = None
        self.sel_res = None
        self.dsfid = None
        self.bitrate = None
        self.pmm = None
        self.uid = self._parse_uid(tech, params)
        self._ndef = None
        self._ndef_read = False

    def _parse_uid(self, tech, p):
        try:
            if tech == TECH_NFC_A:
                # SENS_RES(2) NFCID1_LEN(1) NFCID1(n) SEL_RES_LEN(1) SEL_RES(n)
                self.sens_res = bytes(p[0:2])
                n = p[2]
                uid = bytes(p[3:3 + n])
                if len(p) > 3 + n and p[3 + n]:
                    self.sel_res = p[4 + n]
                return uid
            if tech == TECH_NFC_B:
                # SENSB_RES_LEN(1) SENSB_RES(n); NFCID0 is bytes 1..4
                n = p[0]
                sensb = bytes(p[1:1 + n])
                self.sens_res = sensb
                return sensb[1:5]
            if tech == TECH_NFC_F:
                # BIT_RATE(1) SENSF_RES_LEN(1) SENSF_RES(n).
                # Two traps here. NFC-F is the only technology whose parameters
                # do not start with a length, and NCI strips the leading 0x01
                # response code from SENSF_RES: the field is n = 16 or 18 bytes
                # of IDm(8) + PMm(8) [+ RD(2)], NOT 01 + IDm + PMm. Skipping a
                # byte yields an IDm that is off by one, and the card then
                # silently ignores every command addressed to it.
                self.bitrate = p[0]
                n = p[1]
                sensf = bytes(p[2:2 + n])
                self.sens_res = sensf
                self.pmm = sensf[8:16]
                return sensf[0:8]
            if tech == TECH_NFC_V:
                # AFI(1) DSFID(1) UID(8, LSB first)
                self.dsfid = p[1]
                # NFC-V UIDs arrive LSB first. reversed() over a
                # bytes object is supported; [::-1] is not.
                return bytes(reversed(bytes(p[2:10])))
        except IndexError:
            pass
        return b""

    @property
    def uid_hex(self):
        """UID as ``'04:8c:e8:...'``."""
        return hexlify(self.uid)

    @property
    def type(self):
        """Human-readable tag type, e.g. ``'Type 2 (NTAG/Ultralight)'``."""
        return PROTOCOL_NAMES.get(self.protocol, "Unknown 0x%02x" % self.protocol)

    @property
    def technology_name(self):
        return TECH_NAMES.get(self.technology, "0x%02x" % self.technology)

    @property
    def ndef(self):
        """The tag's :class:`NDEFMessage`, or ``None``.

        Read lazily on first access and cached. Returns ``None`` rather than
        raising when the tag simply holds no NDEF data.
        """
        if not self._ndef_read:
            self._ndef_read = True
            try:
                self._ndef = self.read_ndef()
            except (PN7150Error, IndexError):
                self._ndef = None
        return self._ndef

    def read_ndef(self):
        """Read and parse NDEF. Subclasses implement this per technology."""
        raise NotSupportedError(
            "NDEF reading is not implemented for %s" % self.type)

    def write_ndef(self, message):
        raise NotSupportedError(
            "NDEF writing is not implemented for %s" % self.type)

    def transceive(self, data, timeout=0.5):
        """Send a raw command to the tag and return its answer."""
        return self._nfc._exchange(bytes(data), timeout)

    def __str__(self):
        out = "%s  %s  UID %s" % (self.type, self.technology_name,
                                  self.uid_hex or "(none)")
        msg = self.ndef
        if msg is not None and len(msg):
            val = msg.value
            if isinstance(val, bytes):
                val = hexlify(val[:8])
            out += "\n  NDEF %s: %s" % (msg.records[0].kind, val)
        return out

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.uid_hex)

    def dump(self):
        """A multi-line description of everything known about the tag."""
        lines = [
            "Tag type   : %s" % self.type,
            "Technology : %s" % self.technology_name,
            "Interface  : %s" % INTERFACE_NAMES.get(self.interface,
                                                    "0x%02x" % self.interface),
            "UID        : %s (%d bytes)" % (self.uid_hex, len(self.uid)),
        ]
        if self.sens_res is not None:
            lines.append("SENS_RES   : %s" % hexlify(self.sens_res))
        if self.sel_res is not None:
            lines.append("SEL_RES    : %02x" % self.sel_res)
        if self.dsfid is not None:
            lines.append("DSFID      : %02x" % self.dsfid)
        msg = self.ndef
        if msg is None:
            lines.append("NDEF       : none")
        else:
            for rec in msg:
                val = rec.value
                if isinstance(val, bytes):
                    val = hexlify(val[:24])
                    if len(rec.payload) > 24:
                        val += "... (%d bytes)" % len(rec.payload)
                lines.append("NDEF %-6s: %s" % (rec.kind, val))
        return "\n".join(lines)


class Type2Tag(Tag):
    """NTAG / MIFARE Ultralight. Pages are 4 bytes; a READ returns 4 pages."""

    PAGE_SIZE = 4

    def read(self, page):
        """READ command: returns 16 bytes (4 consecutive pages)."""
        resp = self.transceive(bytes([0x30, page & 0xFF]))
        payload, _ = _split_status(resp, "read of page %d" % page)
        return payload

    @property
    def capacity(self):
        """Usable data bytes, from the capability container in page 3."""
        try:
            cc = self.read(3)[:4]
        except PN7150Error:
            return 48
        if cc[0] != 0xE1:
            return 48
        return cc[2] * 8

    def write(self, page, data):
        """WRITE one 4-byte page. Refuses pages 0-3 (UID and lock bytes)."""
        data = bytes(data)
        if len(data) != 4:
            raise ValueError("a Type 2 page is exactly 4 bytes")
        if page < 4:
            raise ValueError(
                "refusing to write page %d: pages 0-3 hold the UID, lock bits "
                "and capability container" % page)
        resp = self.transceive(bytes([0xA2, page & 0xFF]) + data)
        if resp and resp[-1] not in (0x00, 0x0A):
            raise CommandError("write of page %d failed (0x%02x)"
                               % (page, resp[-1]))
        return True

    def read_memory(self, start=4, pages=16):
        """Read a run of pages, returning one flat ``bytes``."""
        out = bytearray()
        page = start
        while page < start + pages:
            try:
                blk = self.read(page)
            except (CommandError, TagLostError, TagTimeoutError):
                break
            if not blk:
                break
            out += blk
            page += 4
        return bytes(out)

    def read_ndef(self):
        # Read only as far as the message needs, bounded by the tag's own
        # declared capacity. Running off the end makes the tag stop answering.
        return _read_ndef_area(self.read, 4, 4, self.capacity)

    def write_ndef(self, message):
        """Write an :class:`NDEFMessage` starting at page 4."""
        if isinstance(message, str):
            message = NDEFMessage.from_uri(message) if "://" in message \
                else NDEFMessage.from_text(message)
        payload = _ndef_to_tlv(message)
        payload += b"\x00" * (-len(payload) % 4)
        for i in range(0, len(payload), 4):
            self.write(4 + i // 4, payload[i:i + 4])
        self._ndef = message
        self._ndef_read = True
        return True


class Type4Tag(Tag):
    """ISO-DEP / ISO 14443-4 (DESFire, most payment and ID cards).

    Talks APDUs. :meth:`read_ndef` runs the NFC Forum Type 4 flow: select the
    NDEF application, read the capability container, then the NDEF file.
    """

    def apdu(self, data, timeout=1.5):
        """Send an APDU; returns ``(response_bytes, status_word)``.

        The default timeout is longer than for other technologies: ISO-DEP
        cards may ask for waiting-time extensions, and a real DESFire was
        observed taking over 0.5s just to answer SELECT.
        """
        resp = self.transceive(bytes(data), timeout)
        resp, _ = _split_status(resp, "APDU")
        if len(resp) < 2:
            raise CommandError("short APDU response: %s" % hexlify(resp))
        return bytes(resp[:-2]), (resp[-2] << 8) | resp[-1]

    def select_ndef_application(self):
        """Select the NDEF application (tries the v2.0 AID, then v1.0)."""
        for aid in (b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00",
                    b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x00"):
            try:
                _, sw = self.apdu(aid)
            except CommandError:
                continue
            if sw == 0x9000:
                return True
        return False

    def select_file(self, file_id):
        _, sw = self.apdu(b"\x00\xa4\x00\x0c\x02" + bytes(file_id))
        return sw == 0x9000

    def read_binary(self, offset, length):
        data, sw = self.apdu(bytes([0x00, 0xB0, (offset >> 8) & 0xFF,
                                    offset & 0xFF, length & 0xFF]))
        if sw != 0x9000:
            raise CommandError("READ BINARY failed, SW=%04x" % sw)
        return data

    def read_ndef(self):
        if not self.select_ndef_application():
            return None
        if not self.select_file(b"\xe1\x03"):     # capability container
            return None
        cc = self.read_binary(0, 15)
        if len(cc) < 15:
            return None
        # CC bytes 9..10 hold the NDEF file id, 11..12 its max size.
        file_id = cc[9:11]
        if not self.select_file(file_id):
            return None
        size = self.read_binary(0, 2)             # NLEN, big endian
        nlen = (size[0] << 8) | size[1]
        if nlen == 0:
            return None
        data = bytearray()
        offset = 2
        while len(data) < nlen:
            chunk = min(0xF0, nlen - len(data))
            data += self.read_binary(offset, chunk)
            offset += chunk
        return NDEFMessage.from_bytes(bytes(data[:nlen]))


class MifareClassicTag(Tag):
    """MIFARE Classic.

    Blocks are 16 bytes, grouped in sectors of 4 blocks, and every sector must
    be authenticated before it can be read. The PN7150 holds the two standard
    keys itself, so :meth:`authenticate` needs no key material for ordinary
    NDEF-formatted or factory-default tags.
    """

    BLOCK_SIZE = 16

    def authenticate(self, sector, key=KEY_DEFAULT, key_b=False):
        """Authenticate a sector.

        ``key`` may be :data:`KEY_DEFAULT`, :data:`KEY_NDEF` (both are stored in
        the controller and need no transfer) or any 6-byte key.

        Authenticate **once per tap**. A card refuses a second authentication
        with a different key inside the same activation (status 0x03), and the
        failure poisons the session, so reads that were working start failing
        too. To use another key, let the tag leave the field and re-present it.
        """
        if key == KEY_DEFAULT:
            cmd = bytes([0x40, sector & 0xFF, _MFC_KEY_SLOT_DEFAULT])
        elif key == KEY_NDEF:
            cmd = bytes([0x40, sector & 0xFF, _MFC_KEY_SLOT_NDEF])
        else:
            key = bytes(key)
            if len(key) != 6:
                raise ValueError("a MIFARE key is exactly 6 bytes")
            cmd = bytes([0x40, sector & 0xFF, 0x11 if key_b else 0x10]) + key
        resp = self.transceive(cmd)
        if not resp or resp[-1] != 0x00:
            raise CommandError(
                "authentication of sector %d failed%s" %
                (sector, "" if not resp else " (0x%02x)" % resp[-1]))
        return True

    def read_block(self, block):
        """Read one 16-byte block. Its sector must be authenticated first.

        The controller answers ``10 <16 data bytes> <status>``: a one-byte echo
        of the MFC command prefix, the data, then the status. Verified against
        hardware, where MAD block 1 came back as
        ``10 c0 01 03 e1 00.. 00`` (CRC, info, NDEF AID 03e1).
        """
        resp = self.transceive(bytes([0x10, 0x30, block & 0xFF]))
        body, _ = _split_status(resp, "read of block %d" % block)
        if len(body) == 17 and body[0] == 0x10:
            body = body[1:]
        return bytes(body)

    def read_sector(self, sector, key=KEY_DEFAULT):
        """Authenticate then read all four blocks of a sector."""
        self.authenticate(sector, key)
        first = sector * 4
        return b"".join(self.read_block(first + i) for i in range(4))

    def read_ndef(self):
        # NDEF-formatted Classic tags keep their data from sector 1 onward,
        # under the NFC Forum key.
        try:
            self.authenticate(1, KEY_NDEF)
        except CommandError:
            return None
        data = bytearray()
        block = 4
        while block < 64:
            if block % 4 == 3:        # sector trailer, skip
                block += 1
                continue
            if block % 4 == 0 and block > 4:
                try:
                    self.authenticate(block // 4, KEY_NDEF)
                except CommandError:
                    break
            try:
                data += self.read_block(block)
            except (CommandError, TagLostError):
                break
            block += 1
            if len(data) >= 48 and bytes(data).find(b"\xfe") >= 0:
                break
        return _ndef_from_tlv(bytes(data))


class Type5Tag(Tag):
    """ISO 15693 / NFC-V vicinity tags."""

    BLOCK_SIZE = 4

    def read_block(self, block):
        """READ SINGLE BLOCK. Flags 0x02 = high data rate, no option.

        The answer is ``<flags> <4 data bytes> <status>``; a non-zero flags
        byte means the tag reported an error.
        """
        resp = self.transceive(bytes([0x02, 0x20, block & 0xFF]))
        payload, _ = _split_status(resp, "read of block %d" % block)
        if not payload:
            raise CommandError("empty answer reading block %d" % block)
        if payload[0] != 0x00:
            raise CommandError("read of block %d failed (flags 0x%02x)"
                               % (block, payload[0]))
        return bytes(payload[1:])

    def read_memory(self, start=0, blocks=16):
        out = bytearray()
        for b in range(start, start + blocks):
            try:
                out += self.read_block(b)
            except (CommandError, TagLostError, TagTimeoutError):
                break
        return bytes(out)

    @property
    def capability_container(self):
        """Block 0 holds the Type 5 CC: ``E1 <ver/access> <MLEN> <features>``."""
        return self.read_block(0)

    def read_ndef(self):
        # Block 0 is the capability container, NOT part of the TLV area -
        # parsing from block 0 makes the CC look like a bogus TLV. The real
        # data starts at block 1 (CC is 4 bytes on these tags).
        try:
            cc = self.capability_container
        except PN7150Error:
            return _read_ndef_area(self.read_block, 0, 1, 128)
        if len(cc) >= 3 and cc[0] in (0xE1, 0xE2):
            limit = cc[2] * 8 or 128
            return _read_ndef_area(self.read_block, 1, 1, limit)
        return _read_ndef_area(self.read_block, 0, 1, 128)


# FeliCa Status Flag 2 values (JIS X 6319-4).
_FELICA_ERRORS = {
    0xA1: "number of services error",
    0xA2: "number of blocks error",
    0xA3: "block list element error",
    0xA4: "access mode error",
    0xA5: "service code list error",
    0xA6: "service not present on this card",
    0xA7: "service code list error",
    0xA8: "block number out of range",
    0xB1: "memory error",
    0xB2: "memory warning",
}


def _felica_error(sf2):
    return _FELICA_ERRORS.get(sf2, "unknown error 0x%02x" % sf2)


class Type3Tag(Tag):
    """FeliCa (NFC-F), the NFC Forum Type 3 tag.

    Reads use the FeliCa CHECK command against the NDEF service (0x000B).
    Unlike Type 2 and Type 5, the data is *not* TLV-wrapped: the attribute
    information block gives the NDEF length directly.
    """

    BLOCK_SIZE = 16
    SERVICE_NDEF_RO = const(0x000B)
    SERVICE_NDEF_RW = const(0x0009)

    @property
    def idm(self):
        """The card's IDm (identical to NFCID2)."""
        return self.uid

    def check(self, block, service=SERVICE_NDEF_RO):
        """FeliCa CHECK: read one 16-byte block.

        Frame is ``LEN 06 <IDm x8> 01 <service LE> 01 80 <block>``; the answer
        is ``LEN 07 <IDm x8> SF1 SF2 <n blocks> <16 data bytes> <status>``.
        """
        if len(self.idm) != 8:
            raise CommandError("no IDm for this card (got %d bytes)"
                               % len(self.idm))
        cmd = bytearray(16)
        cmd[0] = 0x10                       # frame length, including this byte
        cmd[1] = 0x06                       # CHECK
        cmd[2:10] = self.idm
        cmd[10] = 0x01                      # one service
        cmd[11] = service & 0xFF            # service code, little endian
        cmd[12] = (service >> 8) & 0xFF
        cmd[13] = 0x01                      # one block
        cmd[14] = 0x80                      # 2-byte block list element
        cmd[15] = block & 0xFF
        resp = self.transceive(bytes(cmd))
        payload, _ = _split_status(resp, "CHECK of block %d" % block)
        if len(payload) < 13:
            raise CommandError("short CHECK response: %s" % hexlify(payload))
        if payload[1] != 0x07:
            raise CommandError("unexpected FeliCa response code 0x%02x"
                               % payload[1])
        if payload[10] != 0x00 or payload[11] != 0x00:
            raise CommandError(
                "CHECK of block %d rejected: %s (SF1=0x%02x SF2=0x%02x)"
                % (block, _felica_error(payload[11]),
                   payload[10], payload[11]))
        return bytes(payload[13:13 + 16])

    @property
    def attribute_block(self):
        """Block 0: the Attribute Information Block."""
        return self.check(0)

    def attributes(self):
        """Decode block 0 into a dict: version, capacity, writability, length."""
        b = self.attribute_block
        return {
            "version": "%d.%d" % (b[0] >> 4, b[0] & 0x0F),
            "blocks_per_read": b[1],
            "blocks_per_write": b[2],
            "max_blocks": (b[3] << 8) | b[4],
            "writing": b[9] == 0x0F,
            "writable": b[10] == 0x01,
            "ndef_length": (b[11] << 16) | (b[12] << 8) | b[13],
        }

    def has_ndef_service(self):
        """True if the card exposes the NFC Forum NDEF service (0x000B).

        Transit and payment cards generally do not: they answer CHECK with
        SF2 = 0xA6 (service not present).
        """
        try:
            self.check(0)
        except CommandError:
            return False
        return True

    def read_ndef(self):
        attr = self.attribute_block
        # Ln is a 3-byte big-endian length at bytes 11..13. (The NXP Arduino
        # reference shifts the middle byte by 16 instead of 8; that is a bug,
        # and it is not reproduced here.)
        length = (attr[11] << 16) | (attr[12] << 8) | attr[13]
        max_blocks = (attr[3] << 8) | attr[4]
        if length == 0:
            return None
        if max_blocks and length > max_blocks * self.BLOCK_SIZE:
            raise NDEFError(
                "attribute block claims %d bytes but the card holds at most %d"
                % (length, max_blocks * self.BLOCK_SIZE))
        data = bytearray()
        block = 1
        while len(data) < length:
            try:
                data += self.check(block)
            except (CommandError, TagLostError, TagTimeoutError):
                break
            block += 1
        if len(data) < length:
            raise NDEFError("NDEF truncated: wanted %d bytes, read %d"
                            % (length, len(data)))
        # Type 3 data is a bare NDEF message, with no TLV wrapper.
        return NDEFMessage.from_bytes(bytes(data[:length]))


_TAG_CLASSES = {
    PROTOCOL_T2T: Type2Tag,
    PROTOCOL_ISO_DEP: Type4Tag,
    PROTOCOL_MIFARE: MifareClassicTag,
    PROTOCOL_T5T: Type5Tag,
    PROTOCOL_T3T: Type3Tag,
}


def _split_status(resp, what="tag command"):
    """Split a tag response into ``(payload, status)``.

    Every RF interface appends exactly one status byte. Measured on hardware:
    a Type 2 READ returns 17 bytes (16 data + status), a MIFARE read 18
    (0x10 prefix + 16 data + status) and an ISO15693 read 6 (flags + 4 data +
    status). Raises on a non-zero status.
    """
    resp = bytes(resp)
    if not resp:
        raise CommandError("%s: empty response" % what)
    status = resp[-1]
    if status != 0x00:
        raise CommandError("%s failed (status 0x%02x)" % (what, status))
    return resp[:-1], status


def _read_ndef_area(reader, first_block, blocks_per_read, limit):
    """Read a TLV area a chunk at a time, stopping as soon as the NDEF message
    is complete. Avoids reading past the end of tag memory, which makes tags
    stop answering."""
    data = bytearray()
    block = first_block
    while len(data) < limit:
        try:
            chunk = reader(block)
        except (CommandError, TagLostError, TagTimeoutError):
            break
        if not chunk:
            break
        data += chunk
        block += blocks_per_read
        try:
            msg = _ndef_from_tlv(bytes(data))
        except NDEFError:
            continue              # message started but not all here yet
        if msg is not None:
            return msg
        if bytes(data).find(b"\xfe") >= 0:
            return None           # terminator reached, genuinely no NDEF
    return _ndef_from_tlv(bytes(data))


# ---------------------------------------------------------------- the driver

_CORE_RESET = b"\x20\x00\x01\x01"
_CORE_INIT = b"\x20\x01\x00"
_PROP_ACT = b"\x2f\x02\x00"
# Map every reader/writer protocol onto its RF interface.
_DISCOVER_MAP_RW = (b"\x21\x00\x10\x05\x01\x01\x01\x02\x01\x01\x03\x01\x01"
                    b"\x04\x01\x02\x80\x01\x80")

DEFAULT_TECHNOLOGIES = (TECH_NFC_A, TECH_NFC_B, TECH_NFC_F, TECH_NFC_V)


class PN7150:
    """Driver for the NXP PN7150 NFC controller.

    The friendly path is to hand it four pins and let it make its own bus::

        nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)

    To share an existing bus, pass ``i2c=`` instead of ``scl``/``sda``.
    """

    def __init__(self, scl=None, sda=None, irq=None, ven=None,
                 i2c=None, address=0x28, frequency=100000, debug=False):
        if irq is None or ven is None:
            raise ValueError("irq and ven pins are required")
        self._own_bus = False
        if i2c is None:
            if scl is None or sda is None:
                raise ValueError("pass scl and sda, or an existing i2c bus")
            i2c = busio.I2C(scl, sda, frequency=frequency)
            self._own_bus = True
        self._i2c = i2c
        self._address = address
        self.debug = debug
        self._irq = DigitalInOut(irq)
        self._irq.switch_to_input(Pull.DOWN)
        self._ven = DigitalInOut(ven)
        self._ven.switch_to_output(False)
        self._buf = bytearray(3 + 255)
        self._connected = False
        self._discovering = False
        self._mapped = False
        self._technologies = DEFAULT_TECHNOLOGIES
        self.firmware_version = None
        self.build_number = None

    @classmethod
    def from_board(cls, board_module, **kwargs):
        """Build from a board that defines ``NFC_SCL``/``NFC_SDA``/``NFC_IRQ``
        /``NFC_RESET`` (the iLabs Challenger RP2040 NFC does)."""
        try:
            return cls(board_module.NFC_SCL, board_module.NFC_SDA,
                       board_module.NFC_IRQ, board_module.NFC_RESET, **kwargs)
        except AttributeError:
            raise NotSupportedError(
                "this board does not define NFC_SCL/NFC_SDA/NFC_IRQ/NFC_RESET; "
                "pass the pins explicitly")

    # -- lifecycle -------------------------------------------------------

    def __enter__(self):
        if not self._connected:
            self.connect()
        return self

    def __exit__(self, *exc):
        self.deinit()
        return False

    def deinit(self):
        """Power the controller down and release the pins."""
        try:
            self._ven.value = False
        except Exception:  # pylint: disable=broad-except
            pass
        self._irq.deinit()
        self._ven.deinit()
        if self._own_bus:
            self._i2c.deinit()
        self._connected = False

    def hard_reset(self):
        """Pulse VEN to reset the controller."""
        self._ven.value = False
        sleep(0.01)
        self._ven.value = True
        sleep(0.01)

    def connect(self):
        """Reset and initialise the controller. Call before anything else."""
        self.hard_reset()
        with _Bus(self._i2c):
            rsp = self._command(_CORE_RESET, timeout=0.5)
            if len(rsp) < 6 or rsp[0] != 0x40 or rsp[1] != 0x00:
                raise CommandError("no CORE_RESET response (got %s)"
                                   % hexlify(rsp))
            self._check_status(rsp[3], "CORE_RESET")

            rsp = self._command(_CORE_INIT, timeout=0.5)
            if len(rsp) < 20 or rsp[0] != 0x40 or rsp[1] != 0x01:
                raise CommandError("bad CORE_INIT response")
            self._check_status(rsp[3], "CORE_INIT")
            n_int = rsp[8]
            fw = rsp[17 + n_int:20 + n_int]
            self.firmware_version = ".".join("%02x" % b for b in fw)

            rsp = self._command(_PROP_ACT, timeout=0.5)
            if len(rsp) >= 8 and rsp[0] == 0x4F:
                self.build_number = bytes(rsp[4:8])
        self._connected = True
        self._mapped = False
        return True

    @property
    def connected(self):
        return self._connected

    # -- discovery -------------------------------------------------------

    def start_discovery(self, technologies=DEFAULT_TECHNOLOGIES):
        """Begin polling. Pass a subset of ``TECH_NFC_A/B/F/V`` to narrow it."""
        self._require_connection()
        self._technologies = technologies
        with _Bus(self._i2c):
            self._ensure_map()
            body = bytearray([len(technologies)])
            for tech in technologies:
                body += bytes([tech, 0x01])       # poll each once per loop
            self._send(bytes([0x21, 0x03, len(body)]) + bytes(body),
                       "RF_DISCOVER")
        self._discovering = True
        return True

    def _ensure_map(self):
        """Map protocols onto RF interfaces. Only valid in the idle state and
        only needed once per reset -- re-sending it after every tag is what
        produced SEMANTIC_ERROR when a slow card left the controller busy."""
        if self._mapped:
            return
        self._send(_DISCOVER_MAP_RW, "RF_DISCOVER_MAP")
        self._mapped = True

    def _send(self, cmd, what):
        """Send a control command, recovering once from a bad-state error.

        A timed-out exchange can leave a tag activated; the command is then
        rejected as SEMANTIC_ERROR. Dropping to idle and retrying clears it
        instead of killing the caller's scan loop.
        """
        rsp = self._command(cmd, timeout=0.5)
        if len(rsp) < 4 or rsp[0] != 0x41:
            raise CommandError("%s: unexpected reply %s" % (what, hexlify(rsp)))
        status = rsp[3]
        if status == 0x00 or status == STATUS_DISCOVERY_ALREADY_STARTED:
            return rsp
        if status in (0x06, 0x03, 0x05):          # semantic/syntax/failed
            self._deactivate(0x00)
            self._drain()
            rsp = self._command(cmd, timeout=0.5)
            if len(rsp) >= 4 and rsp[0] == 0x41:
                status = rsp[3]
                if status == 0x00 or status == STATUS_DISCOVERY_ALREADY_STARTED:
                    return rsp
        self._check_status(status, what)
        return rsp

    def stop_discovery(self):
        """Stop polling and return the controller to idle."""
        if not self._connected:
            return False
        with _Bus(self._i2c):
            self._deactivate(0x00)
        self._discovering = False
        return True

    def _deactivate(self, mode):
        try:
            self._command(bytes([0x21, 0x06, 0x01, mode]), timeout=0.3)
        except (CommandError, TagTimeoutError):
            pass

    # -- reading tags ----------------------------------------------------

    def wait_for_tag(self, timeout=None):
        """Block until a tag is activated. Returns a :class:`Tag`, or ``None``
        if ``timeout`` (seconds) elapses first."""
        self._require_connection()
        if not self._discovering:
            self.start_discovery()
        deadline = None if timeout is None else _deadline(timeout)
        with _Bus(self._i2c):
            while True:
                pkt = self._read_frame(0.2)
                if pkt is None:
                    if deadline is not None and _expired(deadline):
                        return None
                    continue
                if pkt[0] == 0x61 and pkt[1] == 0x05:
                    return self._build_tag(pkt)

    def read_tag(self, timeout=None):
        """Wait for one tag, then stop polling. Convenience for one-shot use."""
        tag = self.wait_for_tag(timeout)
        return tag

    def scan(self, timeout=None, skip_repeats=True):
        """Yield tags as they arrive.

        By default a tag left sitting on the antenna is reported once: it is
        put to sleep after being read, so it stays quiet until it leaves the
        field and comes back.
        """
        self._require_connection()
        if not self._discovering:
            self.start_discovery()
        while True:
            tag = self.wait_for_tag(timeout)
            if tag is None:
                return
            yield tag
            self.resume_discovery(sleep_tag=skip_repeats)

    def resume_discovery(self, sleep_tag=True):
        """Finish with the current tag and go back to polling.

        ``sleep_tag=True`` first deactivates the tag to sleep, which puts it in
        the HALT state so it ignores the poll loop until it leaves the field --
        that is what stops a tag resting on the antenna being read over and
        over.

        Deactivating to sleep leaves the controller in W4_HOST_SELECT, which is
        *not* a polling state, so we must then drop to idle and re-issue
        RF_DISCOVER. Skipping that leaves the reader alive but permanently
        blind, which looks exactly like a freeze.
        """
        with _Bus(self._i2c):
            if sleep_tag:
                self._deactivate(0x01)      # tag -> HALT, ctrl -> W4_HOST_SELECT
            self._deactivate(0x00)          # ctrl -> IDLE
            self._drain()
        self._discovering = False
        self.start_discovery(self._technologies)
        return True

    def _build_tag(self, pkt):
        # RF_INTF_ACTIVATED_NTF: 3 header bytes, then
        # id, interface, protocol, tech, max payload, credits, n_params, params
        disc_id = pkt[3]
        interface = pkt[4]
        protocol = pkt[5]
        tech = pkt[6]
        params = pkt[10:]
        cls = _TAG_CLASSES.get(protocol, Tag)
        return cls(self, disc_id, interface, protocol, tech, params)

    # -- transport -------------------------------------------------------

    def _require_connection(self):
        if not self._connected:
            raise NotConnectedError("call connect() first")

    @staticmethod
    def _check_status(status, what):
        if status != 0x00:
            raise CommandError("%s returned %s (0x%02x)" % (
                what, STATUS_NAMES.get(status, "unknown"), status))

    def _raw_read(self):
        self._i2c.readfrom_into(self._address, self._buf, start=0, end=3)
        end = 3 + self._buf[2]
        if end > 3:
            self._i2c.readfrom_into(self._address, self._buf, start=3, end=end)
        if self.debug:
            print("<-", hexlify(self._buf[:end]))
        return bytes(self._buf[:end])

    def _read_frame(self, timeout):
        """Wait up to ``timeout`` seconds for a frame. ``None`` on timeout."""
        deadline = _deadline(timeout)
        while not self._irq.value:
            if _expired(deadline):
                return None
        return self._raw_read()

    def _drain(self):
        """Throw away anything the controller still has queued."""
        while self._irq.value:
            self._raw_read()

    def _write_frame(self, data):
        self._drain()
        if self.debug:
            print("->", hexlify(data))
        self._i2c.writeto(self._address, data)

    def _command(self, cmd, timeout=0.5):
        """Send a command and return the first frame that comes back."""
        self._write_frame(cmd)
        rsp = self._read_frame(timeout)
        if rsp is None:
            raise TagTimeoutError("no response to %s" % hexlify(cmd[:2]))
        return rsp

    def _exchange(self, payload, timeout=0.5):
        """Send a data packet to the activated tag and return its answer."""
        frame = bytes([0x00, 0x00, len(payload)]) + bytes(payload)
        with _Bus(self._i2c):
            self._write_frame(frame)
            deadline = _deadline(timeout)
            while True:
                pkt = self._read_frame(0.05)
                if pkt is None:
                    if not _expired(deadline):
                        continue
                    # Drain anything that arrives late, so it is not mistaken
                    # for the answer to the next command.
                    self._drain()
                    raise TagTimeoutError("tag did not answer in %.2fs"
                                          % timeout)
                if pkt[0] & 0xE0 == 0x00:          # data packet
                    return pkt[3:]
                if pkt[0] == 0x61 and pkt[1] == 0x06:
                    raise TagLostError("tag left the field")
                # anything else is a notification we do not care about


class _Bus:
    """Hold the I2C lock for the duration of a block, re-entrantly."""

    def __init__(self, i2c):
        self._i2c = i2c
        self._locked = False

    def __enter__(self):
        if not self._i2c.try_lock():
            # Already ours (nested use); proceed without double-locking.
            return self
        self._locked = True
        return self

    def __exit__(self, *exc):
        if self._locked:
            self._i2c.unlock()
        return False


def _deadline(seconds):
    """A wrap-safe deadline, `seconds` from now."""
    return (ticks_ms() + int(seconds * 1000)) % _TICKS_PERIOD


def _expired(deadline):
    """True once `deadline` has passed. ticks_ms() wraps at 2**29 ms, so
    compare via a signed difference rather than subtracting directly."""
    diff = (ticks_ms() - deadline + _TICKS_PERIOD // 2) % _TICKS_PERIOD \
        - _TICKS_PERIOD // 2
    return diff >= 0

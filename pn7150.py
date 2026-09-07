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

__version__ = "1.2.0"

_TICKS_PERIOD = const(1 << 29)

# ---------------------------------------------------------------- exceptions


class PN7150Error(Exception):
    """Base class for every error this driver raises."""


class NotConnectedError(PN7150Error):
    """The controller has not completed :meth:`PN7150.connect` yet."""


class CommandError(PN7150Error):
    """The controller rejected a command or answered unexpectedly.

    :attr:`status` is the NCI status byte when there was one, so a caller can
    tell a transient RF glitch from a flat refusal.
    """

    def __init__(self, message, status=None):
        # super(), not PN7150Error.__init__: CircuitPython's native exception
        # types expose no Python-level __init__, so the unbound call raises
        # AttributeError on the board while passing fine on CPython.
        super().__init__(message)
        self.status = status


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
    0xC0: "NFCEE_INTERFACE_ACTIVATION_FAILED",
    0xC1: "NFCEE_TRANSMISSION_ERROR",
    0xC2: "NFCEE_PROTOCOL_ERROR",
    0xC3: "NFCEE_TIMEOUT_ERROR",
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

    def __eq__(self, other):
        # CircuitPython does not derive __ne__ from __eq__, so both are here.
        return (isinstance(other, NDEFRecord)
                and self.tnf == other.tnf
                and bytes(self.type) == bytes(other.type)
                and bytes(self.payload) == bytes(other.payload)
                and bytes(self.id) == bytes(other.id))

    def __ne__(self, other):
        return not self.__eq__(other)

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

    @classmethod
    def external(cls, type_name, data):
        """Build an external-type record.

        ``type_name`` is the domain-qualified name without the ``urn:nfc:ext:``
        prefix, e.g. ``external("example.com:widget", b"...")``.
        """
        return cls(TNF_EXTERNAL, type_name.encode("utf-8"), bytes(data))


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

    def __eq__(self, other):
        return (isinstance(other, NDEFMessage)
                and len(self.records) == len(other.records)
                and all(a == b for a, b in zip(self.records, other.records)))

    def __ne__(self, other):
        return not self.__eq__(other)

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
            if length == 0:
                # A formatted but empty tag holds `03 00 FE`. That is a valid
                # empty message, not a malformed one.
                return None
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


#: Statuses that mean "the radio glitched", not "the tag said no". A read that
#: hits one of these is worth repeating: NFC links drop frames routinely when a
#: tag is moved or held at the edge of the field, and giving up on the first
#: one throws away everything read so far.
TRANSIENT_STATUSES = (0x02, 0xB0, 0xB1, 0xB2)

#: How many times a block read is attempted before giving up.
READ_ATTEMPTS = const(3)


def _is_transient(err):
    if isinstance(err, TagTimeoutError):
        return True
    return isinstance(err, CommandError) and err.status in TRANSIENT_STATUSES


def _read_retrying(reader, block, attempts=READ_ATTEMPTS):
    """Read one block, repeating the attempt while the failure looks like RF
    noise. A tag that answers "no" is not retried."""
    last = None
    for _ in range(attempts):
        try:
            return reader(block)
        except (CommandError, TagTimeoutError) as err:
            if not _is_transient(err):
                raise
            last = err
    raise last


# ----------------------------------------------------------------- tag types


class Tag:
    """A tag currently in the field.

    Instances come from :meth:`PN7150.scan` or :meth:`PN7150.read_tag`; the
    right subclass is chosen for you from the activated protocol.
    """

    def __init__(self, nfc, disc_id, interface, protocol, tech, params,
                 max_payload=None):
        self._nfc = nfc
        self.discovery_id = disc_id
        self.interface = interface
        self.protocol = protocol
        self.technology = tech
        self.rf_params = params
        #: Largest payload the controller will carry to this tag in one packet,
        #: as reported at activation (``None`` if the tag was built by hand).
        self.max_payload = max_payload
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
        if self.max_payload and len(data) > self.max_payload:
            raise ValueError(
                "%d bytes exceeds the %d the controller negotiated for this "
                "tag" % (len(data), self.max_payload))
        return self._nfc._exchange(bytes(data), timeout)

    def _probe(self):
        """Send the cheapest command that proves the tag is still there.

        Subclasses override this. Raising :class:`CommandError` still counts as
        present - the tag answered, it just refused.
        """
        raise NotSupportedError(
            "presence checking is not implemented for %s" % self.type)

    def is_present(self):
        """``True`` while the tag is still in the field.

        Cheap enough to poll. Note that a Type 2 tag put to sleep by
        :meth:`PN7150.resume_discovery` will report absent, so use this before
        finishing with the tag, not after.
        """
        try:
            self._probe()
        except (TagLostError, TagTimeoutError):
            return False
        except CommandError:
            return True
        return True

    def wait_for_removal(self, timeout=None, poll=0.1):
        """Block until the tag leaves the field.

        Returns ``True`` once it is gone, or ``False`` if ``timeout`` seconds
        elapse first. Useful for "hold the badge until the door opens".
        """
        deadline = None if timeout is None else _deadline(timeout)
        while True:
            if not self.is_present():
                return True
            if deadline is not None and _expired(deadline):
                return False
            sleep(poll)

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
        """A multi-line description of everything known about the tag.

        Like ``str(tag)``, this touches :attr:`ndef`, so the first call reads
        from the tag and blocks. Use :func:`repr` for a no-I/O one-liner.
        """
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
    DEFAULT_CAPACITY = 48         # a bare Ultralight, with no usable CC

    # Class-level default so the cache works even for instances built without
    # going through Type2Tag.__init__ (the test doubles do this).
    _capacity = None

    def _probe(self):
        self.transceive(b"\x30\x00", 0.1)

    def read(self, page):
        """READ command: returns 16 bytes (4 consecutive pages)."""
        resp = self.transceive(bytes([0x30, page & 0xFF]))
        payload, _ = _split_status(resp, "read of page %d" % page)
        return payload

    @property
    def capacity(self):
        """Usable data bytes, from the capability container in page 3.

        Read once and cached: :meth:`write` consults it on every page, and a
        round trip per page would triple the cost of a write.
        """
        if self._capacity is None:
            try:
                cc = self.read(3)[:4]
            except PN7150Error:
                return self.DEFAULT_CAPACITY      # do not cache a failure
            # Not every tag answers a READ of page 3 with four pages: one in
            # this survey returned a single byte. Anything shorter than a CC
            # is treated as "no usable CC", never indexed blindly.
            if len(cc) < 3 or cc[0] != 0xE1:
                self._capacity = self.DEFAULT_CAPACITY
            else:
                self._capacity = cc[2] * 8
        return self._capacity

    @property
    def last_data_page(self):
        """Highest page holding user data, per the capability container."""
        return 3 + self.capacity // self.PAGE_SIZE

    def write(self, page, data, force=False):
        """WRITE one 4-byte page.

        Pages 0-3 (UID, lock bits, capability container) are always refused.
        Pages past the end of user memory are refused too, because on an NTAG
        they are the dynamic lock bytes, the mirror/AUTH0 config and the
        password - writing there can lock a tag permanently. Pass
        ``force=True`` only if you know the tag's real layout; it lifts the
        upper bound, never the lower one.
        """
        data = bytes(data)
        if len(data) != self.PAGE_SIZE:
            raise ValueError("a Type 2 page is exactly 4 bytes")
        if page < 4:
            raise ValueError(
                "refusing to write page %d: pages 0-3 hold the UID, lock bits "
                "and capability container" % page)
        if not force:
            last = self.last_data_page
            if page > last:
                raise ValueError(
                    "refusing to write page %d: the capability container "
                    "declares user memory ending at page %d, and the pages "
                    "beyond it are lock bits, config and password bytes "
                    "(pass force=True to override)" % (page, last))
        resp = self.transceive(bytes([0xA2, page & 0xFF]) + data)
        if resp and resp[-1] not in (0x00, 0x0A):
            raise CommandError("write of page %d failed (0x%02x)"
                               % (page, resp[-1]))
        return True

    def read_memory(self, start=4, pages=16, attempts=READ_ATTEMPTS):
        """Read a run of pages, returning one flat ``bytes``."""
        out = bytearray()
        page = start
        while page < start + pages:
            try:
                blk = _read_retrying(self.read, page, attempts)
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
        """Write an :class:`NDEFMessage` starting at page 4.

        Raises :class:`NDEFError` if the message does not fit in the capacity
        the tag's capability container declares, rather than running off the
        end of user memory into the config pages.
        """
        if isinstance(message, str):
            message = NDEFMessage.from_uri(message) if "://" in message \
                else NDEFMessage.from_text(message)
        payload = _ndef_to_tlv(message)
        capacity = self.capacity
        if len(payload) > capacity:
            raise NDEFError(
                "message needs %d bytes (with its TLV wrapper) but the tag "
                "declares %d" % (len(payload), capacity))
        payload += b"\x00" * (-len(payload) % self.PAGE_SIZE)
        for i in range(0, len(payload), self.PAGE_SIZE):
            self.write(4 + i // self.PAGE_SIZE, payload[i:i + self.PAGE_SIZE])
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
        """Select the NDEF application (tries the v2.0 AID, then v1.0).

        Returns ``False`` rather than raising when the card does not answer:
        plenty of ISO-DEP cards (hotel keys, transit, payment) simply ignore
        the SELECT, and "no NDEF application" is the right answer for them.
        """
        for aid in (b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01\x00",
                    b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x00"):
            try:
                _, sw = self.apdu(aid)
            except PN7150Error:
                continue
            if sw == 0x9000:
                return True
        return False

    def select_file(self, file_id):
        _, sw = self.apdu(b"\x00\xa4\x00\x0c\x02" + bytes(file_id))
        return sw == 0x9000

    def _probe(self):
        # An invalid class byte: the card answers 6E00, which is all we need.
        self.transceive(b"\x00\x00\x00\x00\x00", 0.3)

    def read_binary(self, offset, length):
        data, sw = self.apdu(bytes([0x00, 0xB0, (offset >> 8) & 0xFF,
                                    offset & 0xFF, length & 0xFF]))
        if sw != 0x9000:
            raise CommandError("READ BINARY failed, SW=%04x" % sw)
        return data

    def update_binary(self, offset, data):
        """UPDATE BINARY: write into the currently selected file."""
        data = bytes(data)
        _, sw = self.apdu(bytes([0x00, 0xD6, (offset >> 8) & 0xFF,
                                 offset & 0xFF, len(data)]) + data)
        if sw != 0x9000:
            raise CommandError("UPDATE BINARY at %d failed, SW=%04x"
                               % (offset, sw))
        return True

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

    def write_ndef(self, message):
        """Write an :class:`NDEFMessage` to the tag's NDEF file.

        Follows the NFC Forum Type 4 write flow: zero NLEN first, so a tag
        interrupted mid-write reads as empty rather than as a truncated
        message, then the data, then the real NLEN.

        Not verified against physical hardware - no writable Type 4 tag was
        available. The read path in :meth:`read_ndef` is.
        """
        if isinstance(message, str):
            message = NDEFMessage.from_uri(message) if "://" in message \
                else NDEFMessage.from_text(message)
        payload = message.to_bytes()
        if not self.select_ndef_application():
            raise NotSupportedError("no NDEF application on this card")
        if not self.select_file(b"\xe1\x03"):
            raise NotSupportedError("no capability container on this card")
        cc = self.read_binary(0, 15)
        if len(cc) < 15:
            raise CommandError("short capability container")
        file_id = cc[9:11]
        # CC bytes 11..12 are the NDEF file's maximum size, NLEN included.
        max_size = (cc[11] << 8) | cc[12]
        if cc[14] != 0x00:
            raise NotSupportedError("the NDEF file is read only (0x%02x)"
                                    % cc[14])
        if len(payload) + 2 > max_size:
            raise NDEFError("message needs %d bytes but the NDEF file holds %d"
                            % (len(payload) + 2, max_size - 2))
        if not self.select_file(file_id):
            raise CommandError("could not select the NDEF file")
        self.update_binary(0, b"\x00\x00")
        offset = 2
        for i in range(0, len(payload), 0xF0):
            chunk = payload[i:i + 0xF0]
            self.update_binary(offset, chunk)
            offset += len(chunk)
        self.update_binary(0, bytes([(len(payload) >> 8) & 0xFF,
                                     len(payload) & 0xFF]))
        self._ndef = message
        self._ndef_read = True
        return True


class MifareClassicTag(Tag):
    """MIFARE Classic.

    Blocks are 16 bytes, grouped in sectors of 4 blocks, and every sector must
    be authenticated before it can be read. The PN7150 holds the two standard
    keys itself, so :meth:`authenticate` needs no key material for ordinary
    NDEF-formatted or factory-default tags.
    """

    BLOCK_SIZE = 16

    @property
    def block_count(self):
        """Total blocks, inferred from SAK. 1K unless the card says otherwise.

        SAK 0x08/0x88 is 1K (64 blocks), 0x18/0x98 is 4K (256 blocks) and 0x09
        is Mini (20 blocks). The high bit varies between NXP and clone silicon,
        hence the mask.
        """
        sak = self.sel_res
        if sak is not None:
            if sak & 0x7F == 0x18:
                return 256
            if sak & 0x7F == 0x09:
                return 20
        return 64

    @staticmethod
    def sector_of(block):
        """Sector containing ``block``. Sectors 0-31 hold 4 blocks, 32-39 hold
        16 (only 4K cards have those)."""
        if block < 128:
            return block // 4
        return 32 + (block - 128) // 16

    @staticmethod
    def first_block_of(sector):
        """First block of ``sector``."""
        if sector < 32:
            return sector * 4
        return 128 + (sector - 32) * 16

    @staticmethod
    def is_trailer(block):
        """True for a sector trailer, which holds keys and access bits."""
        if block < 128:
            return block % 4 == 3
        return (block - 128) % 16 == 15

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

    def _probe(self):
        # Unauthenticated, so the card refuses - but refusing proves presence.
        self.transceive(b"\x10\x30\x00", 0.1)

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

    def write_block(self, block, data, force=False):
        """Write one 16-byte block. Its sector must be authenticated first.

        MIFARE writes are two exchanges, not one: the command ``10 A0 <block>``
        is acknowledged before the 16 data bytes are sent as ``10 <data>``.
        (Both frames confirmed against NXP's own reference implementation.)

        Block 0 is the manufacturer block and is always refused. Sector
        trailers are refused unless ``force=True``, because they hold the keys
        and the access bits: a trailer written with the wrong access bits
        locks that sector for good, with no way back. This driver cannot
        format a card, so there is no ordinary reason to write one.
        """
        data = bytes(data)
        if len(data) != self.BLOCK_SIZE:
            raise ValueError("a MIFARE Classic block is exactly %d bytes"
                             % self.BLOCK_SIZE)
        if block == 0:
            raise ValueError("refusing to write block 0: it is the read-only "
                             "manufacturer block (UID and BCC)")
        if self.is_trailer(block) and not force:
            raise ValueError(
                "refusing to write block %d: it is the trailer of sector %d, "
                "holding the keys and access bits. Wrong access bits lock the "
                "sector permanently (pass force=True if you are certain)"
                % (block, self.sector_of(block)))
        resp = self.transceive(bytes([0x10, 0xA0, block & 0xFF]))
        if not resp or resp[-1] != 0x00:
            raise CommandError(
                "write of block %d was not accepted%s" %
                (block, "" if not resp else " (0x%02x)" % resp[-1]),
                resp[-1] if resp else None)
        resp = self.transceive(bytes([0x10]) + data)
        if not resp or resp[-1] != 0x00:
            raise CommandError(
                "data for block %d was not accepted%s" %
                (block, "" if not resp else " (0x%02x)" % resp[-1]),
                resp[-1] if resp else None)
        return True

    def ndef_blocks(self):
        """The data blocks that hold NDEF, in order.

        Sector 0 is the MAD, sector trailers hold keys, and on a 4K card
        sector 16 is MAD2. None of them carry message data.
        """
        blocks = []
        total = self.block_count
        block = 4
        while block < total:
            if not self.is_trailer(block) and not (
                    total > 64 and self.sector_of(block) == 16):
                blocks.append(block)
            block += 1
        return blocks

    @property
    def ndef_capacity(self):
        """Bytes available for an NDEF message, TLV wrapper included."""
        return len(self.ndef_blocks()) * self.BLOCK_SIZE

    def write_ndef(self, message, key=KEY_NDEF):
        """Write an :class:`NDEFMessage` to an already NDEF-formatted card.

        Formatting is *not* done here: a card that is not already formatted
        has no NDEF key and no MAD, and setting those up means writing sector
        trailers, which risks locking sectors permanently. Use a dedicated
        tool for that; this only fills in the message.

        Not verified against physical hardware - no NDEF-formatted writable
        MIFARE Classic was available.
        """
        if isinstance(message, str):
            message = NDEFMessage.from_uri(message) if "://" in message \
                else NDEFMessage.from_text(message)
        payload = _ndef_to_tlv(message)
        capacity = self.ndef_capacity
        if len(payload) > capacity:
            raise NDEFError(
                "message needs %d bytes (with its TLV wrapper) but the card "
                "holds %d" % (len(payload), capacity))
        payload += b"\x00" * (-len(payload) % self.BLOCK_SIZE)
        self.authenticate(1, key)
        sector = 1
        for i, block in enumerate(self.ndef_blocks()):
            if i * self.BLOCK_SIZE >= len(payload):
                break
            if self.sector_of(block) != sector:
                sector = self.sector_of(block)
                self.authenticate(sector, key)
            self.write_block(block,
                             payload[i * self.BLOCK_SIZE:
                                     (i + 1) * self.BLOCK_SIZE])
        self._ndef = message
        self._ndef_read = True
        return True

    def read_sector(self, sector, key=KEY_DEFAULT):
        """Authenticate then read every block of a sector, trailer included.

        Sectors 0-31 are four blocks; on a 4K card sectors 32-39 are sixteen.
        """
        self.authenticate(sector, key)
        first = self.first_block_of(sector)
        count = 4 if sector < 32 else 16
        return b"".join(self.read_block(first + i) for i in range(count))

    def read_ndef(self):
        # NDEF-formatted Classic tags keep their data from sector 1 onward,
        # under the NFC Forum key. Each sector needs its own authentication.
        try:
            self.authenticate(1, KEY_NDEF)
        except CommandError:
            return None
        data = bytearray()
        for block in self.ndef_blocks():
            sector = self.sector_of(block)
            if block == self.first_block_of(sector) and sector != 1:
                try:
                    self.authenticate(sector, KEY_NDEF)
                except CommandError:
                    break
            try:
                data += self.read_block(block)
            except (CommandError, TagLostError, TagTimeoutError):
                break
            # Stop on the length the TLV itself declares. The old test - "a
            # 0xFE byte appeared somewhere" - truncated any message whose
            # binary payload happened to contain one.
            end = _ndef_tlv_end(data)
            if end == TLV_NO_NDEF:
                return None
            if end != TLV_NEED_MORE and len(data) >= end:
                break
        return _ndef_from_tlv(bytes(data))


class Type5Tag(Tag):
    """ISO 15693 / NFC-V vicinity tags.

    The capability container is 4 bytes on most tags, but 8 on any tag whose
    T5T area exceeds 2040 bytes: MLEN cannot be expressed in one byte, so it
    is zeroed and a 16-bit MLEN appears in bytes 6-7 instead. The T5T area
    starts immediately after the CC, which means block 2 rather than block 1
    for those tags. (NFC Forum T5T Operation spec; see also ST AN4911.)
    """

    BLOCK_SIZE = 4
    # Class-level default so the cache also works for hand-built instances.
    _cc = None

    def _probe(self):
        self.transceive(b"\x02\x20\x00", 0.2)

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

    def read_memory(self, start=0, blocks=16, attempts=READ_ATTEMPTS):
        out = bytearray()
        for b in range(start, start + blocks):
            try:
                out += _read_retrying(self.read_block, b, attempts)
            except (CommandError, TagLostError, TagTimeoutError):
                break
        return bytes(out)

    def write_block(self, block, data):
        """WRITE SINGLE BLOCK.

        Refuses block 0, which is the capability container. The timeout is
        generous because ISO15693 tags take milliseconds to commit a write.

        Not verified against physical hardware.
        """
        data = bytes(data)
        if len(data) != self.BLOCK_SIZE:
            raise ValueError("an ISO15693 block is exactly %d bytes"
                             % self.BLOCK_SIZE)
        try:
            first = self.first_data_block
        except PN7150Error:
            first = 1                         # CC unreadable; guard block 0
        if block < first:
            raise ValueError(
                "refusing to write block %d: it is part of the %d-byte "
                "capability container" % (block, first * self.BLOCK_SIZE))
        resp = self.transceive(bytes([0x02, 0x21, block & 0xFF]) + data, 1.0)
        payload, _ = _split_status(resp, "write of block %d" % block)
        if payload and payload[0] != 0x00:
            raise CommandError("write of block %d failed (flags 0x%02x)"
                               % (block, payload[0]))
        return True

    def _read_cc(self):
        """Read the CC once and cache it, fetching block 1 too when it is the
        8-byte form."""
        if self._cc is None:
            cc = bytes(self.read_block(0))
            if len(cc) >= 3 and cc[2] == 0x00:
                try:
                    cc += bytes(self.read_block(1))
                except PN7150Error:
                    pass          # keep the 4 bytes we have
            self._cc = cc
        return self._cc

    @property
    def capability_container(self):
        """The Type 5 CC: ``E1 <ver/access> <MLEN> <features>``, or the 8-byte
        form ``E2 <ver/access> 00 <features> <rfu x2> <MLEN hi> <MLEN lo>``."""
        return self._read_cc()

    @property
    def cc_size(self):
        """4 or 8 bytes. Byte 2 being zero is what marks the long form."""
        cc = self._read_cc()
        return 8 if (len(cc) >= 3 and cc[2] == 0x00) else 4

    @property
    def first_data_block(self):
        """First block of the T5T area, which begins right after the CC."""
        return self.cc_size // self.BLOCK_SIZE

    @property
    def formatted(self):
        """True if the CC carries an NFC Forum magic number."""
        cc = self._read_cc()
        return len(cc) >= 3 and cc[0] in (0xE1, 0xE2)

    @property
    def capacity(self):
        """Usable data bytes: ``MLEN * 8``, from whichever CC form is present."""
        try:
            cc = self._read_cc()
        except PN7150Error:
            return 0
        if not (len(cc) >= 3 and cc[0] in (0xE1, 0xE2)):
            return 0
        if cc[2]:
            return cc[2] * 8
        if len(cc) >= 8:                      # 16-bit MLEN, big endian
            return ((cc[6] << 8) | cc[7]) * 8
        return 0

    def write_ndef(self, message):
        """Write an :class:`NDEFMessage` starting at block 1.

        Not verified against physical hardware.
        """
        if isinstance(message, str):
            message = NDEFMessage.from_uri(message) if "://" in message \
                else NDEFMessage.from_text(message)
        payload = _ndef_to_tlv(message)
        capacity = self.capacity
        if capacity and len(payload) > capacity:
            raise NDEFError(
                "message needs %d bytes (with its TLV wrapper) but the tag "
                "declares %d" % (len(payload), capacity))
        payload += b"\x00" * (-len(payload) % self.BLOCK_SIZE)
        first = self.first_data_block
        for i in range(0, len(payload), self.BLOCK_SIZE):
            self.write_block(first + i // self.BLOCK_SIZE,
                             payload[i:i + self.BLOCK_SIZE])
        self._ndef = message
        self._ndef_read = True
        return True

    def read_ndef(self):
        # The CC is NOT part of the TLV area - parsing from block 0 makes it
        # look like a bogus TLV. The data starts right after it, which is
        # block 1 for a 4-byte CC and block 2 for the 8-byte form.
        try:
            if not self.formatted:
                return _read_ndef_area(self.read_block, 0, 1, 128)
            return _read_ndef_area(self.read_block, self.first_data_block, 1,
                                   self.capacity or 128)
        except PN7150Error:
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

    def _probe(self):
        # A card with no NDEF service answers with an error, which still
        # proves it is in the field - is_present() treats that as present.
        self.check(0)

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
        SF2 = 0xA6 (service not present). Some simply do not answer at all,
        which is also a "no" - hence catching every driver error here rather
        than only :class:`CommandError`.
        """
        try:
            self.check(0)
        except PN7150Error:
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
        raise CommandError("%s failed (status 0x%02x %s)"
                           % (what, status,
                              STATUS_NAMES.get(status, "unknown")), status)
    return resp[:-1], status


# _ndef_tlv_end() return values.
TLV_NEED_MORE = const(-1)
TLV_NO_NDEF = const(0)


def _ndef_tlv_end(data):
    """How many bytes of a TLV area must be read for the NDEF message.

    Returns the offset just past the NDEF message, :data:`TLV_NO_NDEF` (0) if
    the area definitively holds no message, or :data:`TLV_NEED_MORE` (-1) if
    the answer is not yet knowable from ``data``.

    Scanning the declared length is the only safe way to know when to stop:
    ``0xFE`` is a terminator only *between* TLVs, and is perfectly ordinary
    inside a binary payload.
    """
    i = 0
    data = bytes(data)
    while True:
        if i >= len(data):
            return TLV_NEED_MORE
        tag = data[i]
        if tag == 0x00:                      # NULL TLV, skip
            i += 1
            continue
        if tag == 0xFE:                      # terminator
            return TLV_NO_NDEF
        if i + 1 >= len(data):
            return TLV_NEED_MORE
        length = data[i + 1]
        i += 2
        if length == 0xFF:                   # 3-byte length form
            if i + 2 > len(data):
                return TLV_NEED_MORE
            length = (data[i] << 8) | data[i + 1]
            i += 2
        if tag == 0x03:                      # NDEF message TLV
            return i + length if length else TLV_NO_NDEF
        i += length


def _read_ndef_area(reader, first_block, blocks_per_read, limit,
                    attempts=READ_ATTEMPTS):
    """Read a TLV area a chunk at a time, stopping as soon as the NDEF message
    is complete. Avoids reading past the end of tag memory, which makes tags
    stop answering."""
    data = bytearray()
    block = first_block
    while len(data) < limit:
        try:
            chunk = _read_retrying(reader, block, attempts)
        except (CommandError, TagLostError, TagTimeoutError):
            break
        if not chunk:
            break
        data += chunk
        block += blocks_per_read
        end = _ndef_tlv_end(data)
        if end == TLV_NO_NDEF:
            return None           # terminator or empty message: genuinely none
        if end != TLV_NEED_MORE and len(data) >= end:
            break                 # the whole message is in hand
    return _ndef_from_tlv(bytes(data))


# ---------------------------------------------------------------- the driver

_CORE_RESET = b"\x20\x00\x01\x01"
_CORE_INIT = b"\x20\x01\x00"
_PROP_ACT = b"\x2f\x02\x00"
# Map every reader/writer protocol onto its RF interface.
_DISCOVER_MAP_RW = (b"\x21\x00\x10\x05\x01\x01\x01\x02\x01\x01\x03\x01\x01"
                    b"\x04\x01\x02\x80\x01\x80")

DEFAULT_TECHNOLOGIES = (TECH_NFC_A, TECH_NFC_B, TECH_NFC_F, TECH_NFC_V)

# Which RF interface each protocol is activated on; mirrors _DISCOVER_MAP_RW.
_PROTOCOL_INTERFACES = {
    PROTOCOL_T1T: INTERFACE_FRAME,
    PROTOCOL_T2T: INTERFACE_FRAME,
    PROTOCOL_T3T: INTERFACE_FRAME,
    PROTOCOL_T5T: INTERFACE_FRAME,
    PROTOCOL_ISO_DEP: INTERFACE_ISO_DEP,
    PROTOCOL_MIFARE: INTERFACE_TAG,
}

#: Order in which to pick when one card offers several protocols. MIFARE comes
#: before ISO-DEP deliberately: the cards that advertise both (MIFARE Plus in
#: SL1, and the UID-changeable "magic" clones) are Classic cards underneath,
#: and selecting ISO-DEP on them activates an interface that then answers
#: nothing useful.
DEFAULT_PROTOCOL_PREFERENCE = (PROTOCOL_T2T, PROTOCOL_T3T, PROTOCOL_T5T,
                               PROTOCOL_T1T, PROTOCOL_MIFARE, PROTOCOL_ISO_DEP)


class PN7150:
    """Driver for the NXP PN7150 NFC controller.

    The friendly path is to hand it four pins and let it make its own bus::

        nfc = PN7150(board.NFC_SCL, board.NFC_SDA, board.NFC_IRQ, board.NFC_RESET)

    To share an existing bus, pass ``i2c=`` instead of ``scl``/``sda``.
    """

    def __init__(self, scl=None, sda=None, irq=None, ven=None,
                 i2c=None, address=0x28, frequency=100000, debug=False,
                 protocol_preference=DEFAULT_PROTOCOL_PREFERENCE):
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
        self._deinited = False
        self._connected = False
        self._discovering = False
        self._mapped = False
        self._technologies = DEFAULT_TECHNOLOGIES
        self.protocol_preference = protocol_preference
        #: Candidates from the most recent multi-protocol discovery, as
        #: ``(discovery_id, protocol, technology, params)`` tuples.
        self.candidates = []
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
        """Power the controller down and release the pins. Safe to call twice."""
        if self._deinited:
            return
        self._deinited = True
        try:
            self._ven.value = False
        except ValueError:
            pass          # already released; nothing left to pull low
        self._irq.deinit()
        self._ven.deinit()
        if self._own_bus:
            self._i2c.deinit()
        self._connected = False
        self._discovering = False

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
        found = []
        with _Bus(self._i2c):
            while True:
                pkt = self._read_frame(0.2)
                if pkt is None:
                    if deadline is not None and _expired(deadline):
                        return None
                    continue
                if pkt[0] == 0x61 and pkt[1] == 0x05:
                    return self._build_tag(pkt)
                if pkt[0] == 0x61 and pkt[1] == 0x03:
                    # RF_DISCOVER_NTF. A card that offers more than one
                    # protocol is not activated automatically: the NFCC lists
                    # the candidates and waits in W4_HOST_SELECT for the host
                    # to choose. Ignoring these leaves the reader in a state
                    # that is not polling, i.e. permanently blind.
                    cand = _parse_discover_ntf(pkt)
                    if cand is not None:
                        found.append(cand)
                    if pkt[-1] != 0x02:          # 0x02 = more notifications
                        self.candidates = list(found)
                        self._select_candidate(found)
                        found = []

    def read_tag(self, timeout=None):
        """Wait for one tag, then stop polling. Convenience for one-shot use.

        The tag stays activated, so it can still be read; call
        :meth:`start_discovery` again to look for the next one.
        """
        tag = self.wait_for_tag(timeout)
        if tag is None:
            self.stop_discovery()
        return tag

    def scan(self, timeout=None, skip_repeats=True):
        """Yield tags as they arrive.

        By default a tag left sitting on the antenna is reported once: it is
        put to sleep after being read, so it stays quiet until it leaves the
        field and comes back.

        ``timeout`` is the wait for *each* tag, not a budget for the whole
        loop: the generator ends the first time that many seconds pass with
        nothing presented. ``None`` waits forever.
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

    def _select_candidate(self, candidates):
        """Activate one of the targets listed by RF_DISCOVER_NTF.

        Tries them in :attr:`protocol_preference` order and falls through to
        the next if the NFCC rejects the choice. If none can be selected the
        controller is dropped back to idle and polling restarted, because
        leaving it in W4_HOST_SELECT would make it deaf to every later tag.
        """
        if not candidates:
            return False
        order = []
        for wanted in self.protocol_preference:
            for cand in candidates:
                if cand[1] == wanted and cand not in order:
                    order.append(cand)
        for cand in candidates:                  # anything not ranked, last
            if cand not in order:
                order.append(cand)

        for disc_id, protocol, _tech, _params in order:
            interface = _PROTOCOL_INTERFACES.get(protocol, INTERFACE_FRAME)
            try:
                rsp = self._command(
                    bytes([0x21, 0x04, 0x03, disc_id, protocol, interface]),
                    timeout=0.5)
            except (CommandError, TagTimeoutError):
                continue
            if len(rsp) >= 4 and rsp[0] == 0x41 and rsp[3] == 0x00:
                return True                      # activation NTF follows
        # Nothing could be selected: get out of W4_HOST_SELECT.
        self._deactivate(0x00)
        self._drain()
        self._discovering = False
        try:
            self.start_discovery(self._technologies)
        except PN7150Error:
            pass
        return False

    def _build_tag(self, pkt):
        # RF_INTF_ACTIVATED_NTF: 3 header bytes, then
        # id, interface, protocol, tech, max payload, credits, n_params, params
        disc_id = pkt[3]
        interface = pkt[4]
        protocol = pkt[5]
        tech = pkt[6]
        max_payload = pkt[7] if len(pkt) > 7 else None
        params = pkt[10:]
        cls = _TAG_CLASSES.get(protocol, Tag)
        return cls(self, disc_id, interface, protocol, tech, params,
                   max_payload)

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

    #: Largest payload one NCI data packet can carry (the length field is a
    #: single byte). Segmentation of longer payloads is not implemented.
    MAX_PACKET_PAYLOAD = const(255)

    def _exchange(self, payload, timeout=0.5):
        """Send a data packet to the activated tag and return its answer."""
        if len(payload) > self.MAX_PACKET_PAYLOAD:
            raise ValueError(
                "payload of %d bytes exceeds the 255-byte NCI packet limit; "
                "segmentation is not implemented" % len(payload))
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
                if pkt[0] == 0x60 and pkt[1] in (0x07, 0x08):
                    # CORE_GENERIC_ERROR_NTF / CORE_INTERFACE_ERROR_NTF: the
                    # controller is telling us this exchange failed, and its
                    # status byte says why. Treating these as "a notification
                    # we do not care about" means waiting out the full timeout
                    # and then reporting a vague "tag did not answer" instead
                    # of the RF_TIMEOUT_ERROR the NFCC already diagnosed.
                    # Payload is <status> for 0x07, <status> <conn id> for
                    # 0x08 (NCI 1.0; matches the Linux nci_core_intf_error_ntf).
                    status = pkt[3] if len(pkt) > 3 else 0
                    self._drain()
                    raise CommandError(
                        "controller reported %s (0x%02x) during the exchange"
                        % (STATUS_NAMES.get(status, "an error"), status),
                        status)
                # anything else is a notification we do not care about


def _parse_discover_ntf(pkt):
    """Pull ``(discovery_id, protocol, technology, params)`` out of an
    RF_DISCOVER_NTF, or ``None`` if the frame is too short to be one."""
    if len(pkt) < 8:
        return None
    disc_id = pkt[3]
    protocol = pkt[4]
    tech = pkt[5]
    n = pkt[6]
    return (disc_id, protocol, tech, bytes(pkt[7:7 + n]))


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

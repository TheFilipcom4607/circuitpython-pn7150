"""Wi-Fi, contact, Bluetooth, HomeKit and dialler records.

The byte layouts here are the ones phones expect, so each test pins the wire
format as well as the round trip: a record that only round-trips through this
library is a record no phone will act on.
"""
import pytest

import pn7150
from pn7150 import NDEFError, NDEFMessage, NDEFRecord


def roundtrip(msg):
    """Re-parse a message the way a reader would, from its own bytes."""
    return NDEFMessage.from_bytes(msg.to_bytes())


# -- phone, SMS, email ------------------------------------------------------

def test_phone_record_is_a_tel_uri_with_the_short_prefix():
    rec = NDEFRecord.tel("+48123456789")
    assert rec.payload[0] == 5              # URI prefix code for "tel:"
    assert rec.value == "tel:+48123456789"
    assert NDEFMessage([rec]).phone == "+48123456789"


def test_tel_adds_the_scheme_only_when_it_is_missing():
    assert NDEFRecord.tel("tel:+48123456789").value == "tel:+48123456789"


def test_phone_survives_a_round_trip_through_bytes():
    assert roundtrip(NDEFMessage.from_tel("+15551234")).phone == "+15551234"


def test_message_without_a_tel_record_has_no_phone():
    assert NDEFMessage.from_uri("https://example.com").phone is None


def test_sms_body_is_percent_encoded():
    rec = NDEFRecord.sms("+15551234", "hi there & bye")
    assert rec.value == "sms:+15551234?body=hi%20there%20%26%20bye"


def test_email_encodes_subject_and_body_as_utf8():
    rec = NDEFRecord.email("a@b.co", "Hej", "cześć")
    assert rec.value == "mailto:a@b.co?subject=Hej&body=cze%C5%9B%C4%87"
    assert rec.payload[0] == 6              # URI prefix code for "mailto:"


def test_email_without_extras_is_a_bare_mailto():
    assert NDEFRecord.email("a@b.co").value == "mailto:a@b.co"


def test_email_reads_back_split_into_its_parts():
    msg = NDEFMessage.from_email("ada@example.com", "Hej cześć", "one & two")
    assert roundtrip(msg).email == {"address": "ada@example.com",
                                    "subject": "Hej cześć",
                                    "body": "one & two"}


def test_a_bare_mailto_reads_back_with_no_subject_or_body():
    assert roundtrip(NDEFMessage.from_email("a@b.co")).email == {
        "address": "a@b.co", "subject": None, "body": None}


def test_a_plus_in_an_address_is_not_a_space():
    """Form encoding says '+' is a space; RFC 6068 mailto says it is a plus."""
    msg = NDEFMessage.from_email("ada+tags@example.com")
    assert roundtrip(msg).email["address"] == "ada+tags@example.com"


def test_email_written_by_something_else_is_still_read():
    """An uppercase scheme, uppercase parameters, and a truncated escape."""
    msg = NDEFMessage.from_uri("MAILTO:a@b.co?SUBJECT=Up&body=x%2")
    assert msg.email == {"address": "a@b.co", "subject": "Up", "body": "x%2"}
    fallback = NDEFMessage.from_uri("mailto:?to=a@b.co")
    assert fallback.email["address"] == "a@b.co"


def test_message_without_a_mailto_record_has_no_email():
    assert NDEFMessage.from_uri("https://example.com").email is None
    assert NDEFMessage.from_tel("+15551234").email is None


# -- Wi-Fi ------------------------------------------------------------------

def test_wifi_payload_is_a_wsc_credential():
    rec = NDEFRecord.wifi("HomeNet", "correcthorse")
    assert rec.type == b"application/vnd.wfa.wsc"
    assert rec.kind == "wifi"
    # Credential attribute (0x100E) wrapping the whole thing, then SSID.
    assert rec.payload[:4] == b"\x10\x0e\x00\x2c"
    assert b"\x10\x45\x00\x07HomeNet" in rec.payload
    assert b"\x10\x27\x00\x0ccorrecthorse" in rec.payload
    # No MAC attribute unless asked for: this is the credential a Pixel 10
    # joined from in the sibling ST25DV driver's hardware run.
    assert b"\x10\x20" not in rec.payload


def test_wifi_defaults_to_wpa2_psk_with_aes():
    creds = NDEFMessage.from_wifi("HomeNet", "correcthorse").wifi
    assert creds["authentication"] == pn7150.WIFI_WPA2_PSK
    assert creds["encryption"] == pn7150.WIFI_ENC_AES
    assert creds["security"] == "wpa2"
    assert creds["mac"] is None


def test_wifi_without_a_password_is_an_open_network():
    creds = NDEFMessage.from_wifi("Guest").wifi
    assert creds["authentication"] == pn7150.WIFI_OPEN
    assert creds["encryption"] == pn7150.WIFI_ENC_NONE
    assert creds["security"] == "open"
    assert creds["password"] == ""


def test_wifi_round_trips_through_bytes():
    msg = NDEFMessage.from_wifi("HomeNet", "correcthorse")
    assert roundtrip(msg).wifi == msg.wifi
    assert roundtrip(msg).wifi["ssid"] == "HomeNet"
    assert roundtrip(msg).wifi["password"] == "correcthorse"


def test_wifi_keeps_a_utf8_ssid():
    msg = NDEFMessage.from_wifi("kawiarnia ☕", "correcthorse")
    assert roundtrip(msg).wifi["ssid"] == "kawiarnia ☕"


def test_wifi_accepts_an_explicit_ap_and_cipher():
    rec = NDEFRecord.wifi("HomeNet", "correcthorse",
                          authentication=pn7150.WIFI_WPA_WPA2_PSK,
                          encryption=pn7150.WIFI_ENC_AES_TKIP,
                          mac="AA:BB:CC:DD:EE:FF")
    creds = rec.value
    assert creds["authentication"] == pn7150.WIFI_WPA_WPA2_PSK
    assert creds["encryption"] == pn7150.WIFI_ENC_AES_TKIP
    assert creds["mac"] == "aa:bb:cc:dd:ee:ff"


def test_wifi_refuses_a_passphrase_no_access_point_would_accept():
    with pytest.raises(NDEFError):
        NDEFRecord.wifi("HomeNet", "short")


def test_wifi_refuses_an_open_network_with_a_password():
    """Rather than writing a credential that quietly drops the password."""
    with pytest.raises(NDEFError):
        NDEFRecord.wifi("HomeNet", "correcthorse",
                        authentication=pn7150.WIFI_OPEN)


def test_wifi_refuses_an_ssid_that_does_not_fit():
    with pytest.raises(NDEFError):
        NDEFRecord.wifi("x" * 33, "correcthorse")
    with pytest.raises(NDEFError):
        NDEFRecord.wifi("")


def test_a_truncated_credential_decodes_to_blanks_rather_than_raising():
    rec = NDEFRecord(pn7150.TNF_MIME, b"application/vnd.wfa.wsc",
                     b"\x10\x0e\x00\xff\x01")
    assert rec.value["ssid"] is None


# -- contacts ---------------------------------------------------------------

def test_contact_is_a_vcard_3_with_the_name_split():
    rec = NDEFRecord.contact("Ada Lovelace", phone="+48123456789")
    text = rec.payload.decode()
    assert rec.type == b"text/vcard"
    assert text.startswith("BEGIN:VCARD\r\nVERSION:3.0\r\n")
    assert "N:Lovelace;Ada;;;\r\n" in text
    assert "FN:Ada Lovelace\r\n" in text
    assert "TEL;TYPE=CELL:+48123456789\r\n" in text
    assert text.endswith("END:VCARD\r\n")


def test_contact_round_trips_every_field():
    msg = NDEFMessage.from_contact(
        "Ada Lovelace", phone=["+48123456789", "+1555"],
        email="ada@example.com", organization="Analytical Co",
        title="Engineer", url="https://ada.example",
        address="12 Baker St", note="met at the fair")
    card = roundtrip(msg).contact
    assert card["name"] == "Ada Lovelace"
    assert card["phone"] == ["+48123456789", "+1555"]
    assert card["email"] == ["ada@example.com"]
    assert card["organization"] == "Analytical Co"
    assert card["title"] == "Engineer"
    assert card["url"] == "https://ada.example"
    assert card["address"] == "12 Baker St"
    assert card["note"] == "met at the fair"


def test_contact_escapes_and_restores_separators():
    msg = NDEFMessage.from_contact("Ada", organization="Analytical; Co",
                                   note="one\ntwo")
    card = roundtrip(msg).contact
    assert card["organization"] == "Analytical; Co"
    assert card["note"] == "one\ntwo"


def test_a_one_word_name_still_produces_a_structured_name():
    assert "N:;Prince;;;\r\n" in NDEFRecord.contact("Prince").payload.decode()


def test_a_contact_needs_a_name():
    with pytest.raises(NDEFError):
        NDEFRecord.contact(phone="+1555")


def test_a_contact_can_be_given_its_name_in_halves():
    assert NDEFRecord.contact(first="Grace", last="Hopper").payload == \
        NDEFRecord.contact("Grace Hopper").payload


def test_a_vcard_from_a_phone_is_read_back():
    """Folded continuation lines, an item group, and x-vCard as the type."""
    card = NDEFRecord(
        pn7150.TNF_MIME, b"text/x-vCard",
        b"BEGIN:VCARD\r\nVERSION:2.1\r\nN:Hopper;Grace;;;\r\n"
        b"item1.TEL;TYPE=WORK:+1 202\r\nADR;TYPE=HOME:;;12 Baker St;London;;"
        b"NW1;UK\r\nEND:VCARD\r\n").value
    assert card["name"] == "Grace Hopper"        # no FN, so N is used
    assert card["phone"] == ["+1 202"]
    assert card["address"] == "12 Baker St, London, NW1, UK"


def test_a_vcard_full_of_junk_decodes_to_blanks_rather_than_raising():
    assert NDEFRecord.vcard("garbage").value["name"] is None


# -- Bluetooth --------------------------------------------------------------

def test_bluetooth_oob_is_length_then_address_little_endian_then_eir():
    rec = NDEFRecord.bluetooth("AA:BB:CC:DD:EE:FF", "Speaker",
                               class_of_device=0x240404)
    assert rec.type == b"application/vnd.bluetooth.ep.oob"
    assert rec.kind == "bluetooth"
    assert rec.payload[0] == len(rec.payload)    # the length counts itself
    assert rec.payload[2:8] == b"\xff\xee\xdd\xcc\xbb\xaa"
    # Name first, then class of device, little-endian: the tested order.
    assert rec.payload[8:] == b"\x08\x09Speaker\x04\x0d\x04\x04\x24"


def test_bluetooth_round_trips():
    msg = NDEFMessage.from_bluetooth("AA:BB:CC:DD:EE:FF", "Speaker",
                                     class_of_device=0x240404)
    device = roundtrip(msg).bluetooth
    assert device["address"] == "aa:bb:cc:dd:ee:ff"
    assert device["name"] == "Speaker"
    assert device["class_of_device"] == 0x240404
    assert device["low_energy"] is False


def test_bluetooth_takes_the_address_with_any_separator_or_as_bytes():
    wanted = NDEFRecord.bluetooth("AA:BB:CC:DD:EE:FF").payload
    assert NDEFRecord.bluetooth("aa-bb-cc-dd-ee-ff").payload == wanted
    assert NDEFRecord.bluetooth("AABBCCDDEEFF").payload == wanted
    assert NDEFRecord.bluetooth(b"\xaa\xbb\xcc\xdd\xee\xff").payload == wanted


def test_bluetooth_refuses_an_address_that_is_not_one():
    with pytest.raises(NDEFError):
        NDEFRecord.bluetooth("AA:BB:CC")
    with pytest.raises(NDEFError):
        NDEFRecord.bluetooth("ZZ:BB:CC:DD:EE:FF")


def test_bluetooth_le_carries_the_address_type_and_role():
    rec = NDEFRecord.bluetooth_le("AA:BB:CC:DD:EE:FF", address_type=1,
                                  name="Tag")
    assert rec.type == b"application/vnd.bluetooth.le.oob"
    assert rec.kind == "bluetooth_le"
    # AD type 0x1B: six address bytes little-endian, then 1 for "random".
    assert rec.payload[:9] == b"\x08\x1b\xff\xee\xdd\xcc\xbb\xaa\x01"
    device = rec.value
    assert device["address"] == "aa:bb:cc:dd:ee:ff"
    assert device["address_type"] == "random"
    assert device["role"] == "peripheral"
    assert device["low_energy"] is True
    assert NDEFMessage([rec]).bluetooth_le == device
    assert NDEFMessage([rec]).bluetooth is None


def test_a_short_oob_payload_decodes_to_blanks_rather_than_raising():
    rec = NDEFRecord(pn7150.TNF_MIME, b"application/vnd.bluetooth.ep.oob",
                     b"\x03\x00")
    assert rec.value["address"] is None


def test_handover_select_lists_each_carrier_by_record_id():
    carrier = NDEFRecord.bluetooth("AA:BB:CC:DD:EE:FF", "Speaker")
    msg = NDEFMessage.handover_select([carrier])
    assert [rec.kind for rec in msg] == ["handover", "bluetooth"]
    assert msg.records[0].type == b"Hs"
    assert msg.records[0].payload[0] == 0x12          # handover version 1.2
    assert msg.records[1].id == b"0"
    # The Hs payload carries an "ac" record naming that same id.
    inner = NDEFMessage.from_bytes(msg.records[0].payload[1:])
    assert inner.records[0].type == b"ac"
    assert inner.records[0].payload == b"\x01\x010\x00"
    # And a reader still finds the device.
    assert roundtrip(msg).bluetooth["name"] == "Speaker"


# -- HomeKit ----------------------------------------------------------------

def test_homekit_uri_matches_the_reference_encoding():
    """Checked against the packing HAP-python and HAP-NodeJS both use."""
    rec = NDEFRecord.homekit("518-08-361", category=pn7150.HOMEKIT_LIGHTBULB,
                             setup_id="7OSX")
    assert rec.value == "X-HM://0052VG2ND7OSX"
    assert NDEFRecord.homekit(12345678, category=pn7150.HOMEKIT_SWITCH,
                              setup_id="ABCD").value == "X-HM://0080RMC0EABCD"


def test_homekit_round_trips_its_fields():
    msg = NDEFMessage.from_homekit("518-08-361",
                                   category=pn7150.HOMEKIT_LIGHTBULB,
                                   setup_id="7OSX")
    setup = roundtrip(msg).homekit
    assert setup["setup_code"] == "518-08-361"
    assert setup["category"] == pn7150.HOMEKIT_LIGHTBULB
    assert setup["flags"] == pn7150.HOMEKIT_PAIR_IP
    assert setup["setup_id"] == "7OSX"
    assert setup["version"] == 0
    assert setup["uri"] == "X-HM://0052VG2ND7OSX"


def test_homekit_takes_the_code_with_or_without_dashes():
    assert (NDEFRecord.homekit("51808361").value
            == NDEFRecord.homekit("518-08-361").value)


def test_homekit_passes_a_whole_uri_through():
    rec = NDEFRecord.homekit("X-HM://0052VG2ND7OSX")
    assert rec.value == "X-HM://0052VG2ND7OSX"
    assert NDEFMessage([rec]).homekit["setup_code"] == "518-08-361"


def test_homekit_handles_every_category_and_the_largest_code():
    for category in range(1, 256):
        msg = NDEFMessage.from_homekit("99999999", category=category,
                                       setup_id="ZZZZ",
                                       flags=pn7150.HOMEKIT_PAIR_BLE)
        setup = msg.homekit
        assert setup["category"] == category
        assert setup["setup_code"] == "999-99-999"
        assert setup["flags"] == pn7150.HOMEKIT_PAIR_BLE


def test_homekit_refuses_a_code_that_is_not_eight_digits():
    with pytest.raises(NDEFError):
        NDEFRecord.homekit("12345")
    with pytest.raises(NDEFError):
        NDEFRecord.homekit(123456789)


def test_a_uri_that_only_looks_like_homekit_is_not_decoded():
    assert NDEFMessage.from_uri("X-HM://nonsense!").homekit is None
    assert NDEFMessage.from_uri("https://example.com").homekit is None


# -- the rest of the driver keeps working with these records ----------------

def test_records_still_compare_and_dump():
    msg = NDEFMessage.from_wifi("HomeNet", "correcthorse")
    assert roundtrip(msg) == msg
    assert "wifi" in repr(msg.records[0])


def test_a_written_tag_takes_any_of_them(monkeypatch):
    """write_ndef() coerces through this same path; only size can refuse."""
    from pn7150 import _ndef_to_tlv
    for msg in (NDEFMessage.from_wifi("HomeNet", "correcthorse"),
                NDEFMessage.from_contact("Ada Lovelace", phone="+1555"),
                NDEFMessage.from_homekit("518-08-361"),
                NDEFMessage.from_bluetooth("AA:BB:CC:DD:EE:FF", "Speaker")):
        tlv = _ndef_to_tlv(msg)
        assert pn7150._ndef_from_tlv(tlv) == msg


# -- the same bytes the sibling driver was tapped with ----------------------
#
# circuitpython-st25dv implements these records too, and was tapped against a
# Pixel 10 and an iPhone 16 Pro. Every builder here emits byte-identical
# payloads, so that hardware run carries over - which it stops doing the
# moment one of these drifts. The literals below come from that driver.

def test_wifi_credential_matches_the_tested_driver():
    assert NDEFRecord.wifi("Guest Wi-Fi", "correct horse").payload == (
        b"\x10\x0e\x001\x10&\x00\x01\x01\x10E\x00\x0bGuest Wi-Fi"
        b"\x10\x03\x00\x02\x00 \x10\x0f\x00\x02\x00\x08"
        b"\x10'\x00\rcorrect horse")


def test_bluetooth_oob_matches_the_tested_driver():
    rec = NDEFRecord.bluetooth("a4:c1:38:01:02:03", "Speaker",
                               class_of_device=0x240404)
    assert rec.payload == (
        b"\x16\x00\x03\x02\x018\xc1\xa4\x08\tSpeaker\x04\r\x04\x04$")


def test_bluetooth_le_oob_matches_the_tested_driver():
    rec = NDEFRecord.bluetooth_le("a4:c1:38:01:02:03", name="Tag")
    assert rec.payload == (
        b"\x08\x1b\x03\x02\x018\xc1\xa4\x00\x02\x1c\x00\x04\tTag")


def test_vcard_matches_the_tested_driver():
    assert NDEFRecord.contact(
        "Grace Hopper", phone="+1 202", email="g@navy.mil",
        organization="Navy", title="Rear Admiral", url="https://navy.mil",
        address="12 Baker St", note="COBOL").payload == (
        b"BEGIN:VCARD\r\nVERSION:3.0\r\nN:Hopper;Grace;;;\r\n"
        b"FN:Grace Hopper\r\nTEL;TYPE=CELL:+1 202\r\n"
        b"EMAIL;TYPE=INTERNET:g@navy.mil\r\nORG:Navy\r\n"
        b"TITLE:Rear Admiral\r\nURL:https://navy.mil\r\n"
        b"ADR;TYPE=HOME:;;12 Baker St\r\nNOTE:COBOL\r\nEND:VCARD\r\n")


def test_sms_matches_the_tested_driver():
    assert NDEFRecord.sms("+12025550100", "on my way!").payload == (
        b"\x00sms:+12025550100?body=on%20my%20way%21")

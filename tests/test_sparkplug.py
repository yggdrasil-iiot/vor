"""The protobuf reader against payloads built field by field, both UInt32 slots, and unknown fields."""

import pytest

from helpers import _field, metric, payload
from vor import sparkplug


def test_scalar_metric_with_properties():
    p = sparkplug.decode(payload(7, metric("Temp", 200.5, timestamp=1234, status=0x808B0000, server=1300, quality=0),
                                 timestamp=99))
    assert (p.timestamp, p.seq) == (99, 7)
    m = p.metrics[0]
    assert (m.name, m.datatype, m.value, m.timestamp) == ("Temp", sparkplug.DOUBLE, 200.5, 1234)
    assert m.properties == {"Quality": 0, "ua_statuscode": 0x808B0000, "ua_server_timestamp": 1300}


@pytest.mark.parametrize("slot", ["int", "long"])
def test_uint32_from_either_slot(slot):
    m = sparkplug.decode(payload(1, metric("T", status=0xC0000000, status_slot=slot))).metrics[0]
    assert m.properties["ua_statuscode"] == 0xC0000000


def test_negative_int32_property():
    body = _field(1, 2, b"Quality") + _field(2, 2, _field(1, 0, 3) + _field(3, 0, 0xFFFFFFFF))
    m = sparkplug.decode(payload(1, _field(1, 2, b"T") + _field(4, 0, 10) + _field(9, 2, body))).metrics[0]
    assert m.properties["Quality"] == -1


def test_absent_timestamp_stays_absent():
    m = sparkplug.decode(payload(1, metric("Temp", timestamp=None))).metrics[0]
    assert m.timestamp is None


def test_unknown_fields_are_skipped():
    extra = _field(99, 2, b"future") + _field(98, 0, 5)
    p = sparkplug.decode(payload(3, metric("Temp", 1.0) + extra) + extra)
    assert p.seq == 3 and p.metrics[0].value == 1.0


def test_truncated_input_is_an_error():
    with pytest.raises(sparkplug.DecodeError):
        sparkplug.decode(payload(1, metric("Temp"))[:-3])

"""Payloads a real Muninn published (feed --session 1000 --hierarchy, against the Bifrost sim, after a rebirth request),
captured off the broker byte for byte: NBIRTH, DBIRTH and two DDATA of one session."""

from helpers import DEVICE, FIXTURES, TOPIC
from vor import sparkplug
from vor.sparkplug import _fields
from vor.stream import SampleCache

WIRE = FIXTURES / "muninn-wire"
GROUP, EDGE = "Bifrost:Line1", "recipe-edge"
TOPICS = [f"spBv1.0/{GROUP}/NBIRTH/{EDGE}", TOPIC.replace("DDATA", "DBIRTH"), TOPIC, TOPIC]
FILES = ["1-nbirth.bin", "2-dbirth.bin", "3-ddata.bin", "4-ddata.bin"]


def raw(name: str) -> bytes:
    return (WIRE / name).read_bytes()


def test_one_session_in_sequence():
    payloads = [sparkplug.decode(raw(f)) for f in FILES]
    assert [p.seq for p in payloads] == [0, 1, 2, 3]
    birth = {m.name: m.value for m in payloads[0].metrics}
    assert birth["bdSeq"] == 0 and birth["Node Control/Rebirth"] is False
    assert [m.name for m in payloads[1].metrics] == ["Rpm", "Temp", "Running", "Secret"]


def test_every_sample_metric_carries_source_time_and_ua_metadata():
    for f in FILES[1:]:
        for m in sparkplug.decode(raw(f)).metrics:
            assert m.timestamp is not None, (f, m.name)
            assert set(m.properties) == {"Quality", "ua_statuscode", "ua_server_timestamp"}, (f, m.name)
            assert m.properties["Quality"] == 192 and m.properties["ua_statuscode"] == 0


def test_tahu_writes_the_uint32_status_code_in_the_long_slot():
    """PropertyValue type 7 (UInt32) arrives in field 4 (long_value), not field 3 (int_value)."""
    metric = next(v for n, _, v in _fields(raw("3-ddata.bin")) if n == 2)
    props = next(v for n, _, v in _fields(metric) if n == 9)
    values = [dict((n, v) for n, _, v in _fields(pv)) for n, _, pv in _fields(props) if n == 2]
    status = next(v for v in values if v[1] == sparkplug.UINT32)
    assert 4 in status and 3 not in status


def test_the_cache_takes_the_latest_temp_from_the_real_session():
    c = SampleCache(clock_ms=lambda: 7)
    for topic, f in zip(TOPICS, FILES):
        c.on_message(topic, raw(f))
    s = c.get(GROUP, EDGE, DEVICE, "Temp")
    last = next(m for m in sparkplug.decode(raw("4-ddata.bin")).metrics if m.name == "Temp")
    assert (s.value, s.seq, s.device, s.datatype) == (200.0, 3, DEVICE, sparkplug.DOUBLE)
    assert (s.source_timestamp, s.server_timestamp, s.status_code, s.quality) == (
        last.timestamp, last.properties["ua_server_timestamp"], 0, 192)

"""The sample cache: sessions, sequence numbers, deaths, and no metadata carried over between messages."""

from helpers import DEVICE, TOPIC, metric, payload
from vor import sparkplug
from vor.stream import SampleCache

GROUP, EDGE = "Bifrost:Line1", "recipe-edge"
NBIRTH, NDEATH = f"spBv1.0/{GROUP}/NBIRTH/{EDGE}", f"spBv1.0/{GROUP}/NDEATH/{EDGE}"
DBIRTH, DDEATH = TOPIC.replace("DDATA", "DBIRTH"), TOPIC.replace("DDATA", "DDEATH")
MIXER2 = "synthetic-site:line1:mixer2"
TOPIC2 = TOPIC.replace(DEVICE, MIXER2)


def cache() -> SampleCache:
    return SampleCache(clock_ms=lambda: 42)


def temp(c: SampleCache):
    return c.get(GROUP, EDGE, DEVICE, "Temp")


def test_birth_then_data_is_cached_with_its_metadata():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(DBIRTH, payload(1, metric("Temp", 200.0, timestamp=1000, server=1100)))
    c.on_message(TOPIC, payload(2, metric("Temp", 201.5, timestamp=2000, server=2100, status=0x808B0000, quality=0)))
    s = temp(c)
    assert (s.value, s.source_timestamp, s.server_timestamp, s.status_code, s.quality) == (201.5, 2000, 2100,
                                                                                            0x808B0000, 0)
    assert s.device == DEVICE and s.received_at == 42 and s.seq == 2 and s.datatype == sparkplug.DOUBLE


def test_data_outside_a_session_is_not_cached():
    c = cache()
    c.on_message(TOPIC, payload(5, metric("Temp", timestamp=1)))
    assert temp(c) is None


def test_a_sequence_gap_drops_the_samples_until_the_next_birth():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", timestamp=1)))
    c.on_message(TOPIC, payload(3, metric("Temp", timestamp=2)))
    assert temp(c) is None
    c.on_message(TOPIC, payload(4, metric("Temp", timestamp=3)))
    assert temp(c) is None
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", timestamp=4)))
    assert temp(c).source_timestamp == 4


def test_sequence_wraps_after_255():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    for seq in list(range(1, 256)) + [0, 1]:
        c.on_message(TOPIC, payload(seq, metric("Temp", timestamp=seq + 1)))
    assert temp(c).seq == 1


def test_node_death_and_device_death_drop_the_samples():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", timestamp=1)))
    c.on_message(DDEATH, payload(2))
    assert temp(c) is None
    c.on_message(TOPIC, payload(3, metric("Temp", timestamp=2)))
    c.on_message(NDEATH, payload(None))
    assert temp(c) is None


def test_metadata_is_never_inherited_from_an_earlier_message():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", timestamp=1000, server=1100)))
    c.on_message(TOPIC, payload(2, metric("Temp", timestamp=None, status=None, server=None, quality=None)))
    s = temp(c)
    assert (s.source_timestamp, s.status_code, s.server_timestamp, s.quality) == (None, None, None, None)


def test_an_undecodable_message_ends_the_session():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", timestamp=1)))
    c.on_message(TOPIC, b"\x0a\xff")
    assert temp(c) is None


def test_other_namespaces_are_ignored():
    c = cache()
    c.on_message("spAv1.0/x/NBIRTH/y", payload(0))
    c.on_message("plain/topic", b"")
    assert temp(c) is None


def test_two_devices_on_one_edge_keep_their_own_sample_of_the_same_metric():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", 201.0, timestamp=1)))
    c.on_message(TOPIC2, payload(2, metric("Temp", 999.0, timestamp=2)))
    assert (temp(c).value, temp(c).device) == (201.0, DEVICE)
    assert (c.get(GROUP, EDGE, MIXER2, "Temp").value, c.get(GROUP, EDGE, MIXER2, "Temp").device) == (999.0, MIXER2)


def test_node_data_is_not_a_device_sample():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(f"spBv1.0/{GROUP}/NDATA/{EDGE}", payload(1, metric("Temp", 5.0, timestamp=1)))
    assert temp(c) is None and c.get(GROUP, EDGE, None, "Temp").value == 5.0


def test_a_device_death_drops_only_that_device():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC, payload(1, metric("Temp", 201.0, timestamp=1)))
    c.on_message(TOPIC2, payload(2, metric("Temp", 999.0, timestamp=2)))
    c.on_message(DDEATH.replace(DEVICE, MIXER2), payload(3))
    assert temp(c).value == 201.0 and c.get(GROUP, EDGE, MIXER2, "Temp") is None


def test_elsewhere_names_the_latest_sample_of_the_metric_under_another_device():
    c = cache()
    c.on_message(NBIRTH, payload(0))
    c.on_message(TOPIC2, payload(1, metric("Temp", 999.0, timestamp=1)))
    assert c.elsewhere(GROUP, EDGE, DEVICE, "Temp").device == MIXER2
    c.on_message(TOPIC, payload(2, metric("Temp", 201.0, timestamp=2)))
    assert c.elsewhere(GROUP, EDGE, MIXER2, "Temp").device == DEVICE
    assert c.elsewhere(GROUP, EDGE, DEVICE, "Rpm") is None

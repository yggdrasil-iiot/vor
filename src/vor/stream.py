"""Keeps the latest Sparkplug B sample of every metric Muninn publishes, and nothing older.

A sample is cached only inside a session Vor saw begin: an NBIRTH (seq 0) opens it and every later message of that
edge node must carry the next seq (0-255, wrapping). A gap, an NDEATH or a DDEATH drops the cached samples, and data
that arrives outside an open session is not cached, so a reader started mid-session reports no sample until the next
birth. Each sample replaces the previous one whole: metadata is never carried over from an earlier message.

Samples are keyed by group, edge, device and metric, so two devices of one edge that publish the same metric name
keep a sample each; node-level data (NBIRTH, NDATA) has no device.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from . import sparkplug

NAMESPACE = "spBv1.0"
QUALITY, UA_STATUSCODE, UA_SERVER_TIMESTAMP = "Quality", "ua_statuscode", "ua_server_timestamp"


@dataclass(frozen=True)
class Sample:
    topic: str
    device: str | None
    metric: str
    datatype: int | None
    value: object
    quality: int | None
    status_code: int | None
    source_timestamp: int | None
    server_timestamp: int | None
    received_at: int
    seq: int | None


class SampleCache:
    def __init__(self, clock_ms=lambda: time.time_ns() // 1_000_000):
        self._clock_ms = clock_ms
        self._lock = threading.Lock()
        self._next_seq: dict[tuple[str, str], int] = {}
        self._samples: dict[tuple[str, str, str | None, str], Sample] = {}

    def get(self, group: str, edge: str, device: str | None, metric: str) -> Sample | None:
        with self._lock:
            return self._samples.get((group, edge, device, metric))

    def elsewhere(self, group: str, edge: str, device: str | None, metric: str) -> Sample | None:
        """The most recently received sample of the metric on the edge under any device other than this one."""
        with self._lock:
            others = [s for k, s in self._samples.items()
                      if k[0] == group and k[1] == edge and k[2] != device and k[3] == metric]
        return max(others, key=lambda s: s.received_at, default=None)

    def _drop(self, group: str, edge: str, device: str | None = None) -> None:
        for key in [k for k in self._samples
                    if k[0] == group and k[1] == edge and (device is None or k[2] == device)]:
            del self._samples[key]

    def on_message(self, topic: str, data: bytes) -> None:
        received_at = self._clock_ms()
        parts = topic.split("/")
        if len(parts) < 4 or parts[0] != NAMESPACE:
            return
        group, kind, edge = parts[1], parts[2], parts[3]
        device = parts[4] if len(parts) > 4 else None
        try:
            payload = sparkplug.decode(data)
        except sparkplug.DecodeError:
            with self._lock:
                self._next_seq.pop((group, edge), None)
                self._drop(group, edge)
            return
        node = (group, edge)
        with self._lock:
            if kind == "NDEATH":
                self._next_seq.pop(node, None)
                self._drop(group, edge)
                return
            if kind == "NBIRTH":
                self._drop(group, edge)
                if payload.seq == 0:
                    self._next_seq[node] = 1
                else:
                    self._next_seq.pop(node, None)
                return
            if kind not in ("NDATA", "DBIRTH", "DDATA", "DDEATH"):
                return
            expected = self._next_seq.get(node)
            if expected is None:
                return
            if payload.seq != expected:
                self._next_seq.pop(node, None)
                self._drop(group, edge)
                return
            self._next_seq[node] = (expected + 1) % 256
            if kind == "DDEATH":
                self._drop(group, edge, device)
                return
            for m in payload.metrics:
                if m.name is None:
                    continue
                props = m.properties
                self._samples[(group, edge, device, m.name)] = Sample(
                    topic=topic, device=device, metric=m.name, datatype=m.datatype, value=m.value,
                    quality=props.get(QUALITY), status_code=props.get(UA_STATUSCODE),
                    source_timestamp=m.timestamp, server_timestamp=props.get(UA_SERVER_TIMESTAMP),
                    received_at=received_at, seq=payload.seq)


class MqttFeed:
    """Subscribes to every Sparkplug B topic on the broker and feeds the cache. Read-only: it publishes nothing."""

    def __init__(self, url: str, cache: SampleCache, client_id: str = "vor-reader"):
        import paho.mqtt.client as mqtt

        u = urlparse(url)
        self.host, self.port = u.hostname or "localhost", u.port or 1883
        self.cache = cache
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=True)
        self.client.on_connect = self._on_connect
        self.client.on_message = lambda _c, _u, msg: cache.on_message(msg.topic, msg.payload)
        self.subscribed = threading.Event()
        self.client.on_subscribe = lambda *_: self.subscribed.set()

    def _on_connect(self, client, _userdata, _flags, reason_code, _properties):
        if not reason_code.is_failure:
            client.subscribe(f"{NAMESPACE}/#", qos=1)

    def start(self) -> None:
        self.client.connect_async(self.host, self.port)
        self.client.loop_start()

    def stop(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()

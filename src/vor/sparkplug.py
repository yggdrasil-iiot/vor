"""Decodes the part of a Sparkplug B payload Vor reads, straight from the protobuf wire format.

Field numbers are those of the Sparkplug B payload definition (Payload, Metric, PropertySet, PropertyValue). Only
scalar metrics are decoded; DataSet, Template and Extension values are skipped. Unknown fields are skipped by wire
type, so a newer writer does not break this reader.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Sparkplug B DataType codes.
INT8, INT16, INT32, INT64 = 1, 2, 3, 4
UINT8, UINT16, UINT32, UINT64 = 5, 6, 7, 8
FLOAT, DOUBLE, BOOLEAN, STRING, DATETIME, TEXT = 9, 10, 11, 12, 13, 14
BYTES = 17
NUMERIC = {INT8, INT16, INT32, INT64, UINT8, UINT16, UINT32, UINT64, FLOAT, DOUBLE}


class DecodeError(ValueError):
    pass


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf):
            raise DecodeError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise DecodeError("varint too long")


def _fields(buf: bytes):
    """(field number, wire type, value) for each field; value is int for varint/fixed, bytes for length-delimited."""
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 1:
            if i + 8 > len(buf):
                raise DecodeError("truncated fixed64")
            value, i = buf[i:i + 8], i + 8
        elif wire == 2:
            n, i = _varint(buf, i)
            if i + n > len(buf):
                raise DecodeError("truncated bytes")
            value, i = buf[i:i + n], i + n
        elif wire == 5:
            if i + 4 > len(buf):
                raise DecodeError("truncated fixed32")
            value, i = buf[i:i + 4], i + 4
        else:
            raise DecodeError(f"wire type {wire}")
        yield number, wire, value


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def _scalar(datatype: int, slots: dict):
    """The typed value of a Metric or PropertyValue from its value slots."""
    if datatype in (INT8, INT16, INT32):
        v = slots.get("int")
        return None if v is None else _signed(v, 32)
    if datatype in (UINT8, UINT16):
        return slots.get("int")
    if datatype == UINT32:
        # Writers differ: the Sparkplug 3.0 text puts UInt32 in the int slot, Eclipse Tahu writes the long slot.
        v = slots.get("long", slots.get("int"))
        return None if v is None else v & 0xFFFFFFFF
    if datatype == INT64:
        v = slots.get("long")
        return None if v is None else _signed(v, 64)
    if datatype in (UINT64, DATETIME):
        return slots.get("long")
    if datatype == FLOAT:
        return slots.get("float")
    if datatype == DOUBLE:
        return slots.get("double")
    if datatype == BOOLEAN:
        return slots.get("bool")
    if datatype in (STRING, TEXT):
        return slots.get("string")
    if datatype == BYTES:
        return slots.get("bytes")
    return None


@dataclass
class Metric:
    name: str | None = None
    alias: int | None = None
    timestamp: int | None = None
    datatype: int | None = None
    is_null: bool = False
    value: object = None
    properties: dict = field(default_factory=dict)


@dataclass
class Payload:
    timestamp: int | None = None
    seq: int | None = None
    metrics: list[Metric] = field(default_factory=list)


def _property_set(buf: bytes) -> dict:
    keys, values = [], []
    for number, wire, v in _fields(buf):
        if number == 1 and wire == 2:
            keys.append(v.decode("utf-8"))
        elif number == 2 and wire == 2:
            values.append(_property_value(v))
    if len(keys) != len(values):
        raise DecodeError("property keys and values differ in count")
    return dict(zip(keys, values))


def _property_value(buf: bytes):
    datatype, is_null, slots = None, False, {}
    for number, wire, v in _fields(buf):
        if number == 1 and wire == 0:
            datatype = v
        elif number == 2 and wire == 0:
            is_null = bool(v)
        elif number == 3 and wire == 0:
            slots["int"] = v
        elif number == 4 and wire == 0:
            slots["long"] = v
        elif number == 5 and wire == 5:
            slots["float"] = struct.unpack("<f", v)[0]
        elif number == 6 and wire == 1:
            slots["double"] = struct.unpack("<d", v)[0]
        elif number == 7 and wire == 0:
            slots["bool"] = bool(v)
        elif number == 8 and wire == 2:
            slots["string"] = v.decode("utf-8")
    return None if is_null or datatype is None else _scalar(datatype, slots)


def _metric(buf: bytes) -> Metric:
    m, slots = Metric(), {}
    for number, wire, v in _fields(buf):
        if number == 1 and wire == 2:
            m.name = v.decode("utf-8")
        elif number == 2 and wire == 0:
            m.alias = v
        elif number == 3 and wire == 0:
            m.timestamp = v
        elif number == 4 and wire == 0:
            m.datatype = v
        elif number == 7 and wire == 0:
            m.is_null = bool(v)
        elif number == 9 and wire == 2:
            m.properties = _property_set(v)
        elif number == 10 and wire == 0:
            slots["int"] = v
        elif number == 11 and wire == 0:
            slots["long"] = v
        elif number == 12 and wire == 5:
            slots["float"] = struct.unpack("<f", v)[0]
        elif number == 13 and wire == 1:
            slots["double"] = struct.unpack("<d", v)[0]
        elif number == 14 and wire == 0:
            slots["bool"] = bool(v)
        elif number == 15 and wire == 2:
            slots["string"] = v.decode("utf-8")
        elif number == 16 and wire == 2:
            slots["bytes"] = bytes(v)
    if not m.is_null and m.datatype is not None:
        m.value = _scalar(m.datatype, slots)
    return m


def decode(buf: bytes) -> Payload:
    p = Payload()
    for number, wire, v in _fields(buf):
        if number == 1 and wire == 0:
            p.timestamp = v
        elif number == 2 and wire == 2:
            p.metrics.append(_metric(v))
        elif number == 3 and wire == 0:
            p.seq = v
    return p

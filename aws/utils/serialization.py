"""
Enterprise Serialization Utilities

Features
--------
• Dataclass Serialization
• Pydantic Serialization
• Enum Serialization
• Datetime Serialization
• JSON Encoding
• JSON Decoding
"""

from __future__ import annotations

import json

from dataclasses import asdict
from dataclasses import is_dataclass

from datetime import datetime
from datetime import date
from datetime import time

from decimal import Decimal

from enum import Enum

from pathlib import Path

from uuid import UUID

from typing import Any
from collections.abc import Mapping
from collections.abc import Sequence

from datetime import timezone

###########################################################################
# JSON Encoder
###########################################################################

class EnterpriseJSONEncoder(
    json.JSONEncoder,
):

    def default(
        self,
        obj,
    ):

        if isinstance(

            obj,

            (datetime, date, time),

        ):

            return obj.isoformat()

        if isinstance(
            obj,
            UUID,
        ):

            return str(obj)

        if isinstance(
            obj,
            Decimal,
        ):

            return float(obj)

        if isinstance(
            obj,
            Enum,
        ):

            return obj.value

        if is_dataclass(obj):

            return asdict(obj)

        if hasattr(
            obj,
            "model_dump",
        ):

            return obj.model_dump()

        if hasattr(
            obj,
            "dict",
        ):

            return obj.dict()

        if hasattr(
            obj,
            "to_dict",
        ):

            return obj.to_dict()

        return super().default(obj)
    
    ###########################################################################
# Serialize
###########################################################################

def serialize(
    obj: Any,
):

    return json.dumps(

        obj,

        cls=EnterpriseJSONEncoder,

        ensure_ascii=False,

        indent=4,

    )


def serialize_compact(
    obj: Any,
):

    return json.dumps(

        obj,

        cls=EnterpriseJSONEncoder,

        separators=(",", ":"),

    )
    
    ###########################################################################
# Deserialize
###########################################################################

def deserialize(
    text: str,
):

    return json.loads(text)


def deserialize_file(
    path: str | Path,
):

    with open(

        path,

        "r",

        encoding="utf-8",

    ) as file:

        return json.load(file)
    
    ###########################################################################
# Save
###########################################################################

def save_json(
    obj: Any,
    path: str | Path,
):

    with open(

        path,

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            obj,

            file,

            cls=EnterpriseJSONEncoder,

            indent=4,

            ensure_ascii=False,

        )
        
    ###########################################################################
# Load
###########################################################################

def load_json(
    path: str | Path,
):

    with open(

        path,

        "r",

        encoding="utf-8",

    ) as file:

        return json.load(file)
    
    ###########################################################################
# Pretty Print
###########################################################################

def pretty(
    obj: Any,
):

    return serialize(obj)

###########################################################################
# Validation
###########################################################################

def is_json(
    value: str,
) -> bool:

    try:

        json.loads(value)

        return True

    except Exception:

        return False
    
    ###########################################################################
# Recursive Conversion
###########################################################################

def to_serializable(
    obj: Any,
):

    if obj is None:

        return None

    if isinstance(

        obj,

        (str, int, float, bool),

    ):

        return obj

    if isinstance(

        obj,

        (datetime, date, time),

    ):

        return obj.isoformat()

    if isinstance(
        obj,
        UUID,
    ):

        return str(obj)

    if isinstance(
        obj,
        Decimal,
    ):

        return float(obj)

    if isinstance(
        obj,
        Enum,
    ):

        return obj.value

    if is_dataclass(obj):

        return {

            k: to_serializable(v)

            for k, v in asdict(obj).items()

        }

    if hasattr(obj, "model_dump"):

        return to_serializable(
            obj.model_dump()
        )

    if hasattr(obj, "dict"):

        return to_serializable(
            obj.dict()
        )

    if hasattr(obj, "to_dict"):

        return to_serializable(
            obj.to_dict()
        )

    if isinstance(obj, Mapping):

        return {

            str(k): to_serializable(v)

            for k, v in obj.items()

        }

    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):

        return [

            to_serializable(item)

            for item in obj

        ]

    return obj

###########################################################################
# Deep Serialization
###########################################################################

def deep_serialize(
    obj: Any,
):

    return serialize(

        to_serializable(obj)

    )


def deep_dict(
    obj: Any,
):

    return to_serializable(obj)

###########################################################################
# Datetime Restoration
###########################################################################

def parse_datetime(
    value: str,
):

    try:

        return datetime.fromisoformat(

            value.replace(

                "Z",

                "+00:00",

            )

        )

    except Exception:

        return value
    
    ###########################################################################
# Enum Restoration
###########################################################################

def parse_enum(
    enum_type,
    value,
):

    try:

        return enum_type(value)

    except Exception:

        return value
    
    ###########################################################################
# Flatten Dictionary
###########################################################################

def flatten(
    data: dict,
    parent: str = "",
    separator: str = ".",
):

    result = {}

    for key, value in data.items():

        new_key = (

            f"{parent}{separator}{key}"

            if parent

            else key

        )

        if isinstance(value, dict):

            result.update(

                flatten(

                    value,

                    new_key,

                    separator,

                )

            )

        else:

            result[new_key] = value

    return result

###########################################################################
# Unflatten Dictionary
###########################################################################

def unflatten(
    data: dict,
    separator: str = ".",
):

    result = {}

    for key, value in data.items():

        parts = key.split(separator)

        current = result

        for part in parts[:-1]:

            current = current.setdefault(

                part,

                {},

            )

        current[parts[-1]] = value

    return result

###########################################################################
# Batch Serialization
###########################################################################

def serialize_many(
    objects: list[Any],
):

    return [

        deep_dict(obj)

        for obj in objects

    ]


def deserialize_many(
    objects: list[str],
):

    return [

        deserialize(obj)

        for obj in objects

    ]
    
    ###########################################################################
# Dictionary Helpers
###########################################################################

def merge(
    *objects: dict,
):

    result = {}

    for obj in objects:

        result.update(obj)

    return result


def remove_none(
    obj: dict,
):

    return {

        key: value

        for key, value in obj.items()

        if value is not None

    }
    
    ###########################################################################
# Deep Merge
###########################################################################

def deep_merge(
    *objects: dict,
):

    result = {}

    for obj in objects:

        for key, value in obj.items():

            if (

                key in result

                and isinstance(result[key], dict)

                and isinstance(value, dict)

            ):

                result[key] = deep_merge(

                    result[key],

                    value,

                )

            else:

                result[key] = value

    return result

###########################################################################
# Schema
###########################################################################

def schema(
    obj: dict,
):

    result = {}

    for key, value in obj.items():

        result[key] = type(value).__name__

    return result


def validate_schema(
    obj: dict,
    expected: dict,
):

    for key, value_type in expected.items():

        if key not in obj:

            return False

        if type(obj[key]).__name__ != value_type:

            return False

    return True

###########################################################################
# Metadata
###########################################################################

def metadata():

    return {

        "serializer": "EnterpriseJSONEncoder",

        "version": "1.0.0",

        "encoding": "UTF-8",

        "supports_dataclasses": True,

        "supports_pydantic": True,

        "supports_enum": True,

        "supports_datetime": True,

    }
    
    ###########################################################################
# Compression
###########################################################################

import gzip


def compress_json(
    obj,
):

    text = serialize(obj)

    return gzip.compress(

        text.encode("utf-8")

    )


def decompress_json(
    data: bytes,
):

    return deserialize(

        gzip.decompress(data)

        .decode("utf-8")

    )
    
    ###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    return {

        "json_supported": True,

        "encoder": EnterpriseJSONEncoder.__name__,

        "indent": 4,

        "compact_mode": True,

    }
    
    ###########################################################################
# Performance
###########################################################################

import time


def measure_serialization(
    obj,
):

    start = time.perf_counter()

    serialize(obj)

    elapsed = time.perf_counter() - start

    return elapsed


def benchmark(
    obj,
    iterations: int = 100,
):

    start = time.perf_counter()

    for _ in range(iterations):

        serialize(obj)

    return time.perf_counter() - start

###########################################################################
# Self Test
###########################################################################

def self_test():

    sample = {

        "name": "Threat",

        "score": 95,

    }

    encoded = serialize(sample)

    decoded = deserialize(encoded)

    return {

        "passed": decoded == sample,

        "encoder": EnterpriseJSONEncoder.__name__,

    }
    
    ###########################################################################
# Convenience
###########################################################################

def summary(
    obj,
):

    data = deep_dict(obj)

    return {

        "type": type(obj).__name__,

        "fields": len(data)

        if isinstance(data, dict)

        else 0,

        "serialized_size": len(

            serialize_compact(data)

        ),

    }
    
    
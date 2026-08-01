"""
Enterprise Hash Utilities

Features
--------
• MD5
• SHA1
• SHA256
• SHA512
• File Hashing
• Stream Hashing
• Hash Validation
"""

from __future__ import annotations

import hashlib

from pathlib import Path
from typing import BinaryIO
import hmac
import secrets

from collections.abc import Iterable

DEFAULT_CHUNK_SIZE = 1024 * 1024

###########################################################################
# String Hashes
###########################################################################

def md5(
    value: str,
) -> str:

    return hashlib.md5(
        value.encode("utf-8")
    ).hexdigest()


def sha1(
    value: str,
) -> str:

    return hashlib.sha1(
        value.encode("utf-8")
    ).hexdigest()


def sha256(
    value: str,
) -> str:

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def sha512(
    value: str,
) -> str:

    return hashlib.sha512(
        value.encode("utf-8")
    ).hexdigest()
    
    ###########################################################################
# Bytes Hashes
###########################################################################

def md5_bytes(
    data: bytes,
) -> str:

    return hashlib.md5(
        data
    ).hexdigest()


def sha1_bytes(
    data: bytes,
) -> str:

    return hashlib.sha1(
        data
    ).hexdigest()


def sha256_bytes(
    data: bytes,
) -> str:

    return hashlib.sha256(
        data
    ).hexdigest()


def sha512_bytes(
    data: bytes,
) -> str:

    return hashlib.sha512(
        data
    ).hexdigest()
    
    ###########################################################################
# Generic Hash
###########################################################################

_SUPPORTED = {

    "md5": hashlib.md5,

    "sha1": hashlib.sha1,

    "sha224": hashlib.sha224,

    "sha256": hashlib.sha256,

    "sha384": hashlib.sha384,

    "sha512": hashlib.sha512,

    "blake2b": hashlib.blake2b,

    "blake2s": hashlib.blake2s,

    "sha3_256": hashlib.sha3_256,

    "sha3_512": hashlib.sha3_512,

}


def hash_string(
    value: str,
    algorithm: str = "sha256",
) -> str:

    algorithm = algorithm.lower()

    if algorithm not in _SUPPORTED:

        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    return _SUPPORTED[
        algorithm
    ](

        value.encode("utf-8")

    ).hexdigest()
    
    ###########################################################################
# File Hash
###########################################################################

def hash_file(
    path: str | Path,
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:

    algorithm = algorithm.lower()

    if algorithm not in _SUPPORTED:

        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    hasher = _SUPPORTED[
        algorithm
    ]()

    with open(
        path,
        "rb",
    ) as file:

        while True:

            chunk = file.read(
                chunk_size
            )

            if not chunk:

                break

            hasher.update(
                chunk
            )

    return hasher.hexdigest()
    
    ###########################################################################
# Stream Hash
###########################################################################

def hash_stream(
    stream: BinaryIO,
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:

    algorithm = algorithm.lower()

    if algorithm not in _SUPPORTED:

        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    hasher = _SUPPORTED[
        algorithm
    ]()

    while True:

        chunk = stream.read(
            chunk_size
        )

        if not chunk:

            break

        hasher.update(
            chunk
        )

    return hasher.hexdigest()
   
   ###########################################################################
# Validation
###########################################################################

def verify_hash(
    value: str,
    expected: str,
    algorithm: str = "sha256",
) -> bool:

    return (

        hash_string(
            value,
            algorithm,
        )

        ==

        expected.lower()

    )


def verify_file(
    path: str | Path,
    expected: str,
    algorithm: str = "sha256",
) -> bool:

    return (

        hash_file(
            path,
            algorithm,
        )

        ==

        expected.lower()

    )
    
    ###########################################################################
# HMAC
###########################################################################

def hmac_sha256(
    key: str,
    message: str,
) -> str:

    return hmac.new(

        key.encode("utf-8"),

        message.encode("utf-8"),

        hashlib.sha256,

    ).hexdigest()


def hmac_sha512(
    key: str,
    message: str,
) -> str:

    return hmac.new(

        key.encode("utf-8"),

        message.encode("utf-8"),

        hashlib.sha512,

    ).hexdigest()


def verify_hmac(
    key: str,
    message: str,
    expected: str,
    algorithm=hashlib.sha256,
) -> bool:

    digest = hmac.new(

        key.encode("utf-8"),

        message.encode("utf-8"),

        algorithm,

    ).hexdigest()

    return hmac.compare_digest(
        digest,
        expected.lower(),
    )
    
    ###########################################################################
# Secure Random
###########################################################################

def random_token(
    length: int = 32,
) -> str:

    return secrets.token_hex(
        length
    )


def random_urlsafe(
    length: int = 32,
) -> str:

    return secrets.token_urlsafe(
        length
    )


def random_bytes(
    length: int = 32,
) -> bytes:

    return secrets.token_bytes(
        length
    )


def generate_salt(
    length: int = 16,
) -> str:

    return secrets.token_hex(
        length
    )
    
    ###########################################################################
# Multiple Hashes
###########################################################################

def all_hashes(
    value: str,
):

    return {

        "md5": md5(value),

        "sha1": sha1(value),

        "sha256": sha256(value),

        "sha512": sha512(value),

    }


def file_hashes(
    path: str | Path,
):

    return {

        "md5": hash_file(path, "md5"),

        "sha1": hash_file(path, "sha1"),

        "sha256": hash_file(path, "sha256"),

        "sha512": hash_file(path, "sha512"),

    }
    
    ###########################################################################
# Directory Hash
###########################################################################

def hash_directory(
    directory: str | Path,
    algorithm: str = "sha256",
):

    result = {}

    directory = Path(directory)

    for file in sorted(directory.rglob("*")):

        if file.is_file():

            result[str(file.relative_to(directory))] = hash_file(

                file,

                algorithm,

            )

    return result

###########################################################################
# Batch Hashing
###########################################################################

def hash_many(
    values: Iterable[str],
    algorithm: str = "sha256",
):

    return {

        value: hash_string(

            value,

            algorithm,

        )

        for value in values

    }


def verify_many(
    mapping: dict[str, str],
    algorithm: str = "sha256",
):

    return {

        value: verify_hash(

            value,

            digest,

            algorithm,

        )

        for value, digest in mapping.items()

    }
    
    ###########################################################################
# Integrity
###########################################################################

def files_equal(
    first: str | Path,
    second: str | Path,
    algorithm: str = "sha256",
) -> bool:

    return (

        hash_file(first, algorithm)

        ==

        hash_file(second, algorithm)

    )


def changed(
    path: str | Path,
    previous_hash: str,
    algorithm: str = "sha256",
) -> bool:

    return (

        hash_file(path, algorithm)

        !=

        previous_hash

    )
    
    ###########################################################################
# Hash Information
###########################################################################

def algorithm_available(
    algorithm: str,
) -> bool:

    return (

        algorithm.lower()

        in

        hashlib.algorithms_available

    )


def available_algorithms():

    return sorted(

        hashlib.algorithms_available

    )
    
    ###########################################################################
# Serialization
###########################################################################

def digest_info(
    digest: str,
):

    digest = digest.lower()

    return {

        "digest": digest,

        "length": len(digest),

        "bits": len(digest) * 4,

        "bytes": len(digest) // 2,

    }


def serialize_hashes(
    hashes: dict[str, str],
):

    return {

        algorithm.lower(): digest.lower()

        for algorithm, digest in hashes.items()

    }
    
    ###########################################################################
# Hash Detection
###########################################################################

_HASH_LENGTHS = {

    32: "md5",

    40: "sha1",

    56: "sha224",

    64: "sha256",

    96: "sha384",

    128: "sha512",

}


def detect_algorithm(
    digest: str,
):

    return _HASH_LENGTHS.get(

        len(digest),

        "unknown",

    )
    
    ###########################################################################
# Summary
###########################################################################

def hash_summary(
    value: str,
):

    hashes = all_hashes(value)

    return {

        "input_length": len(value),

        "algorithms": len(hashes),

        "hashes": hashes,

    }


def file_summary(
    path: str | Path,
):

    path = Path(path)

    return {

        "name": path.name,

        "size": path.stat().st_size,

        "hashes": file_hashes(path),

    }
    
    ###########################################################################
# Performance
###########################################################################

import time


def measure_hash(
    value: str,
    algorithm: str = "sha256",
):

    start = time.perf_counter()

    digest = hash_string(

        value,

        algorithm,

    )

    elapsed = time.perf_counter() - start

    return {

        "digest": digest,

        "algorithm": algorithm,

        "elapsed": elapsed,

    }


def benchmark_hash(
    value: str,
    iterations: int = 1000,
    algorithm: str = "sha256",
):

    start = time.perf_counter()

    for _ in range(iterations):

        hash_string(

            value,

            algorithm,

        )

    return time.perf_counter() - start

###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    return {

        "available_algorithms": available_algorithms(),

        "default_algorithm": "sha256",

        "chunk_size": DEFAULT_CHUNK_SIZE,

    }
    
    ###########################################################################
# Convenience
###########################################################################

def fingerprint(
    value: str,
):

    digest = sha256(value)

    return ":".join(

        digest[i:i + 2]

        for i in range(

            0,

            len(digest),

            2,

        )

    )


def short_hash(
    value: str,
    length: int = 12,
):

    return sha256(value)[:length]

###########################################################################
# Self Test
###########################################################################

def self_test():

    sample = "ThreatDetection"

    hashes = all_hashes(sample)

    return {

        "passed": (

            verify_hash(

                sample,

                hashes["sha256"],

                "sha256",

            )

            and

            verify_hash(

                sample,

                hashes["md5"],

                "md5",

            )

        ),

        "algorithms": len(hashes),

    }
    
    

"""
Enterprise File Utilities

Features
--------
• JSON
• CSV
• YAML
• Text
• Binary
• File Validation
• Safe File Operations
"""

from __future__ import annotations

import csv
import json
import shutil

from pathlib import Path
from typing import Any
import gzip
import tempfile
import zipfile

from datetime import datetime
try:
    import yaml
except ImportError:
    yaml = None
    
###########################################################################
# Path
###########################################################################

def to_path(
    path: str | Path,
) -> Path:

    return Path(path)


def exists(
    path: str | Path,
) -> bool:

    return to_path(path).exists()


def is_file(
    path: str | Path,
) -> bool:

    return to_path(path).is_file()


def is_directory(
    path: str | Path,
) -> bool:

    return to_path(path).is_dir()


def file_size(
    path: str | Path,
) -> int:

    return to_path(path).stat().st_size
###########################################################################
# JSON
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


def save_json(
    data: Any,
    path: str | Path,
    indent: int = 4,
):

    with open(

        path,

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            data,

            file,

            indent=indent,

            ensure_ascii=False,

        )
    ###########################################################################
# CSV
###########################################################################

def load_csv(
    path: str | Path,
):

    with open(

        path,

        newline="",

        encoding="utf-8",

    ) as file:

        return list(

            csv.DictReader(file)

        )


def save_csv(
    rows: list[dict],
    path: str | Path,
):

    if not rows:

        return

    with open(

        path,

        "w",

        newline="",

        encoding="utf-8",

    ) as file:

        writer = csv.DictWriter(

            file,

            fieldnames=list(rows[0].keys()),

        )

        writer.writeheader()

        writer.writerows(rows)
        
        ###########################################################################
# YAML
###########################################################################

def load_yaml(
    path: str | Path,
):

    if yaml is None:

        raise RuntimeError(

            "PyYAML is not installed."

        )

    with open(

        path,

        "r",

        encoding="utf-8",

    ) as file:

        return yaml.safe_load(file)


def save_yaml(
    data: Any,
    path: str | Path,
):

    if yaml is None:

        raise RuntimeError(

            "PyYAML is not installed."

        )

    with open(

        path,

        "w",

        encoding="utf-8",

    ) as file:

        yaml.safe_dump(

            data,

            file,

            sort_keys=False,

            allow_unicode=True,

        )
        
        ###########################################################################
# Text
###########################################################################

def read_text(
    path: str | Path,
) -> str:

    return to_path(path).read_text(

        encoding="utf-8"

    )


def write_text(
    text: str,
    path: str | Path,
):

    to_path(path).write_text(

        text,

        encoding="utf-8",

    )
    
    ###########################################################################
# Binary
###########################################################################

def read_bytes(
    path: str | Path,
) -> bytes:

    return to_path(path).read_bytes()


def write_bytes(
    data: bytes,
    path: str | Path,
):

    to_path(path).write_bytes(data)
    
    ###########################################################################
# Copy / Move
###########################################################################

def copy(
    source: str | Path,
    destination: str | Path,
):

    shutil.copy2(

        source,

        destination,

    )


def move(
    source: str | Path,
    destination: str | Path,
):

    shutil.move(

        source,

        destination,

    )
    
    ###########################################################################
# Directories
###########################################################################

def ensure_directory(
    path: str | Path,
):

    directory = to_path(path)

    directory.mkdir(

        parents=True,

        exist_ok=True,

    )

    return directory


def remove_directory(
    path: str | Path,
):

    shutil.rmtree(

        path,

        ignore_errors=True,

    )


def clear_directory(
    path: str | Path,
):

    directory = to_path(path)

    if not directory.exists():

        return

    for item in directory.iterdir():

        if item.is_dir():

            shutil.rmtree(item)

        else:

            item.unlink()
    ###########################################################################
# Search
###########################################################################

def list_files(
    directory: str | Path,
    pattern: str = "*",
):

    return list(

        to_path(directory).glob(pattern)

    )


def recursive_files(
    directory: str | Path,
    pattern: str = "*",
):

    return list(

        to_path(directory).rglob(pattern)

    )


def find_file(
    directory: str | Path,
    filename: str,
):

    for file in recursive_files(directory):

        if file.name == filename:

            return file

    return None

###########################################################################
# Extensions
###########################################################################

def extension(
    path: str | Path,
):

    return to_path(path).suffix.lower()


def filename(
    path: str | Path,
):

    return to_path(path).name


def stem(
    path: str | Path,
):

    return to_path(path).stem

###########################################################################
# ZIP
###########################################################################

def zip_file(
    source: str | Path,
    destination: str | Path,
):

    with zipfile.ZipFile(

        destination,

        "w",

        zipfile.ZIP_DEFLATED,

    ) as archive:

        archive.write(

            source,

            arcname=filename(source),

        )


def unzip(
    archive: str | Path,
    destination: str | Path,
):

    with zipfile.ZipFile(

        archive,

        "r",

    ) as zip_ref:

        zip_ref.extractall(destination)
        
    ###########################################################################
# GZIP
###########################################################################

def gzip_file(
    source: str | Path,
    destination: str | Path,
):

    with open(source, "rb") as src:

        with gzip.open(

            destination,

            "wb",

        ) as dst:

            shutil.copyfileobj(

                src,

                dst,

            )


def gunzip(
    source: str | Path,
    destination: str | Path,
):

    with gzip.open(

        source,

        "rb",

    ) as src:

        with open(

            destination,

            "wb",

        ) as dst:

            shutil.copyfileobj(

                src,

                dst,

            )
    ###########################################################################
# Temporary
###########################################################################

def temporary_file(
    suffix: str = "",
):

    return tempfile.NamedTemporaryFile(

        suffix=suffix,

        delete=False,

    )


def temporary_directory():

    return tempfile.TemporaryDirectory()

###########################################################################
# Backup
###########################################################################

def backup(
    path: str | Path,
):

    path = to_path(path)

    timestamp = datetime.utcnow().strftime(

        "%Y%m%d_%H%M%S"

    )

    backup_path = path.with_suffix(

        path.suffix + f".{timestamp}.bak"

    )

    shutil.copy2(

        path,

        backup_path,

    )

    return backup_path


def restore(
    backup_file: str | Path,
    destination: str | Path,
):

    shutil.copy2(

        backup_file,

        destination,

    )
    
    ###########################################################################
# Atomic Write
###########################################################################

def atomic_write(
    text: str,
    destination: str | Path,
):

    destination = to_path(destination)

    temp = destination.with_suffix(

        destination.suffix + ".tmp"

    )

    temp.write_text(

        text,

        encoding="utf-8",

    )

    temp.replace(destination)
    
    ###########################################################################
# Batch
###########################################################################

def copy_many(
    files: list[str | Path],
    destination: str | Path,
):

    ensure_directory(destination)

    for file in files:

        copy(

            file,

            to_path(destination) / filename(file),

        )


def delete_many(
    files: list[str | Path],
):

    for file in files:

        path = to_path(file)

        if path.exists():

            path.unlink()
            
    ###########################################################################
# Metadata
###########################################################################

def metadata(
    path: str | Path,
):

    path = to_path(path)

    stat = path.stat()

    return {

        "name": path.name,

        "stem": path.stem,

        "suffix": path.suffix,

        "absolute_path": str(path.resolve()),

        "size": stat.st_size,

        "created": stat.st_ctime,

        "modified": stat.st_mtime,

        "is_file": path.is_file(),

        "is_directory": path.is_dir(),

    }


def directory_size(
    directory: str | Path,
):

    total = 0

    for file in recursive_files(directory):

        if file.is_file():

            total += file.stat().st_size

    return total

###########################################################################
# Statistics
###########################################################################

def directory_statistics(
    directory: str | Path,
):

    files = recursive_files(directory)

    return {

        "files": sum(

            1

            for f in files

            if f.is_file()

        ),

        "directories": sum(

            1

            for f in files

            if f.is_dir()

        ),

        "total_size": directory_size(directory),

    }
    
    ###########################################################################
# Integrity
###########################################################################

from .hash_utils import hash_file


def checksum(
    path: str | Path,
):

    return hash_file(path)


def verify_checksum(
    path: str | Path,
    digest: str,
):

    return checksum(path) == digest.lower()

###########################################################################
# Cleanup
###########################################################################

def delete(
    path: str | Path,
):

    path = to_path(path)

    if path.exists():

        path.unlink()


def delete_empty_directories(
    directory: str | Path,
):

    directory = to_path(directory)

    for path in sorted(

        directory.rglob("*"),

        reverse=True,

    ):

        if path.is_dir():

            try:

                path.rmdir()

            except OSError:

                pass
            
    ###########################################################################
# Serialization
###########################################################################

def serialize_path(
    path: str | Path,
):

    path = to_path(path)

    return {

        "name": path.name,

        "suffix": path.suffix,

        "absolute": str(path.resolve()),

        "exists": path.exists(),

    }
    
    ###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    temp = temporary_directory()

    return {

        "working_directory": str(

            Path.cwd()

        ),

        "temporary_directory": temp.name,

        "json_supported": True,

        "csv_supported": True,

        "yaml_supported": yaml is not None,

    }
    
    ###########################################################################
# Performance
###########################################################################

import time


def measure_read(
    path: str | Path,
):

    start = time.perf_counter()

    read_bytes(path)

    elapsed = time.perf_counter() - start

    return elapsed


def measure_write(
    path: str | Path,
    data: bytes,
):

    start = time.perf_counter()

    write_bytes(

        data,

        path,

    )

    elapsed = time.perf_counter() - start

    return elapsed

    ###########################################################################
# Self Test
###########################################################################

def self_test():

    temp = temporary_file(

        ".txt"

    )

    temp.write(

        b"Threat Detection"

    )

    temp.close()

    passed = read_text(

        temp.name

    ) == "Threat Detection"

    delete(temp.name)

    return {

        "passed": passed,

        "json": True,

        "csv": True,

        "yaml": yaml is not None,

    }
    
    ###########################################################################
# Convenience
###########################################################################

def summary(
    path: str | Path,
):

    path = to_path(path)

    return {

        "metadata": metadata(path),

        "checksum": checksum(path)

        if path.exists()

        and path.is_file()

        else None,

    }
    
    
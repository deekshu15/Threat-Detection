"""
Enterprise Time Utilities

Features
--------
• ISO8601 Parsing
• Timestamp Validation
• UTC Conversion
• Epoch Conversion
• Timezone Support
• Duration Calculation
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from zoneinfo import ZoneInfo

from typing import Any


###########################################################################
# Current Time
###########################################################################

def now() -> datetime:

    return datetime.now(UTC)


def utc_now() -> datetime:

    return datetime.now(UTC)


###########################################################################
# Parsing
###########################################################################

def parse_iso(
    value: str,
) -> datetime:

    value = value.replace(
        "Z",
        "+00:00",
    )

    dt = datetime.fromisoformat(
        value
    )

    if dt.tzinfo is None:

        dt = dt.replace(
            tzinfo=UTC,
        )

    return dt


###########################################################################
# Validation
###########################################################################

def is_valid_iso(
    value: str,
) -> bool:

    try:

        parse_iso(value)

        return True

    except Exception:

        return False
    
    ###########################################################################
# Formatting
###########################################################################

def to_iso(
    value: datetime,
) -> str:

    return value.astimezone(
        UTC
    ).isoformat()


def to_date(
    value: datetime,
) -> str:

    return value.strftime(
        "%Y-%m-%d"
    )


def to_time(
    value: datetime,
) -> str:

    return value.strftime(
        "%H:%M:%S"
    )


def to_datetime(
    value: datetime,
) -> str:

    return value.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    
    ###########################################################################
# Epoch
###########################################################################

def to_epoch(
    value: datetime,
) -> int:

    return int(
        value.timestamp()
    )


def from_epoch(
    epoch: int | float,
) -> datetime:

    return datetime.fromtimestamp(
        epoch,
        UTC,
    )
    
    ###########################################################################
# Timezones
###########################################################################

def convert_timezone(
    value: datetime,
    timezone: str,
) -> datetime:

    return value.astimezone(
        ZoneInfo(timezone)
    )


def utc(
    value: datetime,
) -> datetime:

    return value.astimezone(
        UTC
    )


def timezone_name(
    value: datetime,
) -> str:

    if value.tzinfo:

        return str(value.tzinfo)

    return "Unknown"

###########################################################################
# Duration
###########################################################################

def duration(
    start: datetime,
    end: datetime,
) -> timedelta:

    return end - start


def duration_seconds(
    start: datetime,
    end: datetime,
) -> float:

    return (

        end - start

    ).total_seconds()


def duration_minutes(
    start: datetime,
    end: datetime,
) -> float:

    return duration_seconds(
        start,
        end,
    ) / 60


def duration_hours(
    start: datetime,
    end: datetime,
) -> float:

    return duration_seconds(
        start,
        end,
    ) / 3600
    
    ###########################################################################
# Relative Time
###########################################################################

def seconds_ago(
    seconds: int,
) -> datetime:

    return now() - timedelta(
        seconds=seconds,
    )


def minutes_ago(
    minutes: int,
) -> datetime:

    return now() - timedelta(
        minutes=minutes,
    )


def hours_ago(
    hours: int,
) -> datetime:

    return now() - timedelta(
        hours=hours,
    )


def days_ago(
    days: int,
) -> datetime:

    return now() - timedelta(
        days=days,
    )


def weeks_ago(
    weeks: int,
) -> datetime:

    return now() - timedelta(
        weeks=weeks,
    )


###########################################################################
# Start / End
###########################################################################

def start_of_day(
    value: datetime,
) -> datetime:

    return value.replace(

        hour=0,

        minute=0,

        second=0,

        microsecond=0,

    )


def end_of_day(
    value: datetime,
) -> datetime:

    return value.replace(

        hour=23,

        minute=59,

        second=59,

        microsecond=999999,

    )


def start_of_week(
    value: datetime,
) -> datetime:

    return start_of_day(

        value - timedelta(

            days=value.weekday(),

        )

    )


def end_of_week(
    value: datetime,
) -> datetime:

    return end_of_day(

        start_of_week(value)

        + timedelta(days=6)

    )


def start_of_month(
    value: datetime,
) -> datetime:

    return value.replace(

        day=1,

        hour=0,

        minute=0,

        second=0,

        microsecond=0,

    )


def start_of_year(
    value: datetime,
) -> datetime:

    return value.replace(

        month=1,

        day=1,

        hour=0,

        minute=0,

        second=0,

        microsecond=0,

    )
    
    ###########################################################################
# Time Windows
###########################################################################

def within_last(
    timestamp: datetime,
    delta: timedelta,
) -> bool:

    return timestamp >= now() - delta


def between(
    timestamp: datetime,
    start: datetime,
    end: datetime,
) -> bool:

    return start <= timestamp <= end


def overlaps(
    start1: datetime,
    end1: datetime,
    start2: datetime,
    end2: datetime,
) -> bool:

    return max(

        start1,

        start2,

    ) <= min(

        end1,

        end2,

    )
    
    ###########################################################################
# Comparison
###########################################################################

def older_than(
    timestamp: datetime,
    delta: timedelta,
) -> bool:

    return timestamp < now() - delta


def newer_than(
    timestamp: datetime,
    delta: timedelta,
) -> bool:

    return timestamp > now() - delta


def age(
    timestamp: datetime,
) -> timedelta:

    return now() - timestamp



###########################################################################
# Business Days
###########################################################################

def is_weekend(
    value: datetime,
) -> bool:

    return value.weekday() >= 5


def is_business_day(
    value: datetime,
) -> bool:

    return not is_weekend(
        value
    )


def next_business_day(
    value: datetime,
) -> datetime:

    current = value

    while True:

        current += timedelta(days=1)

        if is_business_day(current):

            return current
        
    ###########################################################################
# Rounding
###########################################################################

def floor_minute(
    value: datetime,
) -> datetime:

    return value.replace(

        second=0,

        microsecond=0,

    )


def floor_hour(
    value: datetime,
) -> datetime:

    return value.replace(

        minute=0,

        second=0,

        microsecond=0,

    )


def floor_day(
    value: datetime,
) -> datetime:

    return start_of_day(
        value
    )
    
    ###########################################################################
# Batch
###########################################################################

def parse_many(
    values: list[str],
):

    return [

        parse_iso(v)

        for v in values

    ]


def format_many(
    values: list[datetime],
):

    return [

        to_iso(v)

        for v in values

    ]
    
    ###########################################################################
# End of Month / Year
###########################################################################

import calendar
import time
from contextlib import contextmanager


def end_of_month(
    value: datetime,
) -> datetime:

    last_day = calendar.monthrange(
        value.year,
        value.month,
    )[1]

    return value.replace(

        day=last_day,

        hour=23,

        minute=59,

        second=59,

        microsecond=999999,

    )


def end_of_year(
    value: datetime,
) -> datetime:

    return value.replace(

        month=12,

        day=31,

        hour=23,

        minute=59,

        second=59,

        microsecond=999999,

    )
    
    ###########################################################################
# Human Readable
###########################################################################

def human_duration(
    delta: timedelta,
) -> str:

    seconds = int(delta.total_seconds())

    if seconds < 60:
        return f"{seconds} seconds"

    minutes = seconds // 60

    if minutes < 60:
        return f"{minutes} minutes"

    hours = minutes // 60

    if hours < 24:
        return f"{hours} hours"

    days = hours // 24

    if days < 30:
        return f"{days} days"

    months = days // 30

    if months < 12:
        return f"{months} months"

    years = months // 12

    return f"{years} years"


def time_since(
    timestamp: datetime,
) -> str:

    return human_duration(

        age(timestamp)

    )


def time_until(
    timestamp: datetime,
) -> str:

    return human_duration(

        timestamp - now()

    )
    
    ###########################################################################
# Stopwatch
###########################################################################

class Stopwatch:

    def __init__(self):

        self._start = None

        self._end = None

    def start(self):

        self._start = time.perf_counter()

        self._end = None

        return self

    def stop(self):

        self._end = time.perf_counter()

        return self

    @property
    def elapsed(self):

        if self._start is None:

            return 0.0

        end = self._end or time.perf_counter()

        return end - self._start

    def reset(self):

        self._start = None

        self._end = None
        
    ###########################################################################
# Timer Context
###########################################################################

@contextmanager
def timer():

    watch = Stopwatch().start()

    try:

        yield watch

    finally:

        watch.stop()
        
    ###########################################################################
# Retry
###########################################################################

def exponential_backoff(
    attempt: int,
    base: float = 1.0,
    factor: float = 2.0,
    maximum: float = 60.0,
) -> float:

    delay = base * (factor ** attempt)

    return min(delay, maximum)


def linear_backoff(
    attempt: int,
    interval: float = 1.0,
) -> float:

    return interval * attempt

###########################################################################
# Serialization
###########################################################################

def datetime_to_dict(
    value: datetime,
):

    return {

        "iso": to_iso(value),

        "epoch": to_epoch(value),

        "date": to_date(value),

        "time": to_time(value),

        "timezone": timezone_name(value),

    }
    
    ###########################################################################
# Summary
###########################################################################

def summary():

    current = now()

    return {

        "utc": to_iso(current),

        "epoch": to_epoch(current),

        "date": to_date(current),

        "time": to_time(current),

        "weekday": current.strftime("%A"),

        "month": current.strftime("%B"),

        "year": current.year,

    }
    
    ###########################################################################
# Performance
###########################################################################

def measure(function, *args, **kwargs):

    watch = Stopwatch().start()

    result = function(*args, **kwargs)

    watch.stop()

    return {

        "result": result,

        "elapsed": watch.elapsed,

    }


def benchmark(function, iterations=100, *args, **kwargs):

    watch = Stopwatch().start()

    for _ in range(iterations):

        function(*args, **kwargs)

    watch.stop()

    return watch.elapsed


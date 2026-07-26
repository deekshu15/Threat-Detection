"""
Temporal Feature Engineering

Generates temporal features from event timestamps.

Responsibilities
----------------
- Hour
- Minute
- Second
- Day
- Weekday
- Month
- Quarter
- Weekend
- Business Hours
- Night Activity
- Cyclic Time Encoding

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import math
from dataclasses import asdict, asdict, dataclass
from datetime import datetime
from typing import Dict

from .constants import (
    BUSINESS_END,
    BUSINESS_START,
)
# ---------------------------------------------------------
# Temporal Features
# ---------------------------------------------------------

@dataclass(slots=True)
class TemporalFeatures:

    hour: int

    minute: int

    second: int

    day: int

    weekday: int

    month: int

    quarter: int

    week_of_year: int

    day_of_year: int

    is_weekend: int

    is_business_hours: int

    is_night: int

    hour_sin: float

    hour_cos: float

    weekday_sin: float

    weekday_cos: float

    month_sin: float

    month_cos: float
    # ---------------------------------------------------------
# Generator
# ---------------------------------------------------------

class TemporalFeatureGenerator:

    """
    Generates temporal ML features.
    """

    def generate(
        self,
        timestamp: datetime,
    ) -> TemporalFeatures:

        hour = timestamp.hour

        minute = timestamp.minute

        second = timestamp.second

        day = timestamp.day

        weekday = timestamp.weekday()

        month = timestamp.month

        quarter = ((month - 1) // 3) + 1

        week_of_year = timestamp.isocalendar().week

        day_of_year = timestamp.timetuple().tm_yday

        is_weekend = 1 if weekday >= 5 else 0

        is_business = int(

            BUSINESS_START <= hour < BUSINESS_END

        )

        is_night = int(

            hour >= 22 or hour < 6

        )
                # -------------------------------------------------
        # Cyclic Encoding
        # -------------------------------------------------

        hour_sin = math.sin(

            2 * math.pi * hour / 24

        )

        hour_cos = math.cos(

            2 * math.pi * hour / 24

        )

        weekday_sin = math.sin(

            2 * math.pi * weekday / 7

        )

        weekday_cos = math.cos(

            2 * math.pi * weekday / 7

        )

        month_sin = math.sin(

            2 * math.pi * month / 12

        )

        month_cos = math.cos(

            2 * math.pi * month / 12

        )

        return TemporalFeatures(

            hour=hour,

            minute=minute,

            second=second,

            day=day,

            weekday=weekday,

            month=month,

            quarter=quarter,

            week_of_year=week_of_year,

            day_of_year=day_of_year,

            is_weekend=is_weekend,

            is_business_hours=is_business,

            is_night=is_night,

            hour_sin=round(hour_sin, 6),

            hour_cos=round(hour_cos, 6),

            weekday_sin=round(weekday_sin, 6),

            weekday_cos=round(weekday_cos, 6),

            month_sin=round(month_sin, 6),

            month_cos=round(month_cos, 6),

        )

    # -------------------------------------------------
    # Dictionary Output
    # -------------------------------------------------

    def generate_dict(
        self,
        timestamp: datetime,
    ) -> Dict:

        return asdict(
            self.generate(timestamp)
        )
        # -------------------------------------------------
    # Batch Processing
    # -------------------------------------------------

    def generate_batch(
        self,
        timestamps,
    ):

        return [

            self.generate_dict(ts)

            for ts in timestamps

        ]


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_generator = TemporalFeatureGenerator()


def generate_temporal_features(
    timestamp: datetime,
) -> Dict:

    return _generator.generate_dict(

        timestamp

    )


def generate_batch_temporal_features(
    timestamps,
):

    return _generator.generate_batch(

        timestamps

    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    now = datetime.now()

    features = generate_temporal_features(

        now

    )

    from pprint import pprint

    pprint(features)
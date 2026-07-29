"""
Enterprise Metrics Utilities

Features
--------
• Counters
• Gauges
• Histograms
• Timers
• Thread Safety
• Metric Registry
• Statistical Aggregation
• Service Performance Monitoring
"""

from __future__ import annotations

import math
import time

from collections import defaultdict
from dataclasses import dataclass, field
from threading import RLock
from typing import Any
###########################################################################
# Base Metric
###########################################################################

@dataclass
class Metric:

    name: str

    description: str = ""

    labels: dict[str, str] = field(
        default_factory=dict
    )

    created_at: float = field(
        default_factory=time.time
    )

    def metadata(
        self,
    ) -> dict[str, Any]:

        return {

            "name": self.name,

            "description": self.description,

            "labels": dict(self.labels),

            "created_at": self.created_at,

        }
    ###########################################################################
# Counter
###########################################################################

class Counter(Metric):

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: dict[str, str] | None = None,
    ):

        super().__init__(
            name=name,
            description=description,
            labels=labels or {},
        )

        self._value = 0.0

        self._lock = RLock()

    def increment(
        self,
        amount: float = 1.0,
    ) -> float:

        if amount < 0:

            raise ValueError(
                "Counter increment cannot be negative."
            )

        with self._lock:

            self._value += amount

            return self._value

    def get(
        self,
    ) -> float:

        with self._lock:

            return self._value

    def reset(
        self,
    ) -> None:

        with self._lock:

            self._value = 0.0

    @property
    def value(
        self,
    ) -> float:

        return self.get()
    
    ###########################################################################
# Gauge
###########################################################################

class Gauge(Metric):

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: dict[str, str] | None = None,
    ):

        super().__init__(
            name=name,
            description=description,
            labels=labels or {},
        )

        self._value = 0.0

        self._lock = RLock()

    def set(
        self,
        value: float,
    ) -> float:

        with self._lock:

            self._value = float(value)

            return self._value

    def increment(
        self,
        amount: float = 1.0,
    ) -> float:

        with self._lock:

            self._value += amount

            return self._value

    def decrement(
        self,
        amount: float = 1.0,
    ) -> float:

        with self._lock:

            self._value -= amount

            return self._value

    def get(
        self,
    ) -> float:

        with self._lock:

            return self._value

    def reset(
        self,
    ) -> None:

        self.set(0.0)

    @property
    def value(
        self,
    ) -> float:

        return self.get()
    
    ###########################################################################
# Histogram
###########################################################################

class Histogram(Metric):

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: dict[str, str] | None = None,
        max_samples: int = 10_000,
    ):

        super().__init__(
            name=name,
            description=description,
            labels=labels or {},
        )

        if max_samples <= 0:

            raise ValueError(
                "max_samples must be greater than zero."
            )

        self.max_samples = max_samples

        self._values: list[float] = []

        self._count = 0

        self._sum = 0.0

        self._min: float | None = None

        self._max: float | None = None

        self._lock = RLock()

    def observe(
        self,
        value: float,
    ) -> None:

        value = float(value)

        if not math.isfinite(value):

            raise ValueError(
                "Histogram values must be finite."
            )

        with self._lock:

            self._count += 1

            self._sum += value

            if self._min is None or value < self._min:

                self._min = value

            if self._max is None or value > self._max:

                self._max = value

            self._values.append(value)

            if len(self._values) > self.max_samples:

                del self._values[
                    : len(self._values) - self.max_samples
                ]
            
                
    def count(
        self,
    ) -> int:

        with self._lock:

            return self._count

    def total(
        self,
    ) -> float:

        with self._lock:

            return self._sum

    def average(
        self,
    ) -> float:

        with self._lock:

            if self._count == 0:

                return 0.0

            return self._sum / self._count

    def minimum(
        self,
    ) -> float | None:

        with self._lock:

            return self._min

    def maximum(
        self,
    ) -> float | None:

        with self._lock:

            return self._max
    
        def percentile(
        self,
        percentile: float,
        ) -> float:

            if not 0 <= percentile <= 100:

                raise ValueError(
                    "Percentile must be between 0 and 100."
               )

        with self._lock:

            if not self._values:

                return 0.0

            values = sorted(
                self._values
            )

        if len(values) == 1:

            return values[0]

        position = (
            percentile / 100
        ) * (
            len(values) - 1
        )

        lower = math.floor(position)

        upper = math.ceil(position)

        if lower == upper:

            return values[lower]

        fraction = position - lower

        return (
            values[lower]
            +
            (
                values[upper]
                - values[lower]
            )
            * fraction
        )

    def p50(
        self,
    ) -> float:

        return self.percentile(50)

    def p95(
        self,
    ) -> float:

        return self.percentile(95)

    def p99(
        self,
    ) -> float:

        return self.percentile(99)
    
        def snapshot(
        self,
        ) -> dict[str, Any]:

          return {
 
            "count": self.count(),

            "sum": self.total(),

            "average": self.average(),

            "minimum": self.minimum(),

            "maximum": self.maximum(),

            "p50": self.p50(),

            "p95": self.p95(),

            "p99": self.p99(),

        }

    def reset(
        self,
    ) -> None:

        with self._lock:

            self._values.clear()

            self._count = 0

            self._sum = 0.0

            self._min = None

            self._max = None
            
            
    ###########################################################################
# Timer
###########################################################################

class Timer:

    def __init__(
        self,
        histogram: Histogram | None = None,
    ):

        self.histogram = histogram

        self.started_at: float | None = None

        self.ended_at: float | None = None

    def start(
        self,
    ) -> "Timer":

        self.started_at = time.perf_counter()

        self.ended_at = None

        return self

    def stop(
        self,
    ) -> float:

        if self.started_at is None:

            raise RuntimeError(
                "Timer has not been started."
            )

        self.ended_at = time.perf_counter()

        elapsed = (
            self.ended_at
            - self.started_at
        )

        if self.histogram is not None:

            self.histogram.observe(
                elapsed
            )

        return elapsed

    @property
    def elapsed(
        self,
    ) -> float:

        if self.started_at is None:

            return 0.0

        end = (
            self.ended_at
            if self.ended_at is not None
            else time.perf_counter()
        )

        return end - self.started_at

    def __enter__(
        self,
    ) -> "Timer":

        return self.start()

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> bool:

        self.stop()

        return False
    
    ###########################################################################
# Metric Registry
###########################################################################

class MetricRegistry:

    def __init__(
        self,
    ):

        self._metrics: dict[
            str,
            Metric,
        ] = {}

        self._lock = RLock()

    def register(
        self,
        metric: Metric,
    ) -> Metric:

        with self._lock:

            existing = self._metrics.get(
                metric.name
            )

            if existing is not None:

                if type(existing) is not type(metric):

                    raise TypeError(
                        f"Metric '{metric.name}' is already registered "
                        f"as {type(existing).__name__}."
                    )

                return existing

            self._metrics[
                metric.name
            ] = metric

            return metric

    def get(
        self,
        name: str,
    ) -> Metric | None:

        with self._lock:

            return self._metrics.get(
                name
            )

    def remove(
        self,
        name: str,
    ) -> bool:

        with self._lock:

            return (
                self._metrics.pop(
                    name,
                    None,
                )
                is not None
            )

    def names(
        self,
    ) -> list[str]:

        with self._lock:

            return sorted(
                self._metrics.keys()
            )
            
            
        def counter(
        self,
        name: str,
        description: str = "",
        ) -> Counter:

          metric = self.register(

            Counter(
                name=name,
                description=description,
            )

        )

        return metric

    def gauge(
        self,
        name: str,
        description: str = "",
    ) -> Gauge:

        metric = self.register(

            Gauge(
                name=name,
                description=description,
            )

        )

        return metric

    def histogram(
        self,
        name: str,
        description: str = "",
    ) -> Histogram:

        metric = self.register(

            Histogram(
                name=name,
                description=description,
            )

        )

        return metric
    
    ###########################################################################
# Error Rate
###########################################################################

@dataclass
class ErrorRate:

    total: int = 0
    errors: int = 0

    _lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
    )

    def record_success(self) -> None:

        with self._lock:
            self.total += 1

    def record_error(self) -> None:

        with self._lock:
            self.total += 1
            self.errors += 1

    def rate(self) -> float:

        with self._lock:

            if self.total == 0:
                return 0.0

            return self.errors / self.total

    def percentage(self) -> float:

        return self.rate() * 100.0

    def reset(self) -> None:

        with self._lock:
            self.total = 0
            self.errors = 0

    def snapshot(self) -> dict[str, Any]:

        with self._lock:

            rate = (
                self.errors / self.total
                if self.total
                else 0.0
            )

            return {
                "total": self.total,
                "errors": self.errors,
                "successful": self.total - self.errors,
                "error_rate": rate,
                "error_percentage": rate * 100.0,
            }
            
    ###########################################################################
# Throughput
###########################################################################

class Throughput:

    def __init__(self):

        self._count = 0

        self._started_at = time.perf_counter()

        self._lock = RLock()

    def record(
        self,
        amount: int = 1,
    ) -> None:

        if amount < 0:

            raise ValueError(
                "Throughput amount cannot be negative."
            )

        with self._lock:

            self._count += amount

    def elapsed(self) -> float:

        with self._lock:

            return (
                time.perf_counter()
                - self._started_at
            )

    def per_second(self) -> float:

        with self._lock:

            elapsed = (
                time.perf_counter()
                - self._started_at
            )

            if elapsed <= 0:
                return 0.0

            return self._count / elapsed

    def per_minute(self) -> float:

        return self.per_second() * 60.0

    def snapshot(self) -> dict[str, Any]:

        with self._lock:

            elapsed = (
                time.perf_counter()
                - self._started_at
            )

            rate = (
                self._count / elapsed
                if elapsed > 0
                else 0.0
            )

            return {
                "count": self._count,
                "elapsed_seconds": elapsed,
                "per_second": rate,
                "per_minute": rate * 60.0,
            }

    def reset(self) -> None:

        with self._lock:

            self._count = 0
            self._started_at = time.perf_counter()
            
    ###########################################################################
# Metric Serialization
###########################################################################

def metric_snapshot(
    metric: Metric,
) -> dict[str, Any]:

    base = metric.metadata()

    if isinstance(metric, Counter):

        base.update({
            "type": "counter",
            "value": metric.get(),
        })

        return base

    if isinstance(metric, Gauge):

        base.update({
            "type": "gauge",
            "value": metric.get(),
        })

        return base

    if isinstance(metric, Histogram):

        base.update({
            "type": "histogram",
            **metric.snapshot(),
        })

        return base

    base["type"] = type(metric).__name__

    return base

    def snapshot(
        self,
    ) -> dict[str, Any]:

        with self._lock:

            metrics = list(
                self._metrics.values()
            )

        return {
            metric.name: metric_snapshot(metric)
            for metric in metrics
        }

    def reset_all(
        self,
    ) -> None:

        with self._lock:

            metrics = list(
                self._metrics.values()
            )

        for metric in metrics:

            reset = getattr(
                metric,
                "reset",
                None,
            )

            if callable(reset):
                reset()

    def clear(
        self,
    ) -> None:

        with self._lock:
            self._metrics.clear()

    def count(
        self,
    ) -> int:

        with self._lock:
            return len(self._metrics)
        
    
    ###########################################################################
# Service Metrics
###########################################################################

class ServiceMetrics:

    def __init__(
        self,
        service_name: str,
        registry: MetricRegistry | None = None,
    ):

        self.service_name = service_name

        self.registry = registry or METRICS

        prefix = service_name.lower().replace(
            " ",
            "_",
        )

        self.requests = self.registry.counter(
            f"{prefix}_requests_total",
            f"Total requests processed by {service_name}.",
        )

        self.errors = self.registry.counter(
            f"{prefix}_errors_total",
            f"Total errors generated by {service_name}.",
        )

        self.active = self.registry.gauge(
            f"{prefix}_active",
            f"Current active operations in {service_name}.",
        )

        self.latency = self.registry.histogram(
            f"{prefix}_latency_seconds",
            f"Execution latency for {service_name}.",
        )

    def record_success(
        self,
        elapsed: float | None = None,
    ) -> None:

        self.requests.increment()

        if elapsed is not None:
            self.latency.observe(elapsed)

    def record_failure(
        self,
        elapsed: float | None = None,
    ) -> None:

        self.requests.increment()
        self.errors.increment()

        if elapsed is not None:
            self.latency.observe(elapsed)

    def error_rate(self) -> float:

        total = self.requests.get()

        if total == 0:
            return 0.0

        return (
            self.errors.get()
            / total
        )

    def snapshot(self) -> dict[str, Any]:

        return {
            "service": self.service_name,
            "requests": self.requests.get(),
            "errors": self.errors.get(),
            "error_rate": self.error_rate(),
            "active": self.active.get(),
            "latency": self.latency.snapshot(),
        }
        
    ###########################################################################
# Service Operation Context
###########################################################################

class ServiceOperation:

    def __init__(
        self,
        metrics: ServiceMetrics,
    ):

        self.metrics = metrics

        self.started_at: float | None = None

    def __enter__(
        self,
    ) -> "ServiceOperation":

        self.metrics.active.increment()

        self.started_at = time.perf_counter()

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> bool:

        elapsed = (
            time.perf_counter()
            - self.started_at
        )

        self.metrics.active.decrement()

        if exc_type is None:

            self.metrics.record_success(
                elapsed
            )

        else:

            self.metrics.record_failure(
                elapsed
            )

        return False
    
    
    ###########################################################################
# Prometheus Export
###########################################################################

def _prometheus_name(
    name: str,
) -> str:

    result = []

    for character in name:

        if (
            character.isalnum()
            or character in "_:"
        ):
            result.append(character)

        else:
            result.append("_")

    return "".join(result)


def _prometheus_labels(
    labels: dict[str, str],
) -> str:

    if not labels:
        return ""

    parts = []

    for key, value in sorted(
        labels.items()
    ):

        escaped = (
            str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )

        parts.append(
            f'{key}="{escaped}"'
        )

    return "{" + ",".join(parts) + "}"

def prometheus_export(
    registry: MetricRegistry = METRICS,
) -> str:

    lines: list[str] = []

    with registry._lock:

        metrics = list(
            registry._metrics.values()
        )

    for metric in metrics:

        name = _prometheus_name(
            metric.name
        )

        labels = _prometheus_labels(
            metric.labels
        )

        if metric.description:

            lines.append(
                f"# HELP {name} {metric.description}"
            )

        if isinstance(metric, Counter):

            lines.append(
                f"# TYPE {name} counter"
            )

            lines.append(
                f"{name}{labels} {metric.get()}"
            )

        elif isinstance(metric, Gauge):

            lines.append(
                f"# TYPE {name} gauge"
            )

            lines.append(
                f"{name}{labels} {metric.get()}"
            )

        elif isinstance(metric, Histogram):

            snapshot = metric.snapshot()

            lines.append(
                f"# TYPE {name} summary"
            )

            for quantile, key in (
                ("0.5", "p50"),
                ("0.95", "p95"),
                ("0.99", "p99"),
            ):

                quantile_labels = dict(
                    metric.labels
                )

                quantile_labels[
                    "quantile"
                ] = quantile

                lines.append(
                    f"{name}"
                    f"{_prometheus_labels(quantile_labels)} "
                    f"{snapshot[key]}"
                )

            lines.append(
                f"{name}_sum{labels} "
                f"{snapshot['sum']}"
            )

            lines.append(
                f"{name}_count{labels} "
                f"{snapshot['count']}"
            )

    return "\n".join(lines) + "\n"

###########################################################################
# CloudWatch Formatting
###########################################################################

def cloudwatch_metric_data(
    registry: MetricRegistry = METRICS,
    namespace: str = "ThreatEnrichment",
) -> dict[str, Any]:

    metric_data = []

    with registry._lock:

        metrics = list(
            registry._metrics.values()
        )

    for metric in metrics:

        dimensions = [

            {
                "Name": str(key),
                "Value": str(value),
            }

            for key, value
            in metric.labels.items()

        ]

        if isinstance(metric, Counter):

            metric_data.append({
                "MetricName": metric.name,
                "Dimensions": dimensions,
                "Value": metric.get(),
                "Unit": "Count",
            })

        elif isinstance(metric, Gauge):

            metric_data.append({
                "MetricName": metric.name,
                "Dimensions": dimensions,
                "Value": metric.get(),
                "Unit": "None",
            })

        elif isinstance(metric, Histogram):

            snapshot = metric.snapshot()

            if snapshot["count"] == 0:
                continue

            metric_data.append({
                "MetricName": metric.name,
                "Dimensions": dimensions,
                "StatisticValues": {
                    "SampleCount": float(
                        snapshot["count"]
                    ),
                    "Sum": snapshot["sum"],
                    "Minimum": snapshot["minimum"],
                    "Maximum": snapshot["maximum"],
                },
                "Unit": "Seconds",
            })

    return {
        "Namespace": namespace,
        "MetricData": metric_data,
    }
    
    ###########################################################################
# Application Metrics
###########################################################################

APPLICATION_ERRORS = ErrorRate()

APPLICATION_THROUGHPUT = Throughput()


IOC_SERVICE_METRICS = ServiceMetrics(
    "ioc_service"
)

CVE_SERVICE_METRICS = ServiceMetrics(
    "cve_service"
)

MITRE_SERVICE_METRICS = ServiceMetrics(
    "mitre_service"
)

ASSET_SERVICE_METRICS = ServiceMetrics(
    "asset_service"
)

BEHAVIOR_SERVICE_METRICS = ServiceMetrics(
    "behavior_service"
)

THREAT_SCORE_METRICS = ServiceMetrics(
    "threat_score_service"
)

ENRICHMENT_PIPELINE_METRICS = ServiceMetrics(
    "enrichment_pipeline"
)

###########################################################################
# Application Snapshot
###########################################################################

def application_snapshot() -> dict[str, Any]:

    return {
        "registry": METRICS.snapshot(),

        "error_rate":
            APPLICATION_ERRORS.snapshot(),

        "throughput":
            APPLICATION_THROUGHPUT.snapshot(),

        "services": {
            "ioc":
                IOC_SERVICE_METRICS.snapshot(),

            "cve":
                CVE_SERVICE_METRICS.snapshot(),

            "mitre":
                MITRE_SERVICE_METRICS.snapshot(),

            "asset":
                ASSET_SERVICE_METRICS.snapshot(),

            "behavior":
                BEHAVIOR_SERVICE_METRICS.snapshot(),

            "threat_score":
                THREAT_SCORE_METRICS.snapshot(),

            "pipeline":
                ENRICHMENT_PIPELINE_METRICS.snapshot(),
        },
    }
    
    ###########################################################################
# Rolling Window
###########################################################################

from collections import deque
from functools import wraps
import asyncio


class RollingWindow:

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_samples: int = 10_000,
    ):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        if max_samples <= 0:
            raise ValueError(
                "max_samples must be greater than zero."
            )

        self.window_seconds = window_seconds
        self.max_samples = max_samples

        self._samples = deque(
            maxlen=max_samples
        )

        self._lock = RLock()

    def _cleanup(
        self,
        current_time: float,
    ) -> None:

        cutoff = (
            current_time
            - self.window_seconds
        )

        while (
            self._samples
            and self._samples[0][0] < cutoff
        ):
            self._samples.popleft()

    def observe(
        self,
        value: float,
    ) -> None:

        value = float(value)

        if not math.isfinite(value):
            raise ValueError(
                "Metric value must be finite."
            )

        current_time = time.monotonic()

        with self._lock:

            self._cleanup(
                current_time
            )

            self._samples.append(
                (
                    current_time,
                    value,
                )
            )

    def values(
        self,
    ) -> list[float]:

        current_time = time.monotonic()

        with self._lock:

            self._cleanup(
                current_time
            )

            return [
                value
                for _, value
                in self._samples
            ]

    def count(
        self,
    ) -> int:

        return len(
            self.values()
        )

    def average(
        self,
    ) -> float:

        values = self.values()

        if not values:
            return 0.0

        return (
            sum(values)
            / len(values)
        )

    def minimum(
        self,
    ) -> float | None:

        values = self.values()

        return (
            min(values)
            if values
            else None
        )

    def maximum(
        self,
    ) -> float | None:

        values = self.values()

        return (
            max(values)
            if values
            else None
        )

    def percentile(
        self,
        percentile: float,
    ) -> float:

        if not 0 <= percentile <= 100:

            raise ValueError(
                "Percentile must be between 0 and 100."
            )

        values = sorted(
            self.values()
        )

        if not values:
            return 0.0

        if len(values) == 1:
            return values[0]

        position = (
            percentile / 100.0
        ) * (
            len(values) - 1
        )

        lower = math.floor(
            position
        )

        upper = math.ceil(
            position
        )

        if lower == upper:
            return values[lower]

        fraction = (
            position - lower
        )

        return (
            values[lower]
            +
            (
                values[upper]
                - values[lower]
            )
            * fraction
        )

    def reset(
        self,
    ) -> None:

        with self._lock:
            self._samples.clear()

    def snapshot(
        self,
    ) -> dict[str, Any]:

        values = self.values()

        if not values:

            return {
                "window_seconds":
                    self.window_seconds,

                "count": 0,

                "average": 0.0,

                "minimum": None,

                "maximum": None,

                "p50": 0.0,

                "p95": 0.0,

                "p99": 0.0,
            }

        return {
            "window_seconds":
                self.window_seconds,

            "count":
                len(values),

            "average":
                sum(values) / len(values),

            "minimum":
                min(values),

            "maximum":
                max(values),

            "p50":
                self.percentile(50),

            "p95":
                self.percentile(95),

            "p99":
                self.percentile(99),
        }
        
    ###########################################################################
# Rolling Throughput
###########################################################################

class RollingThroughput:

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_events: int = 100_000,
    ):

        self.window_seconds = window_seconds

        self._events = deque(
            maxlen=max_events
        )

        self._lock = RLock()

    def _cleanup(
        self,
        current_time: float,
    ) -> None:

        cutoff = (
            current_time
            - self.window_seconds
        )

        while (
            self._events
            and self._events[0] < cutoff
        ):
            self._events.popleft()

    def record(
        self,
        amount: int = 1,
    ) -> None:

        if amount < 0:

            raise ValueError(
                "Amount cannot be negative."
            )

        current_time = time.monotonic()

        with self._lock:

            self._cleanup(
                current_time
            )

            for _ in range(amount):

                self._events.append(
                    current_time
                )

    def per_second(
        self,
    ) -> float:

        current_time = time.monotonic()

        with self._lock:

            self._cleanup(
                current_time
            )

            return (
                len(self._events)
                / self.window_seconds
            )

    def per_minute(
        self,
    ) -> float:

        return (
            self.per_second()
            * 60.0
        )

    def reset(
        self,
    ) -> None:

        with self._lock:
            self._events.clear()

    def snapshot(
        self,
    ) -> dict[str, Any]:

        current_time = time.monotonic()

        with self._lock:

            self._cleanup(
                current_time
            )

            count = len(
                self._events
            )

        rate = (
            count
            / self.window_seconds
        )

        return {
            "window_seconds":
                self.window_seconds,

            "events":
                count,

            "per_second":
                rate,

            "per_minute":
                rate * 60.0,
        }
        
        
    ###########################################################################
# Health
###########################################################################

@dataclass(slots=True)
class HealthThresholds:

    warning_error_rate: float = 0.05

    critical_error_rate: float = 0.20

    warning_p95_latency: float = 2.0

    critical_p95_latency: float = 5.0


DEFAULT_HEALTH_THRESHOLDS = (
    HealthThresholds()
)

def service_health(
    metrics: ServiceMetrics,
    thresholds: HealthThresholds | None = None,
) -> dict[str, Any]:

    thresholds = (
        thresholds
        or DEFAULT_HEALTH_THRESHOLDS
    )

    error_rate = (
        metrics.error_rate()
    )

    p95 = (
        metrics.latency.p95()
    )

    status = "HEALTHY"

    reasons: list[str] = []

    if (
        error_rate
        >= thresholds.critical_error_rate
    ):

        status = "CRITICAL"

        reasons.append(
            "Critical error rate."
        )

    elif (
        error_rate
        >= thresholds.warning_error_rate
    ):

        status = "DEGRADED"

        reasons.append(
            "Elevated error rate."
        )

    if (
        p95
        >= thresholds.critical_p95_latency
    ):

        status = "CRITICAL"

        reasons.append(
            "Critical P95 latency."
        )

    elif (
        p95
        >= thresholds.warning_p95_latency
        and status != "CRITICAL"
    ):

        status = "DEGRADED"

        reasons.append(
            "Elevated P95 latency."
        )

    return {
        "service":
            metrics.service_name,

        "status":
            status,

        "error_rate":
            error_rate,

        "p95_latency_seconds":
            p95,

        "reasons":
            reasons,
    }
    
    ###########################################################################
# Application Health
###########################################################################

def application_health() -> dict[str, Any]:

    services = {

        "ioc":
            IOC_SERVICE_METRICS,

        "cve":
            CVE_SERVICE_METRICS,

        "mitre":
            MITRE_SERVICE_METRICS,

        "asset":
            ASSET_SERVICE_METRICS,

        "behavior":
            BEHAVIOR_SERVICE_METRICS,

        "threat_score":
            THREAT_SCORE_METRICS,

        "pipeline":
            ENRICHMENT_PIPELINE_METRICS,
    }

    health = {

        name:
            service_health(metrics)

        for name, metrics
        in services.items()
    }

    statuses = {

        item["status"]

        for item
        in health.values()

    }

    if "CRITICAL" in statuses:

        overall = "CRITICAL"

    elif "DEGRADED" in statuses:

        overall = "DEGRADED"

    else:

        overall = "HEALTHY"

    return {
        "status":
            overall,

        "services":
            health,
    }
    
    ###########################################################################
# Metric Decorators
###########################################################################

def timed(
    histogram: Histogram,
):

    def decorator(
        function,
    ):

        @wraps(function)
        def wrapper(
            *args,
            **kwargs,
        ):

            start = (
                time.perf_counter()
            )

            try:

                return function(
                    *args,
                    **kwargs,
                )

            finally:

                histogram.observe(
                    time.perf_counter()
                    - start
                )

        return wrapper

    return decorator

    def counted(
        counter: Counter,
    ):

        def decorator(
            function,
        ):

            @wraps(function)
            def wrapper(
                *args,
                **kwargs,
            ):

                result = function(
                    *args,
                    **kwargs,
                )

                counter.increment()

                return result

            return wrapper

        return decorator
    
    def count_failures(
        counter: Counter,
    ):

        def decorator(
            function,
        ):

            @wraps(function)
            def wrapper(
                *args,
                **kwargs,
            ):

                try:

                    return function(
                        *args,
                        **kwargs,
                    )

                except Exception:

                    counter.increment()

                    raise

            return wrapper

        return decorator
    
    def instrument(
        metrics: ServiceMetrics,
    ):

        def decorator(
            function,
        ):

            @wraps(function)
            def wrapper(
                *args,
                **kwargs,
            ):

                with ServiceOperation(
                    metrics
                ):

                    return function(
                       *args,
                       **kwargs,
                    )

            return wrapper

        return decorator
    
    ###########################################################################
# Async Instrumentation
###########################################################################

def async_instrument(
    metrics: ServiceMetrics,
):

    def decorator(
        function,
    ):

        @wraps(function)
        async def wrapper(
            *args,
            **kwargs,
        ):

            metrics.active.increment()

            start = (
                time.perf_counter()
            )

            try:

                result = await function(
                    *args,
                    **kwargs,
                )

                elapsed = (
                    time.perf_counter()
                    - start
                )

                metrics.record_success(
                    elapsed
                )

                return result

            except asyncio.CancelledError:

                raise

            except Exception:

                elapsed = (
                    time.perf_counter()
                    - start
                )

                metrics.record_failure(
                    elapsed
                )

                raise

            finally:

                metrics.active.decrement()

        return wrapper

    return decorator


    ###########################################################################
# Reset
###########################################################################

def reset_application_metrics() -> None:

    METRICS.reset_all()

    APPLICATION_ERRORS.reset()

    APPLICATION_THROUGHPUT.reset()
    
    ###########################################################################
# Diagnostics
###########################################################################

def diagnostics() -> dict[str, Any]:

    snapshot = (
        METRICS.snapshot()
    )

    return {
        "module":
            "metrics",

        "version":
            "1.0.0",

        "registered_metrics":
            METRICS.count(),

        "metric_names":
            METRICS.names(),

        "supports_counter":
            True,

        "supports_gauge":
            True,

        "supports_histogram":
            True,

        "supports_percentiles":
            True,

        "supports_rolling_window":
            True,

        "supports_async":
            True,

        "supports_prometheus":
            True,

        "supports_cloudwatch":
            True,

        "snapshot":
            snapshot,
    }
    
    ###########################################################################
# Summary
###########################################################################

def summary() -> dict[str, Any]:

    return {
        "health":
            application_health(),

        "errors":
            APPLICATION_ERRORS.snapshot(),

        "throughput":
            APPLICATION_THROUGHPUT.snapshot(),

        "metrics":
            METRICS.snapshot(),
    }
    
    ###########################################################################
# Self Test
###########################################################################

def self_test() -> dict[str, Any]:

    registry = (
        MetricRegistry()
    )

    counter = registry.counter(
        "test_counter"
    )

    gauge = registry.gauge(
        "test_gauge"
    )

    histogram = registry.histogram(
        "test_latency"
    )

    counter.increment()
    counter.increment(2)

    gauge.set(5)
    gauge.decrement(2)

    histogram.observe(0.10)
    histogram.observe(0.20)
    histogram.observe(0.30)
    histogram.observe(0.40)
    histogram.observe(0.50)

    passed = all([
        counter.get() == 3,
        gauge.get() == 3,
        histogram.count() == 5,
        histogram.minimum() == 0.10,
        histogram.maximum() == 0.50,
        registry.count() == 3,
    ])

    return {
        "passed":
            passed,

        "counter":
            counter.get(),

        "gauge":
            gauge.get(),

        "histogram":
            histogram.snapshot(),

        "registered":
            registry.count(),
    }
    
    
    
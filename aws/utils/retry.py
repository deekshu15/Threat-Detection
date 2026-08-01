"""
Enterprise Retry Utilities

Features
--------
• Retry Decorator
• Exponential Backoff
• Linear Backoff
• Fixed Delay
• Exception Filtering
• Sync Retry
"""

from __future__ import annotations

import random
import time

from functools import wraps
from typing import Callable
from typing import Iterable
from typing import Type
import asyncio

from dataclasses import dataclass, field

from typing import Awaitable
from typing import Optional
###########################################################################
# Retry Configuration
###########################################################################

class RetryConfig:

    def __init__(

        self,

        attempts: int = 3,

        delay: float = 1.0,

        backoff: float = 2.0,

        maximum_delay: float = 60.0,

        jitter: bool = True,

    ):

        self.attempts = attempts

        self.delay = delay

        self.backoff = backoff

        self.maximum_delay = maximum_delay

        self.jitter = jitter
        
    ###########################################################################
# Delay Strategies
###########################################################################

def fixed_delay(

    attempt: int,

    config: RetryConfig,

):

    return config.delay


def linear_delay(

    attempt: int,

    config: RetryConfig,

):

    return config.delay * attempt


def exponential_delay(

    attempt: int,

    config: RetryConfig,

):

    delay = (

        config.delay

        * (config.backoff ** (attempt - 1))

    )

    return min(

        delay,

        config.maximum_delay,

    )
    
    ###########################################################################
# Jitter
###########################################################################

def add_jitter(

    delay: float,

) -> float:

    return random.uniform(

        delay * 0.5,

        delay * 1.5,

    )
    
    ###########################################################################
# Retry
###########################################################################

def retry(

    exceptions: Type[Exception] | tuple[Type[Exception], ...] = Exception,

    config: RetryConfig | None = None,

    strategy: Callable = exponential_delay,

):

    if config is None:

        config = RetryConfig()

    def decorator(function):

        @wraps(function)

        def wrapper(*args, **kwargs):

            last_exception = None

            for attempt in range(

                1,

                config.attempts + 1,

            ):

                try:

                    return function(

                        *args,

                        **kwargs,

                    )

                except exceptions as exc:

                    last_exception = exc

                    if attempt == config.attempts:

                        break

                    delay = strategy(

                        attempt,

                        config,

                    )

                    if config.jitter:

                        delay = add_jitter(delay)

                    time.sleep(delay)

            raise last_exception

        return wrapper

    return decorator

###########################################################################
# Retry Helper
###########################################################################

def retry_call(

    function: Callable,

    *args,

    config: RetryConfig | None = None,

    strategy: Callable = exponential_delay,

    exceptions=Exception,

    **kwargs,

):

    if config is None:

        config = RetryConfig()

    return retry(

        exceptions=exceptions,

        config=config,

        strategy=strategy,

    )(function)(*args, **kwargs)
    
    ###########################################################################
# Batch Retry
###########################################################################

def retry_many(

    functions: Iterable[Callable],

    config: RetryConfig | None = None,

):

    results = []

    for function in functions:

        results.append(

            retry(

                config=config,

            )(function)()

        )

    return results

    ###########################################################################
# Retry Callbacks
###########################################################################

@dataclass(slots=True)
class RetryCallbacks:

    on_retry: Optional[Callable] = None

    on_success: Optional[Callable] = None

    on_failure: Optional[Callable] = None
    
    ###########################################################################
# Retry Predicate
###########################################################################

def default_retry_predicate(
    result,
) -> bool:

    return False


def should_retry_result(
    result,
    predicate: Callable | None,
):

    if predicate is None:

        return False

    return predicate(result)

###########################################################################
# Stop Conditions
###########################################################################

def stop_after_attempt(
    attempt: int,
    config: RetryConfig,
):

    return attempt >= config.attempts


def stop_never(
    attempt: int,
    config: RetryConfig,
):

    return False

###########################################################################
# Async Retry
###########################################################################

def async_retry(

    exceptions=Exception,

    config: RetryConfig | None = None,

    strategy: Callable = exponential_delay,

    callbacks: RetryCallbacks | None = None,

):

    if config is None:

        config = RetryConfig()

    if callbacks is None:

        callbacks = RetryCallbacks()

    def decorator(function):

        @wraps(function)

        async def wrapper(*args, **kwargs):

            last_exception = None

            for attempt in range(

                1,

                config.attempts + 1,

            ):

                try:

                    result = await function(

                        *args,

                        **kwargs,

                    )

                    if callbacks.on_success:

                        callbacks.on_success(

                            result,

                            attempt,

                        )

                    return result

                except exceptions as exc:

                    last_exception = exc

                    if callbacks.on_retry:

                        callbacks.on_retry(

                            exc,

                            attempt,

                        )

                    if attempt == config.attempts:

                        break

                    delay = strategy(

                        attempt,

                        config,

                    )

                    if config.jitter:

                        delay = add_jitter(delay)

                    await asyncio.sleep(delay)

            if callbacks.on_failure:

                callbacks.on_failure(

                    last_exception,

                )

            raise last_exception

        return wrapper

    return decorator

###########################################################################
# Timeout
###########################################################################

def timeout(

    seconds: float,

):

    def decorator(function):

        @wraps(function)

        def wrapper(*args, **kwargs):

            start = time.perf_counter()

            result = function(

                *args,

                **kwargs,

            )

            elapsed = (

                time.perf_counter()

                - start

            )

            if elapsed > seconds:

                raise TimeoutError(

                    f"Execution exceeded {seconds} seconds"

                )

            return result

        return wrapper

    return decorator

###########################################################################
# Async Timeout
###########################################################################

async def wait_for(

    coroutine: Awaitable,

    timeout_seconds: float,

):

    return await asyncio.wait_for(

        coroutine,

        timeout_seconds,

    )
    
    ###########################################################################
# Policies
###########################################################################

FAST_POLICY = RetryConfig(

    attempts=3,

    delay=0.5,

    backoff=2,

)

DEFAULT_POLICY = RetryConfig(

    attempts=5,

    delay=1,

    backoff=2,

)

AGGRESSIVE_POLICY = RetryConfig(

    attempts=10,

    delay=2,

    backoff=2,

)

NETWORK_POLICY = RetryConfig(

    attempts=6,

    delay=1,

    backoff=2.5,

)

DATABASE_POLICY = RetryConfig(

    attempts=5,

    delay=2,

    backoff=2,

)

###########################################################################
# Retry Until
###########################################################################

def retry_until(

    predicate: Callable,

    config: RetryConfig | None = None,

):

    if config is None:

        config = RetryConfig()

    def decorator(function):

        @wraps(function)

        def wrapper(*args, **kwargs):

            for attempt in range(

                1,

                config.attempts + 1,

            ):

                result = function(

                    *args,

                    **kwargs,

                )

                if predicate(result):

                    return result

                delay = exponential_delay(

                    attempt,

                    config,

                )

                time.sleep(delay)

            return result

        return wrapper

    return decorator

###########################################################################
# Circuit Breaker
###########################################################################

class CircuitBreaker:

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ):

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"

    def can_execute(self):

        if self.state == "CLOSED":
            return True

        if self.state == "OPEN":

            elapsed = (
                time.time() - self.last_failure_time
            )

            if elapsed >= self.recovery_timeout:

                self.state = "HALF_OPEN"
                return True

            return False

        return True

    def record_success(self):

        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):

        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:

            self.state = "OPEN"

    def reset(self):

        self.failure_count = 0
        self.state = "CLOSED"
        self.last_failure_time = None
        
    ###########################################################################
# Statistics
###########################################################################

@dataclass(slots=True)
class RetryStatistics:

    total_calls: int = 0

    successful_calls: int = 0

    failed_calls: int = 0

    retries: int = 0

    total_delay: float = 0.0

    def success_rate(self):

        if self.total_calls == 0:

            return 0.0

        return (

            self.successful_calls

            / self.total_calls

        ) * 100

    def reset(self):

        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.retries = 0
        self.total_delay = 0.0
        
    ###########################################################################
# Context Manager
###########################################################################

class RetryContext:

    def __init__(
        self,
        statistics: RetryStatistics,
    ):

        self.statistics = statistics

    def __enter__(self):

        self.statistics.total_calls += 1

        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):

        if exc is None:

            self.statistics.successful_calls += 1

        else:

            self.statistics.failed_calls += 1

        return False
    ###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    return {

        "module": "retry",

        "version": "1.0.0",

        "default_attempts": DEFAULT_POLICY.attempts,

        "default_backoff": DEFAULT_POLICY.backoff,

        "supports_async": True,

        "supports_callbacks": True,

        "supports_circuit_breaker": True,

    }
    
    ###########################################################################
# Benchmark
###########################################################################

def benchmark_retry(

    function,

    iterations=100,

):

    start = time.perf_counter()

    for _ in range(iterations):

        try:

            function()

        except Exception:

            pass

    return (

        time.perf_counter()

        - start

    )
    
    ###########################################################################
# Convenience
###########################################################################

def retry_summary(

    statistics: RetryStatistics,

):

    return {

        "calls": statistics.total_calls,

        "success": statistics.successful_calls,

        "failed": statistics.failed_calls,

        "retries": statistics.retries,

        "success_rate": statistics.success_rate(),

        "delay": statistics.total_delay,

    }
    
    ###########################################################################
# Self Test
###########################################################################

def self_test():

    stats = RetryStatistics()

    with RetryContext(stats):

        pass

    return {

        "passed": (

            stats.total_calls == 1

            and stats.successful_calls == 1

        ),

        "statistics": retry_summary(stats),

    }
    
###########################################################################
# Global Statistics
###########################################################################

GLOBAL_RETRY_STATISTICS = RetryStatistics()


from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    last_ts: float


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str, str], TokenBucket] = {}

    def allow(self, session_id: str, service: str, operation: str, *, capacity: float, refill_per_sec: float) -> bool:
        key = (session_id, service, operation)
        now = time.time()
        b = self._buckets.get(key)
        if b is None:
            b = TokenBucket(capacity=capacity, refill_per_sec=refill_per_sec, tokens=capacity, last_ts=now)
            self._buckets[key] = b

        # refill
        elapsed = max(0.0, now - b.last_ts)
        b.tokens = min(b.capacity, b.tokens + elapsed * b.refill_per_sec)
        b.last_ts = now

        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False


rate_limiter = RateLimiter()


def allow_db(fetchone_fn, execute_fn, conn, key: str, limit: int) -> bool:
    """Postgres-backed rate limit: atomic upsert counter per 1-minute window.

    Survives restarts and works across replicas, unlike the in-memory bucket.
    Caller must commit so the increment persists even when the request is
    rejected (the 429 path would otherwise roll it back).
    """
    # ponytail: fixed window (allows ~2x burst at boundaries); switch to a
    # sliding window or DB token bucket if that matters
    row = fetchone_fn(conn, """
        INSERT INTO rate_limit_counters (key, window_start, count)
        VALUES (%s, date_trunc('minute', now()), 1)
        ON CONFLICT (key, window_start)
        DO UPDATE SET count = rate_limit_counters.count + 1
        RETURNING count
    """, [key])
    execute_fn(conn, """
        DELETE FROM rate_limit_counters
        WHERE key = %s AND window_start < now() - interval '10 minutes'
    """, [key])
    return row["count"] <= limit

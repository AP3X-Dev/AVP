"""Tests for rate limiting (in-memory bucket and Postgres-backed counter)."""
from avp_server.rate_limit import RateLimiter, allow_db


def test_memory_bucket_allows_then_denies():
    rl = RateLimiter()
    for _ in range(5):
        assert rl.allow("s1", "openai", "chat", capacity=5.0, refill_per_sec=0.0)
    assert not rl.allow("s1", "openai", "chat", capacity=5.0, refill_per_sec=0.0)
    # Different key has its own bucket
    assert rl.allow("s2", "openai", "chat", capacity=5.0, refill_per_sec=0.0)


def _fake_db(count):
    """Return (fetchone, execute, captured) where the upsert reports `count`."""
    captured = {"queries": []}

    def fetchone_fn(conn, query, params):
        captured["queries"].append((query, params))
        return {"count": count}

    def execute_fn(conn, query, params):
        captured["queries"].append((query, params))

    return fetchone_fn, execute_fn, captured


def test_allow_db_under_limit():
    fetchone_fn, execute_fn, _ = _fake_db(count=60)
    assert allow_db(fetchone_fn, execute_fn, None, "ses:openai:chat", 60)


def test_allow_db_over_limit():
    fetchone_fn, execute_fn, _ = _fake_db(count=61)
    assert not allow_db(fetchone_fn, execute_fn, None, "ses:openai:chat", 60)


def test_allow_db_upserts_and_prunes():
    fetchone_fn, execute_fn, captured = _fake_db(count=1)
    allow_db(fetchone_fn, execute_fn, None, "k", 60)
    upsert, prune = captured["queries"]
    assert "ON CONFLICT" in upsert[0] and upsert[1] == ["k"]
    assert "DELETE" in prune[0] and prune[1] == ["k"]

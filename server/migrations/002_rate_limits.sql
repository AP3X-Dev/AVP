-- Postgres-backed rate limit counters (fixed 1-minute windows)

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    key          TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);

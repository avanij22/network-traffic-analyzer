CREATE TABLE IF NOT EXISTS stats_windows (
    id              BIGSERIAL PRIMARY KEY,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    packets_per_sec DOUBLE PRECISION NOT NULL,
    bytes_per_sec   DOUBLE PRECISION NOT NULL,
    protocol_counts JSONB NOT NULL,
    top_talkers     JSONB NOT NULL,
    top_ports       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stats_start ON stats_windows (window_start);

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    src_ip      INET,
    dst_ip      INET,
    description TEXT NOT NULL,
    evidence    JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts (ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts (src_ip);
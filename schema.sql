CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    iface TEXT NOT NULL,
    log TEXT NOT NULL,
    severity JSONB,
    anomaly JSONB
);

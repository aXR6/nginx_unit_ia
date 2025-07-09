CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    iface TEXT NOT NULL,
    log TEXT NOT NULL,
    ip TEXT,
    ip_info JSONB,
    severity JSONB,
    anomaly JSONB,
    nids JSONB,
    semantic JSONB,
    is_attack BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip TEXT NOT NULL,
    reason TEXT,
    ip_info JSONB,
    status TEXT NOT NULL DEFAULT 'blocked',
    blocked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS whitelist_ips (
    id SERIAL PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    added_at TIMESTAMPTZ DEFAULT NOW()
);

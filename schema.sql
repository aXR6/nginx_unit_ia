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
    attack_type TEXT,
    semantic JSONB
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'blocked',
    blocked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS whitelist_ips (
    id SERIAL PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    added_at TIMESTAMPTZ DEFAULT NOW()
);

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
    semantic JSONB
);

-- Tabelas separadas para registros de ameacas e logs comuns
CREATE TABLE IF NOT EXISTS threat_logs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    iface TEXT NOT NULL,
    log TEXT NOT NULL,
    ip TEXT,
    ip_info JSONB,
    severity JSONB,
    anomaly JSONB,
    nids JSONB,
    semantic JSONB
);

CREATE TABLE IF NOT EXISTS common_logs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    iface TEXT NOT NULL,
    log TEXT NOT NULL,
    ip TEXT,
    ip_info JSONB,
    severity JSONB,
    anomaly JSONB,
    nids JSONB,
    semantic JSONB
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

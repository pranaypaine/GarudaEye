-- Initial schema for GarudaEye
-- Assets table stores all discovered cloud assets

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    sk TEXT NOT NULL,  -- Sort key: the actual value (IP, domain, bucket name, etc.)
    provider TEXT NOT NULL,
    region TEXT,
    service TEXT,
    resource_id TEXT,
    
    -- Enrichment data from analyzers
    ports TEXT,  -- JSON array
    country TEXT,
    city TEXT,
    organization TEXT,
    isp TEXT,
    asn TEXT,
    vulnerabilities TEXT,  -- JSON array
    http_title TEXT,
    http_server TEXT,
    ssl_cert TEXT,
    last_seen TIMESTAMP,
    shodan_data TEXT,  -- JSON object
    virustotal_score REAL,
    observatory_grade TEXT,
    observatory_score INTEGER,
    nmap_results TEXT,  -- JSON array
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(asset_type, sk)
);

CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_provider ON assets(provider);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON assets(created_at DESC);

-- Counts table stores aggregated statistics
CREATE TABLE IF NOT EXISTS counts (
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (category, value)
);

CREATE INDEX IF NOT EXISTS idx_counts_category ON counts(category);

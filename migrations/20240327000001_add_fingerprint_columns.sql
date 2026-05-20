-- Add fingerprint columns for risk scoring and OS detection
ALTER TABLE assets ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE assets ADD COLUMN os_guess TEXT;

CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score DESC);

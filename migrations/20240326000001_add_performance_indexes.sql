-- Add performance indexes for commonly queried fields

CREATE INDEX IF NOT EXISTS idx_assets_arn ON assets(arn);
CREATE INDEX IF NOT EXISTS idx_assets_encryption_enabled ON assets(encryption_enabled);
CREATE INDEX IF NOT EXISTS idx_assets_service ON assets(service);

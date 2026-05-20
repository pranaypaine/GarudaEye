-- Add relationships table to track connections between assets
CREATE TABLE IF NOT EXISTS asset_relationships (
    id TEXT PRIMARY KEY,
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,  -- e.g., 'uses', 'attached_to', 'member_of', 'routes_to', 'triggers'
    metadata TEXT,  -- JSON object with additional relationship details
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (source_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (target_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_relationships_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON asset_relationships(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationships_type ON asset_relationships(relationship_type);

-- Add metadata columns to assets table for enhanced information
ALTER TABLE assets ADD COLUMN tags TEXT;  -- JSON object
ALTER TABLE assets ADD COLUMN vpc_id TEXT;
ALTER TABLE assets ADD COLUMN subnet_id TEXT;
ALTER TABLE assets ADD COLUMN security_groups TEXT;  -- JSON array
ALTER TABLE assets ADD COLUMN iam_role TEXT;
ALTER TABLE assets ADD COLUMN network_interfaces TEXT;  -- JSON array
ALTER TABLE assets ADD COLUMN public_access BOOLEAN DEFAULT FALSE;
ALTER TABLE assets ADD COLUMN encryption_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE assets ADD COLUMN compliance_status TEXT;
ALTER TABLE assets ADD COLUMN configuration TEXT;  -- JSON object with full resource configuration
ALTER TABLE assets ADD COLUMN dns_name TEXT;
ALTER TABLE assets ADD COLUMN arn TEXT;  -- AWS Resource Name

-- Add indexes for new searchable fields
CREATE INDEX IF NOT EXISTS idx_assets_vpc ON assets(vpc_id);
CREATE INDEX IF NOT EXISTS idx_assets_subnet ON assets(subnet_id);
CREATE INDEX IF NOT EXISTS idx_assets_public_access ON assets(public_access);
CREATE INDEX IF NOT EXISTS idx_assets_dns_name ON assets(dns_name);
CREATE INDEX IF NOT EXISTS idx_assets_arn ON assets(arn);

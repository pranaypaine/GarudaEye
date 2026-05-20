<template>
  <div class="asset-detail-view">
    <div class="page-header">
      <div class="header-left">
        <button @click="$router.back()" class="btn-back">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
          Back
        </button>
        <div v-if="!loading && asset">
          <h2>{{ asset.sk }}</h2>
          <p>{{ formatType(asset.asset_type) }} · {{ asset.provider.toUpperCase() }} · {{ asset.region || 'Global' }}</p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">
      <div class="spinner"></div>
      Loading asset details...
    </div>

    <div v-else-if="error" class="error-state">
      <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <p>{{ error }}</p>
      <button @click="$router.push('/assets')" class="btn btn-primary">Go to Assets</button>
    </div>

    <div v-else class="content-layout">
      <!-- Main Asset Information -->
      <div class="card main-card">
        <div class="card-header">
          <h3>Asset Information</h3>
          <div class="header-badges">
            <span :class="['badge', `badge-${asset.provider}`]">{{ asset.provider.toUpperCase() }}</span>
            <span v-if="asset.public_access === true" class="badge badge-warning">Public Access</span>
            <span v-if="asset.public_access === false" class="badge badge-success">Private</span>
            <span v-if="asset.encryption_enabled === true" class="badge badge-success">Encrypted</span>
            <span v-if="asset.encryption_enabled === false" class="badge badge-danger">Unencrypted</span>
          </div>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item">
              <label>Type</label>
              <span :class="['badge', `badge-${asset.asset_type.replace(/_/g, '')}`]">{{ formatType(asset.asset_type) }}</span>
            </div>
            <div class="info-item">
              <label>Name / Value</label>
              <span class="value">{{ asset.sk }}</span>
            </div>
            <div class="info-item" v-if="asset.service">
              <label>Service</label>
              <span>{{ asset.service }}</span>
            </div>
            <div class="info-item" v-if="asset.region">
              <label>Region</label>
              <span>{{ asset.region }}</span>
            </div>
            <div class="info-item" v-if="asset.resource_id">
              <label>Resource ID</label>
              <span class="code-small">{{ asset.resource_id }}</span>
            </div>
            <div class="info-item" v-if="asset.arn">
              <label>ARN</label>
              <span class="code-small">{{ asset.arn }}</span>
            </div>
            <div class="info-item" v-if="asset.dns_name">
              <label>DNS Name</label>
              <span>{{ asset.dns_name }}</span>
            </div>
            <div class="info-item">
              <label>Asset ID</label>
              <span class="code">{{ asset.id }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Network Information -->
      <div class="card" v-if="hasNetworkInfo">
        <div class="card-header">
          <h3>Network Configuration</h3>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="asset.vpc_id">
              <label>VPC ID</label>
              <span class="code-small">{{ asset.vpc_id }}</span>
            </div>
            <div class="info-item" v-if="asset.subnet_id">
              <label>Subnet ID</label>
              <span class="code-small">{{ asset.subnet_id }}</span>
            </div>
            <div class="info-item" v-if="asset.iam_role">
              <label>IAM Role</label>
              <span class="code-small">{{ asset.iam_role }}</span>
            </div>
            <div class="info-item" v-if="asset.security_groups && asset.security_groups.length > 0">
              <label>Security Groups</label>
              <div class="tag-list">
                <span v-for="sg in asset.security_groups" :key="sg" class="tag">{{ sg }}</span>
              </div>
            </div>
            <div class="info-item" v-if="asset.network_interfaces && asset.network_interfaces.length > 0">
              <label>Network Interfaces</label>
              <span>{{ asset.network_interfaces.length }} interface(s)</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Security & Compliance -->
      <div class="card" v-if="hasSecurityInfo">
        <div class="card-header">
          <h3>Security &amp; Compliance</h3>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="asset.public_access !== null && asset.public_access !== undefined">
              <label>Public Access</label>
              <span :class="['badge', asset.public_access ? 'badge-warning' : 'badge-success']">
                {{ asset.public_access ? 'Exposed to Internet' : 'Private' }}
              </span>
            </div>
            <div class="info-item" v-if="asset.encryption_enabled !== null && asset.encryption_enabled !== undefined">
              <label>Encryption at Rest</label>
              <span :class="['badge', asset.encryption_enabled ? 'badge-success' : 'badge-danger']">
                {{ asset.encryption_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="asset.compliance_status">
              <label>Compliance Status</label>
              <span>{{ asset.compliance_status }}</span>
            </div>
            <div class="info-item" v-if="asset.vulnerabilities && asset.vulnerabilities.length > 0">
              <label>Vulnerabilities</label>
              <span class="badge badge-danger">{{ asset.vulnerabilities.length }} found</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Service-Specific Configuration Panels -->

      <!-- Lambda -->
      <div class="card" v-if="asset.asset_type === 'lambda' && cfg">
        <div class="card-header"><h3>Lambda Function</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.runtime"><label>Runtime</label><span>{{ cfg.runtime }}</span></div>
            <div class="info-item" v-if="cfg.memory_size"><label>Memory</label><span>{{ cfg.memory_size }} MB</span></div>
            <div class="info-item" v-if="cfg.timeout"><label>Timeout</label><span>{{ cfg.timeout }}s</span></div>
            <div class="info-item" v-if="cfg.architectures"><label>Architecture</label><span>{{ cfg.architectures.join(', ') }}</span></div>
            <div class="info-item" v-if="cfg.package_type"><label>Package Type</label><span>{{ cfg.package_type }}</span></div>
            <div class="info-item" v-if="cfg.handler"><label>Handler</label><span class="code-small">{{ cfg.handler }}</span></div>
            <div class="info-item" v-if="cfg.code_size"><label>Code Size</label><span>{{ formatBytes(cfg.code_size) }}</span></div>
            <div class="info-item" v-if="cfg.last_modified"><label>Last Modified</label><span>{{ cfg.last_modified }}</span></div>
            <div class="info-item" v-if="cfg.layers && cfg.layers.length"><label>Layers</label><span>{{ cfg.layers.length }} layer(s)</span></div>
          </div>
          <div v-if="cfg.environment_variables && Object.keys(cfg.environment_variables).length" class="subsection">
            <h4>Environment Variables</h4>
            <div class="kv-table">
              <div v-for="(val, key) in cfg.environment_variables" :key="key" class="kv-row">
                <span class="kv-key">{{ key }}</span>
                <span class="kv-val">{{ val }}</span>
              </div>
            </div>
          </div>
          <div v-if="cfg.dlq_config" class="subsection">
            <h4>Dead Letter Queue</h4>
            <div class="info-grid">
              <div class="info-item"><label>Target ARN</label><span class="code-small">{{ cfg.dlq_config.target_arn }}</span></div>
            </div>
          </div>
        </div>
      </div>

      <!-- S3 Bucket -->
      <div class="card" v-if="asset.asset_type === 's3_bucket' && cfg">
        <div class="card-header"><h3>S3 Bucket Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.creation_date"><label>Created</label><span>{{ cfg.creation_date }}</span></div>
            <div class="info-item"><label>Versioning</label>
              <span :class="['badge', cfg.versioning_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.versioning_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item"><label>MFA Delete</label>
              <span :class="['badge', cfg.mfa_delete ? 'badge-success' : 'badge-muted']">
                {{ cfg.mfa_delete ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item"><label>Server Access Logging</label>
              <span :class="['badge', cfg.logging_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.logging_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
          </div>
          <div v-if="cfg.public_access_block" class="subsection">
            <h4>Public Access Block Settings</h4>
            <div class="info-grid">
              <div class="info-item"><label>BlockPublicAcls</label>
                <span :class="['badge', cfg.public_access_block.block_public_acls ? 'badge-success' : 'badge-danger']">
                  {{ cfg.public_access_block.block_public_acls ? 'Blocked' : 'Allowed' }}
                </span>
              </div>
              <div class="info-item"><label>BlockPublicPolicy</label>
                <span :class="['badge', cfg.public_access_block.block_public_policy ? 'badge-success' : 'badge-danger']">
                  {{ cfg.public_access_block.block_public_policy ? 'Blocked' : 'Allowed' }}
                </span>
              </div>
              <div class="info-item"><label>IgnorePublicAcls</label>
                <span :class="['badge', cfg.public_access_block.ignore_public_acls ? 'badge-success' : 'badge-danger']">
                  {{ cfg.public_access_block.ignore_public_acls ? 'Yes' : 'No' }}
                </span>
              </div>
              <div class="info-item"><label>RestrictPublicBuckets</label>
                <span :class="['badge', cfg.public_access_block.restrict_public_buckets ? 'badge-success' : 'badge-danger']">
                  {{ cfg.public_access_block.restrict_public_buckets ? 'Restricted' : 'Unrestricted' }}
                </span>
              </div>
            </div>
          </div>
          <div v-if="cfg.encryption" class="subsection">
            <h4>Encryption</h4>
            <div class="info-grid">
              <div class="info-item" v-if="cfg.encryption.sse_algorithm"><label>Algorithm</label><span>{{ cfg.encryption.sse_algorithm }}</span></div>
              <div class="info-item" v-if="cfg.encryption.kms_key_id"><label>KMS Key</label><span class="code-small">{{ cfg.encryption.kms_key_id }}</span></div>
            </div>
          </div>
        </div>
      </div>

      <!-- RDS Database -->
      <div class="card" v-if="asset.asset_type === 'database' && cfg">
        <div class="card-header"><h3>RDS Instance Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.engine"><label>Engine</label><span>{{ cfg.engine }} {{ cfg.engine_version }}</span></div>
            <div class="info-item" v-if="cfg.instance_class"><label>Instance Class</label><span>{{ cfg.instance_class }}</span></div>
            <div class="info-item" v-if="cfg.db_instance_status"><label>Status</label><span>{{ cfg.db_instance_status }}</span></div>
            <div class="info-item"><label>Multi-AZ</label>
              <span :class="['badge', cfg.multi_az ? 'badge-success' : 'badge-muted']">
                {{ cfg.multi_az ? 'Yes' : 'No' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.master_username"><label>Master User</label><span>{{ cfg.master_username }}</span></div>
            <div class="info-item" v-if="cfg.db_name"><label>Database Name</label><span>{{ cfg.db_name }}</span></div>
            <div class="info-item" v-if="cfg.port"><label>Port</label><span>{{ cfg.port }}</span></div>
            <div class="info-item" v-if="cfg.allocated_storage"><label>Storage</label><span>{{ cfg.allocated_storage }} GB ({{ cfg.storage_type }})</span></div>
            <div class="info-item" v-if="cfg.iops"><label>IOPS</label><span>{{ cfg.iops }}</span></div>
            <div class="info-item" v-if="cfg.backup_retention_period !== undefined"><label>Backup Retention</label><span>{{ cfg.backup_retention_period }} days</span></div>
            <div class="info-item"><label>Deletion Protection</label>
              <span :class="['badge', cfg.deletion_protection ? 'badge-success' : 'badge-warning']">
                {{ cfg.deletion_protection ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.ca_certificate_identifier"><label>CA Certificate</label><span>{{ cfg.ca_certificate_identifier }}</span></div>
          </div>
        </div>
      </div>

      <!-- EC2 Instance -->
      <div class="card" v-if="asset.asset_type === 'ip_address' && cfg && cfg.instance_id">
        <div class="card-header"><h3>EC2 Instance Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.instance_id"><label>Instance ID</label><span class="code-small">{{ cfg.instance_id }}</span></div>
            <div class="info-item" v-if="cfg.instance_type"><label>Instance Type</label><span>{{ cfg.instance_type }}</span></div>
            <div class="info-item" v-if="cfg.state"><label>State</label><span>{{ cfg.state }}</span></div>
            <div class="info-item" v-if="cfg.image_id"><label>AMI</label><span class="code-small">{{ cfg.image_id }}</span></div>
            <div class="info-item" v-if="cfg.platform"><label>Platform</label><span>{{ cfg.platform }}</span></div>
            <div class="info-item" v-if="cfg.architecture"><label>Architecture</label><span>{{ cfg.architecture }}</span></div>
            <div class="info-item" v-if="cfg.launch_time"><label>Launch Time</label><span>{{ cfg.launch_time }}</span></div>
            <div class="info-item" v-if="cfg.key_name"><label>Key Pair</label><span>{{ cfg.key_name }}</span></div>
          </div>
          <div v-if="cfg.ebs_volumes && cfg.ebs_volumes.length" class="subsection">
            <h4>EBS Volumes</h4>
            <table class="mini-table">
              <thead><tr><th>Device</th><th>Volume ID</th><th>State</th><th>Encrypted</th></tr></thead>
              <tbody>
                <tr v-for="vol in cfg.ebs_volumes" :key="vol.volume_id">
                  <td>{{ vol.device_name }}</td>
                  <td class="code-tiny">{{ vol.volume_id }}</td>
                  <td>{{ vol.status }}</td>
                  <td><span :class="['badge', vol.encrypted ? 'badge-success' : 'badge-danger']">{{ vol.encrypted ? 'Yes' : 'No' }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="cfg.elastic_ips && cfg.elastic_ips.length" class="subsection">
            <h4>Elastic IPs</h4>
            <div class="tag-list">
              <span v-for="eip in cfg.elastic_ips" :key="eip" class="tag">{{ eip }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Security Group -->
      <div class="card" v-if="asset.asset_type === 'security_group' && cfg">
        <div class="card-header"><h3>Security Group Rules</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.group_name"><label>Group Name</label><span>{{ cfg.group_name }}</span></div>
            <div class="info-item" v-if="cfg.description"><label>Description</label><span>{{ cfg.description }}</span></div>
            <div class="info-item" v-if="cfg.owner_id"><label>Owner ID</label><span class="code-small">{{ cfg.owner_id }}</span></div>
          </div>
          <div v-if="cfg.ingress_rules && cfg.ingress_rules.length" class="subsection">
            <h4>Inbound Rules ({{ cfg.ingress_rules.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>Protocol</th><th>Ports</th><th>Source</th><th>Open to World</th></tr></thead>
              <tbody>
                <tr v-for="(rule, i) in cfg.ingress_rules" :key="i">
                  <td>{{ rule.protocol === '-1' ? 'All' : rule.protocol }}</td>
                  <td>{{ formatPortRange(rule) }}</td>
                  <td>{{ ruleSources(rule) }}</td>
                  <td>
                    <span v-if="isOpenToWorld(rule)" class="badge badge-danger">⚠ Open to World</span>
                    <span v-else class="badge badge-success">Restricted</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="cfg.egress_rules && cfg.egress_rules.length" class="subsection">
            <h4>Outbound Rules ({{ cfg.egress_rules.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>Protocol</th><th>Ports</th><th>Destination</th></tr></thead>
              <tbody>
                <tr v-for="(rule, i) in cfg.egress_rules" :key="i">
                  <td>{{ rule.protocol === '-1' ? 'All' : rule.protocol }}</td>
                  <td>{{ formatPortRange(rule) }}</td>
                  <td>{{ ruleSources(rule) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- VPC -->
      <div class="card" v-if="asset.asset_type === 'vpc' && cfg">
        <div class="card-header"><h3>VPC Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.cidr_block"><label>CIDR Block</label><span class="code-small">{{ cfg.cidr_block }}</span></div>
            <div class="info-item" v-if="cfg.state"><label>State</label><span>{{ cfg.state }}</span></div>
            <div class="info-item"><label>Default VPC</label>
              <span :class="['badge', cfg.is_default ? 'badge-warning' : 'badge-muted']">{{ cfg.is_default ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item" v-if="cfg.dhcp_options_id"><label>DHCP Options</label><span class="code-small">{{ cfg.dhcp_options_id }}</span></div>
            <div class="info-item" v-if="cfg.instance_tenancy"><label>Tenancy</label><span>{{ cfg.instance_tenancy }}</span></div>
            <div class="info-item" v-if="cfg.owner_id"><label>Owner ID</label><span class="code-small">{{ cfg.owner_id }}</span></div>
          </div>
          <div v-if="cfg.ipv6_cidr_associations && cfg.ipv6_cidr_associations.length" class="subsection">
            <h4>IPv6 CIDR Associations</h4>
            <div class="tag-list">
              <span v-for="assoc in cfg.ipv6_cidr_associations" :key="assoc.ipv6_cidr_block" class="tag">{{ assoc.ipv6_cidr_block }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Subnet -->
      <div class="card" v-if="asset.asset_type === 'subnet' && cfg">
        <div class="card-header"><h3>Subnet Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.cidr_block"><label>CIDR Block</label><span class="code-small">{{ cfg.cidr_block }}</span></div>
            <div class="info-item" v-if="cfg.availability_zone"><label>Availability Zone</label><span>{{ cfg.availability_zone }}</span></div>
            <div class="info-item" v-if="cfg.available_ip_count !== undefined"><label>Available IPs</label><span>{{ cfg.available_ip_count }}</span></div>
            <div class="info-item" v-if="cfg.state"><label>State</label><span>{{ cfg.state }}</span></div>
            <div class="info-item"><label>Default for AZ</label>
              <span class="badge badge-muted">{{ cfg.default_for_az ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item"><label>Auto-assign Public IP</label>
              <span :class="['badge', cfg.map_public_ip_on_launch ? 'badge-warning' : 'badge-success']">
                {{ cfg.map_public_ip_on_launch ? 'Yes' : 'No' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- ElastiCache -->
      <div class="card" v-if="asset.asset_type === 'cache' && cfg">
        <div class="card-header"><h3>ElastiCache Cluster Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.engine"><label>Engine</label><span>{{ cfg.engine }} {{ cfg.engine_version }}</span></div>
            <div class="info-item" v-if="cfg.cache_node_type"><label>Node Type</label><span>{{ cfg.cache_node_type }}</span></div>
            <div class="info-item" v-if="cfg.cluster_status"><label>Status</label><span>{{ cfg.cluster_status }}</span></div>
            <div class="info-item" v-if="cfg.num_cache_nodes !== undefined"><label>Nodes</label><span>{{ cfg.num_cache_nodes }}</span></div>
            <div class="info-item"><label>Multi-AZ</label>
              <span :class="['badge', cfg.multi_az_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.multi_az_enabled ? 'Yes' : 'No' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.automatic_failover_enabled !== undefined"><label>Auto Failover</label>
              <span :class="['badge', cfg.automatic_failover_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.automatic_failover_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.replication_group_id"><label>Replication Group</label><span class="code-small">{{ cfg.replication_group_id }}</span></div>
            <div class="info-item" v-if="cfg.primary_endpoint"><label>Primary Endpoint</label><span>{{ cfg.primary_endpoint }}</span></div>
          </div>
        </div>
      </div>

      <!-- DynamoDB Table -->
      <div class="card" v-if="asset.asset_type === 'table' && cfg">
        <div class="card-header"><h3>DynamoDB Table Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.table_status"><label>Status</label><span>{{ cfg.table_status }}</span></div>
            <div class="info-item" v-if="cfg.table_class"><label>Table Class</label><span>{{ cfg.table_class }}</span></div>
            <div class="info-item" v-if="cfg.item_count !== undefined"><label>Item Count</label><span>{{ cfg.item_count.toLocaleString() }}</span></div>
            <div class="info-item" v-if="cfg.table_size_bytes !== undefined"><label>Size</label><span>{{ formatBytes(cfg.table_size_bytes) }}</span></div>
            <div class="info-item"><label>Point-in-Time Recovery</label>
              <span :class="['badge', cfg.point_in_time_recovery_enabled ? 'badge-success' : 'badge-warning']">
                {{ cfg.point_in_time_recovery_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.stream_specification"><label>Streams</label>
              <span :class="['badge', cfg.stream_specification.stream_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.stream_specification.stream_enabled ? cfg.stream_specification.stream_view_type : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.replicas && cfg.replicas.length"><label>Replicas</label><span>{{ cfg.replicas.length }} region(s)</span></div>
          </div>
          <div v-if="cfg.global_secondary_indexes && cfg.global_secondary_indexes.length" class="subsection">
            <h4>Global Secondary Indexes ({{ cfg.global_secondary_indexes.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>Name</th><th>Status</th><th>Projection</th></tr></thead>
              <tbody>
                <tr v-for="gsi in cfg.global_secondary_indexes" :key="gsi.index_name">
                  <td>{{ gsi.index_name }}</td>
                  <td>{{ gsi.index_status }}</td>
                  <td>{{ gsi.projection_type }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- SQS Queue -->
      <div class="card" v-if="asset.asset_type === 'queue' && cfg">
        <div class="card-header"><h3>SQS Queue Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item"><label>FIFO Queue</label>
              <span :class="['badge', cfg.fifo_queue ? 'badge-info' : 'badge-muted']">{{ cfg.fifo_queue ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item" v-if="cfg.visibility_timeout !== undefined"><label>Visibility Timeout</label><span>{{ cfg.visibility_timeout }}s</span></div>
            <div class="info-item" v-if="cfg.maximum_message_size !== undefined"><label>Max Message Size</label><span>{{ formatBytes(cfg.maximum_message_size) }}</span></div>
            <div class="info-item" v-if="cfg.message_retention_period !== undefined"><label>Retention Period</label><span>{{ formatSeconds(cfg.message_retention_period) }}</span></div>
            <div class="info-item" v-if="cfg.receive_message_wait_time_seconds !== undefined"><label>Receive Wait Time</label><span>{{ cfg.receive_message_wait_time_seconds }}s</span></div>
            <div class="info-item" v-if="cfg.approximate_number_of_messages !== undefined"><label>Messages Available</label><span>{{ cfg.approximate_number_of_messages }}</span></div>
            <div class="info-item" v-if="cfg.approximate_number_of_messages_not_visible !== undefined"><label>Messages In Flight</label><span>{{ cfg.approximate_number_of_messages_not_visible }}</span></div>
            <div class="info-item"><label>SSE (SQS-managed)</label>
              <span :class="['badge', cfg.sqs_managed_sse_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.sqs_managed_sse_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
          </div>
          <div v-if="cfg.dead_letter_target_arn" class="subsection">
            <h4>Dead Letter Queue</h4>
            <div class="info-grid">
              <div class="info-item"><label>DLQ ARN</label><span class="code-small">{{ cfg.dead_letter_target_arn }}</span></div>
              <div class="info-item" v-if="cfg.max_receive_count"><label>Max Receive Count</label><span>{{ cfg.max_receive_count }}</span></div>
            </div>
          </div>
        </div>
      </div>

      <!-- SNS Topic -->
      <div class="card" v-if="asset.asset_type === 'topic' && cfg">
        <div class="card-header"><h3>SNS Topic Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item"><label>FIFO Topic</label>
              <span :class="['badge', cfg.fifo_topic ? 'badge-info' : 'badge-muted']">{{ cfg.fifo_topic ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item" v-if="cfg.subscriptions_confirmed !== undefined"><label>Confirmed Subscriptions</label><span>{{ cfg.subscriptions_confirmed }}</span></div>
            <div class="info-item" v-if="cfg.subscriptions_pending !== undefined"><label>Pending Subscriptions</label><span>{{ cfg.subscriptions_pending }}</span></div>
            <div class="info-item" v-if="cfg.subscriptions_deleted !== undefined"><label>Deleted Subscriptions</label><span>{{ cfg.subscriptions_deleted }}</span></div>
            <div class="info-item"><label>Content-Based Deduplication</label>
              <span :class="['badge', cfg.content_based_deduplication ? 'badge-success' : 'badge-muted']">
                {{ cfg.content_based_deduplication ? 'Yes' : 'No' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Load Balancer -->
      <div class="card" v-if="asset.asset_type === 'load_balancer' && cfg">
        <div class="card-header"><h3>Load Balancer Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.load_balancer_type"><label>Type</label><span>{{ cfg.load_balancer_type }}</span></div>
            <div class="info-item" v-if="cfg.scheme"><label>Scheme</label>
              <span :class="['badge', cfg.scheme === 'internet-facing' ? 'badge-warning' : 'badge-success']">
                {{ cfg.scheme }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.state"><label>State</label><span>{{ cfg.state }}</span></div>
            <div class="info-item" v-if="cfg.ip_address_type"><label>IP Address Type</label><span>{{ cfg.ip_address_type }}</span></div>
          </div>
          <div v-if="cfg.listeners && cfg.listeners.length" class="subsection">
            <h4>Listeners ({{ cfg.listeners.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>Protocol</th><th>Port</th><th>SSL Policy</th></tr></thead>
              <tbody>
                <tr v-for="(listener, i) in cfg.listeners" :key="i">
                  <td>{{ listener.protocol }}</td>
                  <td>{{ listener.port }}</td>
                  <td>{{ listener.ssl_policy || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- API Gateway -->
      <div class="card" v-if="asset.asset_type === 'api_gateway' && cfg">
        <div class="card-header"><h3>API Gateway Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.protocol_type"><label>Protocol</label><span>{{ cfg.protocol_type }}</span></div>
            <div class="info-item" v-if="cfg.stage_name"><label>Stage</label><span>{{ cfg.stage_name }}</span></div>
            <div class="info-item"><label>Logging Enabled</label>
              <span :class="['badge', cfg.logging_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.logging_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item"><label>X-Ray Tracing</label>
              <span :class="['badge', cfg.xray_tracing_enabled ? 'badge-success' : 'badge-muted']">
                {{ cfg.xray_tracing_enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.endpoint_type"><label>Endpoint Type</label>
              <span :class="['badge', cfg.endpoint_type === 'PRIVATE' ? 'badge-success' : 'badge-warning']">
                {{ cfg.endpoint_type }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.deployment_id"><label>Deployment ID</label><span class="code-small">{{ cfg.deployment_id }}</span></div>
          </div>
        </div>
      </div>

      <!-- EKS Cluster -->
      <div class="card" v-if="asset.asset_type === 'cluster' && cfg">
        <div class="card-header"><h3>EKS Cluster Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.kubernetes_version"><label>Kubernetes Version</label><span>{{ cfg.kubernetes_version }}</span></div>
            <div class="info-item" v-if="cfg.status"><label>Status</label><span>{{ cfg.status }}</span></div>
            <div class="info-item" v-if="cfg.platform_version"><label>Platform Version</label><span>{{ cfg.platform_version }}</span></div>
            <div class="info-item"><label>Public Endpoint</label>
              <span :class="['badge', cfg.endpoint_public_access ? 'badge-warning' : 'badge-success']">
                {{ cfg.endpoint_public_access ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item"><label>Private Endpoint</label>
              <span :class="['badge', cfg.endpoint_private_access ? 'badge-success' : 'badge-muted']">
                {{ cfg.endpoint_private_access ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="info-item" v-if="cfg.role_arn"><label>Role ARN</label><span class="code-small">{{ cfg.role_arn }}</span></div>
          </div>
          <div v-if="cfg.node_groups && cfg.node_groups.length" class="subsection">
            <h4>Node Groups ({{ cfg.node_groups.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>Name</th><th>Status</th><th>Scaling</th></tr></thead>
              <tbody>
                <tr v-for="ng in cfg.node_groups" :key="ng.nodegroup_name">
                  <td>{{ ng.nodegroup_name }}</td>
                  <td>{{ ng.status }}</td>
                  <td v-if="ng.scaling_config">{{ ng.scaling_config.min_size }}/{{ ng.scaling_config.desired_size }}/{{ ng.scaling_config.max_size }}</td>
                  <td v-else>-</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ECS Container/Service -->
      <div class="card" v-if="asset.asset_type === 'container' && cfg">
        <div class="card-header"><h3>ECS Service Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.cluster_arn"><label>Cluster ARN</label><span class="code-small">{{ cfg.cluster_arn }}</span></div>
            <div class="info-item" v-if="cfg.task_definition"><label>Task Definition</label><span class="code-small">{{ cfg.task_definition }}</span></div>
            <div class="info-item" v-if="cfg.status"><label>Status</label><span>{{ cfg.status }}</span></div>
            <div class="info-item" v-if="cfg.desired_count !== undefined"><label>Desired Count</label><span>{{ cfg.desired_count }}</span></div>
            <div class="info-item" v-if="cfg.running_count !== undefined"><label>Running</label><span>{{ cfg.running_count }}</span></div>
            <div class="info-item" v-if="cfg.pending_count !== undefined"><label>Pending</label><span>{{ cfg.pending_count }}</span></div>
            <div class="info-item" v-if="cfg.launch_type"><label>Launch Type</label><span>{{ cfg.launch_type }}</span></div>
            <div class="info-item" v-if="cfg.scheduling_strategy"><label>Scheduling</label><span>{{ cfg.scheduling_strategy }}</span></div>
          </div>
        </div>
      </div>

      <!-- CloudFront Distribution -->
      <div class="card" v-if="asset.asset_type === 'cdn' && cfg">
        <div class="card-header"><h3>CloudFront Distribution</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.distribution_id"><label>Distribution ID</label><span class="code-small">{{ cfg.distribution_id }}</span></div>
            <div class="info-item" v-if="cfg.status"><label>Status</label><span>{{ cfg.status }}</span></div>
            <div class="info-item"><label>IPv6 Enabled</label>
              <span :class="['badge', cfg.is_ipv6_enabled ? 'badge-success' : 'badge-muted']">{{ cfg.is_ipv6_enabled ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item" v-if="cfg.http_version"><label>HTTP Version</label><span>{{ cfg.http_version }}</span></div>
            <div class="info-item" v-if="cfg.price_class"><label>Price Class</label><span>{{ cfg.price_class }}</span></div>
            <div class="info-item" v-if="cfg.geo_restriction_type"><label>Geo Restriction</label><span>{{ cfg.geo_restriction_type }}</span></div>
          </div>
          <div v-if="cfg.origins && cfg.origins.length" class="subsection">
            <h4>Origins ({{ cfg.origins.length }})</h4>
            <table class="mini-table">
              <thead><tr><th>ID</th><th>Domain</th><th>Protocol Policy</th></tr></thead>
              <tbody>
                <tr v-for="origin in cfg.origins" :key="origin.id">
                  <td>{{ origin.id }}</td>
                  <td>{{ origin.domain_name }}</td>
                  <td>{{ origin.origin_protocol_policy || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="cfg.aliases && cfg.aliases.length" class="subsection">
            <h4>Custom Domains (CNAMEs)</h4>
            <div class="tag-list">
              <span v-for="alias in cfg.aliases" :key="alias" class="tag">{{ alias }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Route53 -->
      <div class="card" v-if="asset.asset_type === 'domain' && cfg && cfg.hosted_zone_id">
        <div class="card-header"><h3>Route53 Zone Details</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="cfg.hosted_zone_id"><label>Zone ID</label><span class="code-small">{{ cfg.hosted_zone_id }}</span></div>
            <div class="info-item"><label>Private Zone</label>
              <span :class="['badge', cfg.private_zone ? 'badge-success' : 'badge-muted']">{{ cfg.private_zone ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item" v-if="cfg.record_count !== undefined"><label>Record Count</label><span>{{ cfg.record_count }}</span></div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: Risk Score Panel -->
      <div class="card fingerprint-risk-card" v-if="fp && asset.risk_score > 0">
        <div class="card-header">
          <h3>Risk Score</h3>
          <span :class="['badge', riskBadgeClass]">{{ riskLabel }}</span>
        </div>
        <div class="card-body">
          <div class="risk-meter-wrap">
            <div class="risk-meter">
              <div class="risk-fill" :style="{ width: Math.min(asset.risk_score, 100) + '%', background: riskColor }"></div>
            </div>
            <span class="risk-score-value">{{ asset.risk_score }} / 100</span>
          </div>
          <div class="security-warnings" v-if="fp.security_warnings && fp.security_warnings.length">
            <div v-for="(w, i) in fp.security_warnings" :key="i" class="warning-item">⚠ {{ w }}</div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: OS Detection -->
      <div class="card" v-if="asset.os_guess">
        <div class="card-header"><h3>OS Detection</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item">
              <label>Detected OS</label>
              <span>{{ asset.os_guess }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: TLS Certificate -->
      <div class="card" v-if="fp && fp.tls">
        <div class="card-header">
          <h3>TLS Certificate</h3>
          <span v-if="fp.tls.is_expired" class="badge badge-danger">Expired</span>
          <span v-else-if="fp.tls.days_until_expiry < 14" class="badge badge-warning">Expiring Soon</span>
          <span v-else class="badge badge-success">Valid</span>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="fp.tls.subject_cn"><label>Subject CN</label><span class="code-small">{{ fp.tls.subject_cn }}</span></div>
            <div class="info-item" v-if="fp.tls.issuer_cn"><label>Issuer</label><span>{{ fp.tls.issuer_cn }}</span></div>
            <div class="info-item"><label>Self-Signed</label>
              <span :class="['badge', fp.tls.self_signed ? 'badge-danger' : 'badge-success']">
                {{ fp.tls.self_signed ? 'Yes' : 'No' }}
              </span>
            </div>
            <div class="info-item" v-if="fp.tls.tls_version"><label>TLS Version</label><span>{{ fp.tls.tls_version }}</span></div>
            <div class="info-item" v-if="fp.tls.days_until_expiry !== undefined && fp.tls.days_until_expiry !== null">
              <label>Expires In</label>
              <span :class="fp.tls.days_until_expiry < 30 ? 'text-warning' : ''">
                {{ fp.tls.days_until_expiry }} days
              </span>
            </div>
            <div class="info-item" v-if="fp.tls.cert_fingerprint"><label>Fingerprint</label><span class="code-tiny">{{ fp.tls.cert_fingerprint }}</span></div>
          </div>
          <div v-if="fp.tls.san_domains && fp.tls.san_domains.length" class="subsection">
            <h4>Subject Alternative Names</h4>
            <div class="tag-list">
              <span v-for="san in fp.tls.san_domains" :key="san" class="tag">{{ san }}</span>
            </div>
          </div>
          <div v-if="fp.tls.tls_warnings && fp.tls.tls_warnings.length" class="subsection">
            <h4>TLS Warnings</h4>
            <div v-for="(w, i) in fp.tls.tls_warnings" :key="i" class="warning-item">⚠ {{ w }}</div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: HTTP Analysis -->
      <div class="card" v-if="fp && (fp.http || fp.https)">
        <div class="card-header"><h3>HTTP Analysis</h3></div>
        <div class="card-body">
          <div v-for="(proto, key) in { HTTP: fp.http, HTTPS: fp.https }" :key="key">
            <div v-if="proto" class="subsection">
              <h4>{{ key }}</h4>
              <div class="info-grid">
                <div class="info-item" v-if="proto.status_code"><label>Status Code</label><span>{{ proto.status_code }}</span></div>
                <div class="info-item" v-if="proto.server"><label>Server</label><span>{{ proto.server }}</span></div>
                <div class="info-item" v-if="proto.title"><label>Page Title</label><span>{{ proto.title }}</span></div>
                <div class="info-item" v-if="proto.content_length"><label>Content Length</label><span>{{ proto.content_length }}</span></div>
                <div class="info-item">
                  <label>HSTS</label>
                  <span :class="['badge', proto.hsts ? 'badge-success' : 'badge-warning']">{{ proto.hsts ? 'Present' : 'Missing' }}</span>
                </div>
                <div class="info-item">
                  <label>CSP</label>
                  <span :class="['badge', proto.csp ? 'badge-success' : 'badge-warning']">{{ proto.csp ? 'Present' : 'Missing' }}</span>
                </div>
              </div>
              <div v-if="proto.technologies && proto.technologies.length" class="subsection">
                <h4>Detected Technologies</h4>
                <div class="tag-list">
                  <span v-for="t in proto.technologies" :key="t" class="tag">{{ t }}</span>
                </div>
              </div>
              <div v-if="proto.security_issues && proto.security_issues.length" class="subsection">
                <div v-for="(issue, i) in proto.security_issues" :key="i" class="warning-item">⚠ {{ issue }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: Banner / Service Detection -->
      <div class="card" v-if="fp && fp.banners && fp.banners.length">
        <div class="card-header"><h3>Service Banners ({{ fp.banners.length }})</h3></div>
        <div class="card-body">
          <table class="mini-table">
            <thead><tr><th>Port</th><th>Protocol</th><th>Product</th><th>Version</th><th>CVE Hints</th></tr></thead>
            <tbody>
              <tr v-for="b in fp.banners" :key="b.port">
                <td>{{ b.port }}</td>
                <td>{{ b.protocol }}</td>
                <td>{{ b.product || '-' }}</td>
                <td>{{ b.version || '-' }}</td>
                <td>
                  <span v-if="b.cve_hints && b.cve_hints.length" class="badge badge-danger">{{ b.cve_hints.length }} hint(s)</span>
                  <span v-else class="badge badge-muted">None</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Fingerprint: DNS Info -->
      <div class="card" v-if="fp && fp.dns">
        <div class="card-header"><h3>DNS Analysis</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="fp.dns.dns_provider"><label>DNS Provider</label><span>{{ fp.dns.dns_provider }}</span></div>
            <div class="info-item" v-if="fp.dns.cloud_hint"><label>Cloud Hint</label><span>{{ fp.dns.cloud_hint }}</span></div>
            <div class="info-item"><label>SPF Record</label>
              <span :class="['badge', fp.dns.has_spf ? 'badge-success' : 'badge-warning']">{{ fp.dns.has_spf ? 'Present' : 'Missing' }}</span>
            </div>
            <div class="info-item"><label>DMARC Record</label>
              <span :class="['badge', fp.dns.has_dmarc ? 'badge-success' : 'badge-warning']">{{ fp.dns.has_dmarc ? 'Present' : 'Missing' }}</span>
            </div>
            <div class="info-item"><label>DNSSEC</label>
              <span :class="['badge', fp.dns.dnssec_enabled ? 'badge-success' : 'badge-muted']">{{ fp.dns.dnssec_enabled ? 'Enabled' : 'Disabled' }}</span>
            </div>
            <div class="info-item" v-if="fp.dns.ttl"><label>TTL</label><span>{{ fp.dns.ttl }}s</span></div>
          </div>
          <div v-if="fp.dns.a_records && fp.dns.a_records.length" class="subsection">
            <h4>A Records</h4>
            <div class="tag-list">
              <span v-for="ip in fp.dns.a_records" :key="ip" class="tag">{{ ip }}</span>
            </div>
          </div>
          <div v-if="fp.dns.mx_records && fp.dns.mx_records.length" class="subsection">
            <h4>MX Records</h4>
            <div class="tag-list">
              <span v-for="mx in fp.dns.mx_records" :key="mx" class="tag">{{ mx }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: ASN / Geo -->
      <div class="card" v-if="fp && fp.asn">
        <div class="card-header"><h3>ASN &amp; Geolocation</h3></div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item" v-if="fp.asn.asn_string"><label>ASN</label><span class="code-small">{{ fp.asn.asn_string }}</span></div>
            <div class="info-item" v-if="fp.asn.org_name"><label>Organization</label><span>{{ fp.asn.org_name }}</span></div>
            <div class="info-item" v-if="fp.asn.country"><label>Country</label><span>{{ fp.asn.country }}</span></div>
            <div class="info-item" v-if="fp.asn.route"><label>Route</label><span class="code-small">{{ fp.asn.route }}</span></div>
            <div class="info-item"><label>Hosting Provider</label>
              <span :class="['badge', fp.asn.is_hosting ? 'badge-warning' : 'badge-muted']">{{ fp.asn.is_hosting ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-item"><label>CDN</label>
              <span :class="['badge', fp.asn.is_cdn ? 'badge-info' : 'badge-muted']">{{ fp.asn.is_cdn ? 'Yes' : 'No' }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Fingerprint: CVE Hints -->
      <div class="card" v-if="asset.vulnerabilities && asset.vulnerabilities.length">
        <div class="card-header">
          <h3>CVE Hints ({{ asset.vulnerabilities.length }})</h3>
          <span class="badge badge-danger">Requires Investigation</span>
        </div>
        <div class="card-body">
          <div v-for="(cve, i) in asset.vulnerabilities" :key="i" class="vuln-hint-item">
            <span class="badge badge-danger">CVE</span>
            <span class="vuln-hint-text">{{ cve }}</span>
          </div>
        </div>
      </div>

      <!-- Tags -->
      <div class="card" v-if="asset.tags && Object.keys(asset.tags).length > 0">
        <div class="card-header">
          <h3>Tags ({{ Object.keys(asset.tags).length }})</h3>
        </div>
        <div class="card-body">
          <div class="tags-grid">
            <div v-for="(value, key) in asset.tags" :key="key" class="tag-item">
              <span class="tag-key">{{ key }}</span>
              <span class="tag-value">{{ value }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Open Ports -->
      <div class="card" v-if="asset.ports && asset.ports.length > 0">
        <div class="card-header">
          <h3>Open Ports</h3>
        </div>
        <div class="card-body">
          <div class="port-grid">
            <div v-for="port in asset.ports" :key="port" class="port-item">
              <span class="port-number">{{ port }}</span>
              <span class="port-service">{{ getPortService(port) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Raw Configuration (fallback for unlisted types) -->
      <div class="card" v-if="cfg && !isKnownType">
        <div class="card-header">
          <h3>Configuration</h3>
        </div>
        <div class="card-body">
          <pre class="configuration-json">{{ JSON.stringify(cfg, null, 2) }}</pre>
        </div>
      </div>

      <!-- Outgoing Relationships -->
      <div class="card" v-if="relationships.outgoing.length > 0">
        <div class="card-header">
          <h3>Uses / Depends On ({{ relationships.outgoing.length }})</h3>
        </div>
        <div class="card-body">
          <div class="relationships-list">
            <div
              v-for="rel in relationships.outgoing"
              :key="rel.relationship_id"
              @click="navigateToAsset(rel.asset.id)"
              class="relationship-item clickable"
            >
              <div class="relationship-type">
                <span class="badge badge-relationship">{{ rel.relationship_type }}</span>
              </div>
              <div class="relationship-asset">
                <span :class="['badge', `badge-${rel.asset.asset_type.replace(/_/g, '')}`]">
                  {{ formatType(rel.asset.asset_type) }}
                </span>
                <span class="relationship-name">{{ rel.asset.sk }}</span>
              </div>
              <div class="relationship-provider">
                <span :class="['badge', `badge-${rel.asset.provider}`]">{{ rel.asset.provider.toUpperCase() }}</span>
                <span v-if="rel.asset.region" class="relationship-region">{{ rel.asset.region }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Incoming Relationships -->
      <div class="card" v-if="relationships.incoming.length > 0">
        <div class="card-header">
          <h3>Used By / Depended On By ({{ relationships.incoming.length }})</h3>
        </div>
        <div class="card-body">
          <div class="relationships-list">
            <div
              v-for="rel in relationships.incoming"
              :key="rel.relationship_id"
              @click="navigateToAsset(rel.asset.id)"
              class="relationship-item clickable"
            >
              <div class="relationship-type">
                <span class="badge badge-relationship">{{ rel.relationship_type }}</span>
              </div>
              <div class="relationship-asset">
                <span :class="['badge', `badge-${rel.asset.asset_type.replace(/_/g, '')}`]">
                  {{ formatType(rel.asset.asset_type) }}
                </span>
                <span class="relationship-name">{{ rel.asset.sk }}</span>
              </div>
              <div class="relationship-provider">
                <span :class="['badge', `badge-${rel.asset.provider}`]">{{ rel.asset.provider.toUpperCase() }}</span>
                <span v-if="rel.asset.region" class="relationship-region">{{ rel.asset.region }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Metadata -->
      <div class="card">
        <div class="card-header">
          <h3>Metadata</h3>
        </div>
        <div class="card-body">
          <div class="info-grid">
            <div class="info-item">
              <label>Discovered At</label>
              <span>{{ formatDate(asset.created_at) }}</span>
            </div>
            <div class="info-item">
              <label>Last Updated</label>
              <span>{{ formatDate(asset.updated_at) }}</span>
            </div>
            <div class="info-item" v-if="asset.last_seen">
              <label>Last Seen</label>
              <span>{{ formatDate(asset.last_seen) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const KNOWN_TYPES = [
  'lambda', 's3_bucket', 'database', 'ip_address', 'security_group',
  'vpc', 'subnet', 'cache', 'table', 'queue', 'topic', 'load_balancer',
  'api_gateway', 'cluster', 'container', 'cdn', 'domain'
]

export default {
  name: 'AssetDetail',
  data() {
    return {
      asset: null,
      relationships: { outgoing: [], incoming: [] },
      loading: true,
      error: null
    }
  },
  computed: {
    cfg() {
      return this.asset?.configuration || null
    },
    fp() {
      // Fingerprint data is the configuration object when it has fingerprint fields
      const c = this.asset?.configuration
      if (!c) return null
      // Distinguish fingerprint JSON from AWS config JSON by checking for fingerprint-specific keys
      if (c.target !== undefined || c.open_ports !== undefined || c.risk_score !== undefined) return c
      return null
    },
    riskLabel() {
      const s = this.asset?.risk_score || 0
      if (s >= 70) return 'Critical'
      if (s >= 40) return 'High'
      if (s >= 20) return 'Medium'
      return 'Low'
    },
    riskBadgeClass() {
      const s = this.asset?.risk_score || 0
      if (s >= 70) return 'badge-danger'
      if (s >= 40) return 'badge-warning'
      if (s >= 20) return 'badge-info'
      return 'badge-success'
    },
    riskColor() {
      const s = this.asset?.risk_score || 0
      if (s >= 70) return '#ef4444'
      if (s >= 40) return '#f59e0b'
      if (s >= 20) return '#3b82f6'
      return '#22c55e'
    },
    isKnownType() {
      return KNOWN_TYPES.includes(this.asset?.asset_type)
    },
    hasNetworkInfo() {
      return !!(
        this.asset.vpc_id ||
        this.asset.subnet_id ||
        this.asset.iam_role ||
        this.asset.security_groups?.length ||
        this.asset.network_interfaces?.length
      )
    },
    hasSecurityInfo() {
      return (
        this.asset.public_access !== null && this.asset.public_access !== undefined ||
        this.asset.encryption_enabled !== null && this.asset.encryption_enabled !== undefined ||
        !!this.asset.compliance_status ||
        this.asset.vulnerabilities?.length > 0
      )
    }
  },
  mounted() {
    this.loadAssetDetails()
  },
  methods: {
    async loadAssetDetails() {
      try {
        const assetId = this.$route.params.id
        const res = await axios.get(`/api/assets/${assetId}`)
        this.asset = res.data.asset
        this.relationships = res.data.relationships
        this.loading = false
      } catch (err) {
        console.error('Failed to load asset details:', err)
        this.error = err.response?.status === 404
          ? 'Asset not found'
          : 'Failed to load asset details'
        this.loading = false
      }
    },
    formatType(type) {
      return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
    },
    formatDate(date) {
      if (!date) return '-'
      return new Date(date).toLocaleString()
    },
    formatBytes(bytes) {
      if (!bytes) return '-'
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
      if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
      return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
    },
    formatSeconds(s) {
      if (!s) return '-'
      if (s < 60) return `${s}s`
      if (s < 3600) return `${Math.floor(s / 60)}m`
      return `${Math.floor(s / 3600)}h`
    },
    formatPortRange(rule) {
      if (rule.protocol === '-1') return 'All'
      if (rule.from_port === rule.to_port) return `${rule.from_port}`
      return `${rule.from_port}-${rule.to_port}`
    },
    ruleSources(rule) {
      const cidrs = rule.ip_ranges?.map(r => r.cidr_ip) || []
      const cidrsv6 = rule.ipv6_ranges?.map(r => r.cidr_ipv6) || []
      const sgs = rule.security_group_refs?.map(r => r.group_id) || []
      return [...cidrs, ...cidrsv6, ...sgs].join(', ') || '-'
    },
    isOpenToWorld(rule) {
      const cidrs = rule.ip_ranges?.map(r => r.cidr_ip) || []
      const cidrsv6 = rule.ipv6_ranges?.map(r => r.cidr_ipv6) || []
      return cidrs.includes('0.0.0.0/0') || cidrsv6.includes('::/0')
    },
    getPortService(port) {
      const services = {
        22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
        5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
        3389: 'RDP', 21: 'FTP', 25: 'SMTP', 53: 'DNS'
      }
      return services[port] || 'Unknown'
    },
    navigateToAsset(assetId) {
      this.$router.push(`/assets/${assetId}`)
      this.loadAssetDetails()
    }
  }
}
</script>

<style scoped>
.asset-detail-view {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header { margin-bottom: 2rem; }

.header-left {
  display: flex;
  align-items: flex-start;
  gap: 1.5rem;
}

.btn-back {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: #2d3548;
  border: 1px solid #3d4558;
  color: #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
  white-space: nowrap;
}

.btn-back:hover { background: #3d4558; border-color: #4d5568; }

.header-left h2 { margin: 0; font-size: 1.75rem; color: #e2e8f0; }
.header-left p { margin: 0.5rem 0 0; color: #94a3b8; }

.header-badges { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }

.content-layout { display: flex; flex-direction: column; gap: 1.5rem; }

.main-card .card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.5rem;
}

.info-item { display: flex; flex-direction: column; gap: 0.5rem; }

.info-item label { font-size: 0.8rem; color: #94a3b8; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.info-item span { color: #e2e8f0; font-size: 0.875rem; }

.value { font-weight: 600; font-size: 1rem !important; color: #3b82f6 !important; }

.code {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 0.7rem;
  background: #0f1419;
  padding: 0.5rem;
  border-radius: 4px;
  border: 1px solid #2d3548;
  word-break: break-all;
}

.code-small {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 0.7rem;
  background: #0f1419;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  border: 1px solid #2d3548;
  word-break: break-all;
}

.tag-list { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.tag { background: #2d3548; color: #e2e8f0; padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid #3d4558; }

.tags-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 0.75rem; }
.tag-item { display: flex; gap: 0.75rem; padding: 0.75rem; background: #0f1419; border-radius: 6px; border: 1px solid #2d3548; }
.tag-key { font-size: 0.8rem; color: #94a3b8; font-weight: 500; min-width: 120px; }
.tag-value { font-size: 0.8rem; color: #e2e8f0; word-break: break-all; }

.port-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 0.75rem; }
.port-item { display: flex; flex-direction: column; padding: 0.75rem; background: #0f1419; border-radius: 6px; border: 1px solid #2d3548; text-align: center; }
.port-number { font-size: 1.25rem; color: #3b82f6; font-weight: 700; }
.port-service { font-size: 0.7rem; color: #94a3b8; margin-top: 0.25rem; }

.configuration-json { background: #0f1419; padding: 1rem; border-radius: 6px; border: 1px solid #2d3548; color: #e2e8f0; font-size: 0.8rem; overflow-x: auto; margin: 0; }

.subsection { margin-top: 1.5rem; }
.subsection h4 { margin: 0 0 0.75rem; font-size: 0.875rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }

.mini-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.mini-table th { text-align: left; padding: 0.5rem 0.75rem; background: #1a1f2e; color: #94a3b8; font-weight: 500; border-bottom: 1px solid #2d3548; }
.mini-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1a1f2e; color: #e2e8f0; }
.mini-table tr:hover td { background: #0f1419; }

.code-tiny { font-family: 'Monaco', 'Menlo', monospace; font-size: 0.65rem; color: #94a3b8; }

.kv-table { display: flex; flex-direction: column; gap: 0.4rem; }
.kv-row { display: flex; gap: 1rem; padding: 0.4rem 0.6rem; background: #0f1419; border-radius: 4px; font-size: 0.8rem; }
.kv-key { color: #94a3b8; min-width: 160px; word-break: break-all; }
.kv-val { color: #e2e8f0; word-break: break-all; }

.relationships-list { display: flex; flex-direction: column; gap: 0.75rem; }
.relationship-item { display: grid; grid-template-columns: 150px 1fr auto; gap: 1rem; align-items: center; padding: 1rem; background: #0f1419; border-radius: 6px; border: 1px solid #2d3548; transition: all 0.2s; }
.relationship-item.clickable { cursor: pointer; }
.relationship-item.clickable:hover { background: #1a1f2e; border-color: #3b82f6; transform: translateX(4px); }

.badge-relationship { background: #3b82f6; color: white; font-size: 0.75rem; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 500; }
.relationship-asset { display: flex; align-items: center; gap: 0.75rem; }
.relationship-name { color: #e2e8f0; font-weight: 500; }
.relationship-provider { display: flex; align-items: center; gap: 0.75rem; }
.relationship-region { color: #94a3b8; font-size: 0.875rem; }

.badge-info { background: #0ea5e9; color: white; }
.badge-muted { background: #374151; color: #9ca3af; }

.error-state { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 4rem 2rem; text-align: center; }
.error-state svg { color: #ef4444; margin-bottom: 1rem; }
.error-state p { font-size: 1.125rem; color: #e2e8f0; margin-bottom: 1.5rem; }

@media (max-width: 768px) {
  .info-grid { grid-template-columns: 1fr; }
  .relationship-item { grid-template-columns: 1fr; gap: 0.75rem; }
  .tags-grid { grid-template-columns: 1fr; }
}

/* Fingerprint panels */
.fingerprint-risk-card .card-header { display: flex; justify-content: space-between; align-items: center; }
.risk-meter-wrap { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
.risk-meter { flex: 1; height: 14px; background: #1a1f2e; border-radius: 7px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 7px; transition: width 0.6s; }
.risk-score-value { font-size: 1.1rem; font-weight: 700; color: #e2e8f0; min-width: 60px; }
.text-warning { color: #f59e0b !important; }
.security-warnings { display: flex; flex-direction: column; gap: 0.4rem; }
.warning-item { font-size: 0.8rem; color: #fbbf24; padding: 0.3rem 0.6rem; background: #78350f30; border-radius: 4px; border-left: 3px solid #f59e0b; }
.vuln-hint-item { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid #1a1f2e; }
.vuln-hint-text { font-size: 0.85rem; color: #e2e8f0; word-break: break-all; }
</style>

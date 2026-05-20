<template>
  <div class="assets-view">
    <div class="page-header">
      <div>
        <h2>Assets Inventory</h2>
        <p>Complete list of discovered cloud assets</p>
      </div>
      <div class="header-actions">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search by name, ARN, VPC, DNS..."
          class="search-input"
        />
        <select v-model="filterType" class="filter-select">
          <option value="">All Types</option>
          <option value="ip_address">IP Address</option>
          <option value="domain">Domain</option>
          <option value="s3_bucket">S3 Bucket</option>
          <option value="database">Database (RDS)</option>
          <option value="load_balancer">Load Balancer</option>
          <option value="cache">Cache (ElastiCache)</option>
          <option value="cdn">CDN (CloudFront)</option>
          <option value="lambda">Lambda</option>
          <option value="api_gateway">API Gateway</option>
          <option value="queue">Queue (SQS)</option>
          <option value="topic">Topic (SNS)</option>
          <option value="table">Table (DynamoDB)</option>
          <option value="vpc">VPC</option>
          <option value="subnet">Subnet</option>
          <option value="security_group">Security Group</option>
          <option value="container">Container (ECS)</option>
          <option value="cluster">Cluster (EKS)</option>
        </select>
        <select v-model="filterProvider" class="filter-select">
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
          <option value="gcp">GCP</option>
        </select>
        <select v-model="filterRegion" class="filter-select">
          <option value="">All Regions</option>
          <option v-for="region in availableRegions" :key="region" :value="region">{{ region }}</option>
        </select>
        <select v-model="filterPublicAccess" class="filter-select">
          <option value="">All Access</option>
          <option value="true">Public Only</option>
          <option value="false">Private Only</option>
        </select>
        <select v-model="filterEncryption" class="filter-select">
          <option value="">All Encryption</option>
          <option value="true">Encrypted</option>
          <option value="false">Unencrypted</option>
        </select>
      </div>
    </div>

    <!-- Summary bar -->
    <div class="summary-bar" v-if="!loading">
      <span class="summary-item">
        <strong>{{ filteredAssets.length }}</strong> assets
      </span>
      <span class="summary-item warning" v-if="publicCount > 0">
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <strong>{{ publicCount }}</strong> public
      </span>
      <span class="summary-item danger" v-if="unencryptedCount > 0">
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>
        <strong>{{ unencryptedCount }}</strong> unencrypted
      </span>
    </div>

    <div class="card">
      <div class="card-body">
        <div v-if="loading" class="loading">
          <div class="spinner"></div>
          Loading assets...
        </div>
        <div v-else-if="filteredAssets.length === 0" class="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <circle cx="11" cy="11" r="8"></circle>
            <path d="m21 21-4.35-4.35"></path>
          </svg>
          <p>No assets found</p>
          <small>Try adjusting your filters or start a new scan</small>
        </div>
        <div v-else class="table-container">
          <table class="modern-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Name / Value</th>
                <th>Provider</th>
                <th>Service</th>
                <th>Region</th>
                <th>Public</th>
                <th>Encrypted</th>
                <th>ARN / Resource ID</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="asset in paginatedAssets"
                :key="asset.id"
                @click="navigateToDetail(asset.id)"
                class="clickable-row"
              >
                <td>
                  <span :class="['badge', `badge-${asset.asset_type.replace(/_/g, '')}`]">
                    {{ formatType(asset.asset_type) }}
                  </span>
                </td>
                <td>
                  <div class="asset-name">
                    <strong>{{ asset.sk }}</strong>
                    <small v-if="asset.dns_name" class="text-muted">{{ asset.dns_name }}</small>
                  </div>
                </td>
                <td>
                  <span :class="['badge', `badge-${asset.provider}`]">{{ asset.provider.toUpperCase() }}</span>
                </td>
                <td>{{ asset.service || '-' }}</td>
                <td>{{ asset.region || '-' }}</td>
                <td>
                  <span v-if="asset.public_access === true" class="badge badge-warning">Public</span>
                  <span v-else-if="asset.public_access === false" class="badge badge-success">Private</span>
                  <span v-else class="text-muted">-</span>
                </td>
                <td>
                  <span v-if="asset.encryption_enabled === true" class="badge badge-success">✓</span>
                  <span v-else-if="asset.encryption_enabled === false" class="badge badge-danger">✗</span>
                  <span v-else class="text-muted">-</span>
                </td>
                <td>
                  <span class="code-tiny">{{ asset.arn || asset.resource_id || '-' }}</span>
                </td>
              </tr>
            </tbody>
          </table>

          <div v-if="totalPages > 1" class="pagination">
            <button
              @click="currentPage--"
              :disabled="currentPage === 1"
              class="btn-pagination"
            >
              Previous
            </button>
            <span class="pagination-info">
              Page {{ currentPage }} of {{ totalPages }} ({{ filteredAssets.length }} assets)
            </span>
            <button
              @click="currentPage++"
              :disabled="currentPage === totalPages"
              class="btn-pagination"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'Assets',
  data() {
    return {
      assets: [],
      loading: true,
      searchQuery: '',
      filterType: '',
      filterProvider: '',
      filterRegion: '',
      filterPublicAccess: '',
      filterEncryption: '',
      currentPage: 1,
      itemsPerPage: 25
    }
  },
  computed: {
    filteredAssets() {
      let filtered = this.assets

      if (this.searchQuery) {
        const query = this.searchQuery.toLowerCase()
        filtered = filtered.filter(a =>
          a.sk.toLowerCase().includes(query) ||
          (a.service && a.service.toLowerCase().includes(query)) ||
          (a.arn && a.arn.toLowerCase().includes(query)) ||
          (a.resource_id && a.resource_id.toLowerCase().includes(query)) ||
          (a.dns_name && a.dns_name.toLowerCase().includes(query)) ||
          (a.vpc_id && a.vpc_id.toLowerCase().includes(query))
        )
      }

      if (this.filterType) {
        filtered = filtered.filter(a => a.asset_type === this.filterType)
      }

      if (this.filterProvider) {
        filtered = filtered.filter(a => a.provider === this.filterProvider)
      }

      if (this.filterRegion) {
        filtered = filtered.filter(a => a.region === this.filterRegion)
      }

      if (this.filterPublicAccess !== '') {
        const want = this.filterPublicAccess === 'true'
        filtered = filtered.filter(a => a.public_access === want)
      }

      if (this.filterEncryption !== '') {
        const want = this.filterEncryption === 'true'
        filtered = filtered.filter(a => a.encryption_enabled === want)
      }

      return filtered
    },
    availableRegions() {
      const regions = this.assets.map(a => a.region).filter(r => r && r.trim() !== '')
      return [...new Set(regions)].sort()
    },
    paginatedAssets() {
      const start = (this.currentPage - 1) * this.itemsPerPage
      return this.filteredAssets.slice(start, start + this.itemsPerPage)
    },
    totalPages() {
      return Math.ceil(this.filteredAssets.length / this.itemsPerPage)
    },
    publicCount() {
      return this.filteredAssets.filter(a => a.public_access === true).length
    },
    unencryptedCount() {
      return this.filteredAssets.filter(a => a.encryption_enabled === false).length
    }
  },
  watch: {
    filterType() { this.currentPage = 1 },
    filterProvider() { this.currentPage = 1 },
    filterRegion() { this.currentPage = 1 },
    filterPublicAccess() { this.currentPage = 1 },
    filterEncryption() { this.currentPage = 1 },
    searchQuery() { this.currentPage = 1 }
  },
  mounted() {
    this.loadAssets()
    this.interval = setInterval(() => this.loadAssets(), 15000)
  },
  beforeUnmount() {
    if (this.interval) clearInterval(this.interval)
  },
  methods: {
    async loadAssets() {
      try {
        const res = await axios.get('/api/assets?limit=2000')
        this.assets = res.data
        this.loading = false
      } catch (err) {
        console.error('Failed to load assets:', err)
        this.loading = false
      }
    },
    formatType(type) {
      return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
    },
    navigateToDetail(assetId) {
      this.$router.push(`/assets/${assetId}`)
    }
  }
}
</script>

<style scoped>
.summary-bar {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 0.75rem 1rem;
  background: #1a1f2e;
  border: 1px solid #2d3548;
  border-radius: 8px;
  margin-bottom: 1rem;
  font-size: 0.875rem;
}

.summary-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  color: #94a3b8;
}

.summary-item strong {
  color: #e2e8f0;
}

.summary-item.warning {
  color: #f59e0b;
}

.summary-item.warning strong {
  color: #f59e0b;
}

.summary-item.danger {
  color: #ef4444;
}

.summary-item.danger strong {
  color: #ef4444;
}

.asset-name {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.asset-name small {
  font-size: 0.7rem;
  color: #64748b;
}

.code-tiny {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 0.65rem;
  color: #64748b;
  word-break: break-all;
  max-width: 220px;
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.clickable-row {
  cursor: pointer;
  transition: background-color 0.2s;
}

.clickable-row:hover {
  background-color: #1a1f2e !important;
}

.clickable-row:hover td {
  color: #e2e8f0;
}
</style>

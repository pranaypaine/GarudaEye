<template>
  <div class="dashboard-view">
    <div class="page-header">
      <div>
        <h2>Dashboard Overview</h2>
        <p>Real-time cloud asset security monitoring</p>
      </div>
      <button @click="refreshData" class="btn-secondary">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
        </svg>
        Refresh
      </button>
    </div>

    <div v-if="error" class="alert alert-error">{{ error }}</div>

    <!-- Top Stats -->
    <div class="stats-grid">
      <div class="stat-card gradient-purple">
        <div class="stat-icon">📊</div>
        <div class="stat-content">
          <h3>Total Assets</h3>
          <div class="stat-value">{{ dashboard.total_assets || 0 }}</div>
          <p class="stat-label">Discovered resources</p>
        </div>
      </div>
      <div class="stat-card gradient-blue">
        <div class="stat-icon">🔗</div>
        <div class="stat-content">
          <h3>Relationships</h3>
          <div class="stat-value">{{ dashboard.total_relationships || 0 }}</div>
          <p class="stat-label">Asset connections</p>
        </div>
      </div>
      <div class="stat-card gradient-orange">
        <div class="stat-icon">🌐</div>
        <div class="stat-content">
          <h3>Public Assets</h3>
          <div class="stat-value">{{ dashboard.public_assets || 0 }}</div>
          <p class="stat-label">Internet-exposed resources</p>
        </div>
      </div>
      <div class="stat-card gradient-red">
        <div class="stat-icon">🔓</div>
        <div class="stat-content">
          <h3>Unencrypted</h3>
          <div class="stat-value">{{ dashboard.unencrypted_assets || 0 }}</div>
          <p class="stat-label">Resources without encryption</p>
        </div>
      </div>
    </div>

    <div class="content-grid">
      <!-- Recent Assets -->
      <div class="card">
        <div class="card-header">
          <h3>Recent Assets</h3>
          <router-link to="/assets" class="link-button">View All →</router-link>
        </div>
        <div class="card-body">
          <div v-if="loading" class="loading">
            <div class="spinner"></div>
            Loading assets...
          </div>
          <div v-else-if="assets.length === 0" class="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
              <path d="M3 3h18v18H3z"></path>
              <path d="M3 9h18"></path>
              <path d="M9 21V9"></path>
            </svg>
            <p>No assets collected yet</p>
            <small>Click "Start Scan" to begin asset discovery</small>
          </div>
          <div v-else class="table-container">
            <table class="modern-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Provider</th>
                  <th>Region</th>
                  <th>Public</th>
                  <th>Encrypted</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="asset in assets.slice(0, 10)"
                  :key="asset.id"
                  @click="$router.push(`/assets/${asset.id}`)"
                  class="clickable-row"
                >
                  <td><span :class="['badge', `badge-${asset.asset_type.replace(/_/g, '')}`]">{{ formatType(asset.asset_type) }}</span></td>
                  <td><strong>{{ asset.sk }}</strong></td>
                  <td><span :class="['badge', `badge-${asset.provider}`]">{{ asset.provider.toUpperCase() }}</span></td>
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
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Sidebar: Asset Inventory + Security -->
      <div class="sidebar">
        <div class="card">
          <div class="card-header">
            <h3>Asset Inventory</h3>
          </div>
          <div class="card-body">
            <div v-for="item in assetInventory" :key="item.label" class="quick-stat">
              <div class="stat-label-row">
                <span class="quick-stat-icon">{{ item.icon }}</span>
                <span class="quick-stat-label">{{ item.label }}</span>
              </div>
              <span class="quick-stat-value">{{ item.value }}</span>
            </div>
          </div>
        </div>

        <div class="card" v-if="topPublicTypes.length > 0">
          <div class="card-header">
            <h3>Public Exposure by Type</h3>
          </div>
          <div class="card-body">
            <div v-for="item in topPublicTypes" :key="item.type" class="quick-stat">
              <span class="quick-stat-label">{{ formatType(item.type) }}</span>
              <span class="badge badge-warning">{{ item.count }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'Dashboard',
  data() {
    return {
      dashboard: {},
      assets: [],
      loading: true,
      error: null
    }
  },
  computed: {
    assetInventory() {
      const d = this.dashboard
      return [
        { label: 'S3 Buckets',       icon: '🪣', value: d.s3_buckets || 0 },
        { label: 'EC2 / IPs',        icon: '🖥️', value: d.ip_addresses || 0 },
        { label: 'Databases (RDS)',  icon: '🗄️', value: d.databases || 0 },
        { label: 'Lambda Functions', icon: 'λ',  value: d.lambdas || 0 },
        { label: 'Load Balancers',   icon: '⚖️', value: d.load_balancers || 0 },
        { label: 'API Gateways',     icon: '🔌', value: d.api_gateways || 0 },
        { label: 'CloudFront CDNs',  icon: '🌍', value: d.cdns || 0 },
        { label: 'ElastiCache',      icon: '⚡', value: d.caches || 0 },
        { label: 'SQS Queues',       icon: '📨', value: d.queues || 0 },
        { label: 'SNS Topics',       icon: '📣', value: d.topics || 0 },
        { label: 'DynamoDB Tables',  icon: '📋', value: d.tables || 0 },
        { label: 'ECS Services',     icon: '📦', value: d.containers || 0 },
        { label: 'EKS Clusters',     icon: '☸️', value: d.clusters || 0 },
        { label: 'VPCs',             icon: '🏠', value: d.vpcs || 0 },
        { label: 'Subnets',          icon: '🔲', value: d.subnets || 0 },
        { label: 'Security Groups',  icon: '🛡️', value: d.security_groups || 0 },
        { label: 'Domains',          icon: '🌐', value: d.domains || 0 },
      ]
    },
    topPublicTypes() {
      const counts = {}
      this.assets.forEach(a => {
        if (a.public_access === true) {
          counts[a.asset_type] = (counts[a.asset_type] || 0) + 1
        }
      })
      return Object.entries(counts)
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6)
    }
  },
  mounted() {
    this.loadData()
    this.interval = setInterval(() => this.loadData(), 10000)
  },
  beforeUnmount() {
    if (this.interval) clearInterval(this.interval)
  },
  methods: {
    async loadData() {
      try {
        this.error = null
        const [dashboardRes, assetsRes] = await Promise.all([
          axios.get('/api/dashboard/dashboard'),
          axios.get('/api/assets?limit=100')
        ])
        this.dashboard = dashboardRes.data
        this.assets = assetsRes.data
        this.loading = false
      } catch (err) {
        this.error = `Failed to load data: ${err.message}`
        this.loading = false
      }
    },
    async refreshData() {
      this.loading = true
      await this.loadData()
    },
    formatType(type) {
      return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
    }
  }
}
</script>

<style scoped>
.clickable-row {
  cursor: pointer;
  transition: background-color 0.2s;
}
.clickable-row:hover {
  background-color: #1a1f2e !important;
}
.stat-label-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.quick-stat-icon {
  font-size: 1rem;
  width: 1.5rem;
  text-align: center;
}
.gradient-red {
  background: linear-gradient(135deg, #7f1d1d 0%, #ef4444 100%);
}
.badge-warning { background: #d97706; color: white; }
.badge-danger  { background: #dc2626; color: white; }
.badge-success { background: #16a34a; color: white; }
</style>

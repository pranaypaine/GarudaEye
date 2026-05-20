<template>
  <div class="attack-surface-view">
    <div class="page-header">
      <div>
        <h2>Attack Surface Analysis</h2>
        <p>Identify exposed services and potential security risks</p>
      </div>
    </div>

    <div v-if="loading" class="loading-container">
      <div class="spinner"></div>
      <p>Analyzing attack surface...</p>
    </div>

    <div v-else>
      <!-- Top Stats 3x3 -->
      <div class="stats-grid as-grid-3">
        <!-- Row 1 -->
        <div class="stat-card gradient-red">
          <div class="stat-icon">🌐</div>
          <div class="stat-content">
            <h3>Publicly Exposed</h3>
            <div class="stat-value">{{ publicAssets.length }}</div>
            <p class="stat-label">Internet-accessible resources</p>
          </div>
        </div>
        <div class="stat-card gradient-orange">
          <div class="stat-icon">🔓</div>
          <div class="stat-content">
            <h3>Unencrypted</h3>
            <div class="stat-value">{{ unencryptedAssets.length }}</div>
            <p class="stat-label">Resources without encryption</p>
          </div>
        </div>
        <div class="stat-card gradient-yellow">
          <div class="stat-icon">🛡️</div>
          <div class="stat-content">
            <h3>Open-to-World SGs</h3>
            <div class="stat-value">{{ openWorldSGs.length }}</div>
            <p class="stat-label">Security groups with 0.0.0.0/0</p>
          </div>
        </div>
        <!-- Row 2 -->
        <div class="stat-card gradient-blue">
          <div class="stat-icon">⚠️</div>
          <div class="stat-content">
            <h3>Vulnerabilities</h3>
            <div class="stat-value">{{ totalVulnerabilities }}</div>
            <p class="stat-label">Known CVEs detected</p>
          </div>
        </div>
        <div class="stat-card gradient-red">
          <div class="stat-icon">🔴</div>
          <div class="stat-content">
            <h3>Critical Risk</h3>
            <div class="stat-value">{{ criticalRiskAssets.length }}</div>
            <p class="stat-label">Risk score ≥ 70</p>
          </div>
        </div>
        <div class="stat-card gradient-orange">
          <div class="stat-icon">🟠</div>
          <div class="stat-content">
            <h3>High Risk</h3>
            <div class="stat-value">{{ highRiskAssets.length }}</div>
            <p class="stat-label">Risk score 40–69</p>
          </div>
        </div>
        <!-- Row 3 -->
        <div class="stat-card gradient-yellow">
          <div class="stat-icon">🟡</div>
          <div class="stat-content">
            <h3>Medium Risk</h3>
            <div class="stat-value">{{ mediumRiskAssets.length }}</div>
            <p class="stat-label">Risk score 10–39</p>
          </div>
        </div>
        <div class="stat-card gradient-yellow">
          <div class="stat-icon">🚨</div>
          <div class="stat-content">
            <h3>Attack Paths</h3>
            <div class="stat-value">{{ attackPaths.length }}</div>
            <p class="stat-label">Calculated attack vectors</p>
          </div>
        </div>
        <div class="stat-card gradient-blue">
          <div class="stat-icon">📦</div>
          <div class="stat-content">
            <h3>Total Assets</h3>
            <div class="stat-value">{{ assets.length }}</div>
            <p class="stat-label">All tracked resources</p>
          </div>
        </div>
      </div>

      <!-- Attack Paths Section (new) -->
      <div class="card" v-if="attackPaths.length > 0" style="margin-bottom: 1.5rem;">
        <div class="card-header">
          <h3>Attack Paths ({{ attackPaths.length }})</h3>
        </div>
        <div class="card-body">
          <div v-for="path in attackPaths" :key="path.id" :class="['attack-path-item', `severity-${path.severity.toLowerCase()}`]">
            <div class="attack-path-header">
              <span :class="['badge', severityBadge(path.severity)]">{{ path.severity }}</span>
              <span class="attack-path-type">{{ formatPathType(path.path_type) }}</span>
              <span class="attack-path-asset" @click="$router.push(`/assets/${path.entry_asset_id}`)" style="cursor:pointer; color:#3b82f6;">
                {{ path.entry_asset_name }}
              </span>
              <span v-if="path.affected_ports.length" class="attack-path-ports">
                ports: {{ path.affected_ports.slice(0, 5).join(', ') }}{{ path.affected_ports.length > 5 ? '...' : '' }}
              </span>
            </div>
            <p class="attack-path-desc">{{ path.description }}</p>
            <div class="attack-path-evidence" v-if="path.evidence.length">
              <span v-for="(e, i) in path.evidence" :key="i" class="evidence-tag">{{ e }}</span>
            </div>
            <div class="attack-path-remediation">
              <strong>Remediation:</strong> {{ path.remediation }}
            </div>
            <div v-if="path.downstream_assets.length" class="attack-path-downstream">
              <strong>Downstream:</strong>
              <span v-for="ds in path.downstream_assets" :key="ds" class="tag">{{ ds }}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="card" v-else-if="!loadingPaths" style="margin-bottom: 1.5rem;">
        <div class="card-header"><h3>Attack Paths</h3></div>
        <div class="card-body">
          <p class="empty-state-small">✅ No attack paths detected based on current data</p>
        </div>
      </div>

      <div class="content-grid">
        <!-- Left column -->
        <div class="main-column">
          <!-- Publicly Accessible Resources -->
          <div class="card">
            <div class="card-header">
              <h3>Publicly Accessible Resources</h3>
              <router-link to="/assets?public_access=true" class="link-button">View All →</router-link>
            </div>
            <div class="card-body">
              <div v-if="publicAssets.length === 0" class="empty-state-small">
                <p>✅ No publicly accessible cloud resources detected</p>
              </div>
              <div v-else class="table-container">
                <table class="modern-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Region</th>
                      <th>Service</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="asset in publicAssets.slice(0, 15)"
                      :key="asset.id"
                      @click="$router.push(`/assets/${asset.id}`)"
                      class="clickable-row"
                    >
                      <td><span :class="['badge', `badge-${asset.asset_type.replace(/_/g, '')}`]">{{ formatType(asset.asset_type) }}</span></td>
                      <td><strong>{{ asset.sk }}</strong></td>
                      <td>{{ asset.region || '-' }}</td>
                      <td>{{ asset.service || '-' }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="publicAssets.length > 15" class="table-footer">
                  And {{ publicAssets.length - 15 }} more...
                  <router-link to="/assets">View All in Assets</router-link>
                </p>
              </div>
            </div>
          </div>

          <!-- Unencrypted Resources -->
          <div class="card">
            <div class="card-header">
              <h3>Unencrypted Resources</h3>
            </div>
            <div class="card-body">
              <div v-if="unencryptedAssets.length === 0" class="empty-state-small">
                <p>✅ All resources have encryption enabled</p>
              </div>
              <div v-else class="table-container">
                <table class="modern-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Region</th>
                      <th>Provider</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="asset in unencryptedAssets.slice(0, 15)"
                      :key="asset.id"
                      @click="$router.push(`/assets/${asset.id}`)"
                      class="clickable-row"
                    >
                      <td><span :class="['badge', `badge-${asset.asset_type.replace(/_/g, '')}`]">{{ formatType(asset.asset_type) }}</span></td>
                      <td><strong>{{ asset.sk }}</strong></td>
                      <td>{{ asset.region || '-' }}</td>
                      <td><span :class="['badge', `badge-${asset.provider}`]">{{ asset.provider.toUpperCase() }}</span></td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="unencryptedAssets.length > 15" class="table-footer">
                  And {{ unencryptedAssets.length - 15 }} more...
                </p>
              </div>
            </div>
          </div>

          <!-- Security Groups Open to World -->
          <div class="card">
            <div class="card-header">
              <h3>Security Groups Open to World (0.0.0.0/0)</h3>
            </div>
            <div class="card-body">
              <div v-if="openWorldSGs.length === 0" class="empty-state-small">
                <p>✅ No security groups open to the world</p>
              </div>
              <div v-else class="sg-list">
                <div v-for="sg in openWorldSGs.slice(0, 10)" :key="sg.id" class="sg-item" @click="$router.push(`/assets/${sg.id}`)">
                  <div class="sg-header">
                    <span class="badge badge-danger">OPEN TO WORLD</span>
                    <strong>{{ sg.sk }}</strong>
                    <span class="text-muted">{{ sg.region }}</span>
                  </div>
                  <div class="sg-rules" v-if="sg.configuration && sg.configuration.ingress_rules">
                    <span
                      v-for="(rule, i) in getOpenRules(sg.configuration.ingress_rules)"
                      :key="i"
                      class="rule-tag"
                    >
                      {{ rule.protocol === '-1' ? 'All Traffic' : rule.protocol }}:{{ formatPortRange(rule) }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Right sidebar -->
        <div class="sidebar">
          <!-- Risk breakdown by asset type -->
          <div class="card">
            <div class="card-header">
              <h3>Public Exposure Breakdown</h3>
            </div>
            <div class="card-body">
              <div v-if="publicByType.length === 0" class="empty-state-small">
                <p>No public resources</p>
              </div>
              <div v-else>
                <div v-for="item in publicByType" :key="item.type" class="breakdown-row">
                  <span class="breakdown-label">{{ formatType(item.type) }}</span>
                  <div class="breakdown-bar-wrap">
                    <div class="breakdown-bar" :style="{ width: item.pct + '%' }"></div>
                  </div>
                  <span class="breakdown-count">{{ item.count }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Unencrypted breakdown -->
          <div class="card">
            <div class="card-header">
              <h3>Unencrypted Breakdown</h3>
            </div>
            <div class="card-body">
              <div v-if="unencryptedByType.length === 0" class="empty-state-small">
                <p>No unencrypted resources</p>
              </div>
              <div v-else>
                <div v-for="item in unencryptedByType" :key="item.type" class="breakdown-row">
                  <span class="breakdown-label">{{ formatType(item.type) }}</span>
                  <div class="breakdown-bar-wrap">
                    <div class="breakdown-bar breakdown-bar-danger" :style="{ width: item.pct + '%' }"></div>
                  </div>
                  <span class="breakdown-count">{{ item.count }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Known vulnerabilities -->
          <div class="card" v-if="commonVulns.length > 0">
            <div class="card-header">
              <h3>Common Vulnerabilities</h3>
            </div>
            <div class="card-body">
              <div v-for="vuln in commonVulns" :key="vuln.cve" class="vuln-item">
                <strong>{{ vuln.cve }}</strong>
                <span class="vuln-count">{{ vuln.count }} assets</span>
              </div>
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
  name: 'AttackSurface',
  data() {
    return {
      assets: [],
      attackPaths: [],
      loading: true,
      loadingPaths: true,
      interval: null,
    }
  },
  computed: {
    publicAssets() {
      return this.assets.filter(a => a.public_access === true)
    },
    unencryptedAssets() {
      return this.assets.filter(a => a.encryption_enabled === false)
    },
    openWorldSGs() {
      return this.assets.filter(a => {
        if (a.asset_type !== 'security_group' || !a.configuration) return false
        const rules = a.configuration.ingress_rules || []
        return rules.some(r => this.isOpenToWorld(r))
      })
    },
    totalVulnerabilities() {
      return this.assets.reduce((sum, a) => sum + (a.vulnerabilities?.length || 0), 0)
    },
    criticalRiskAssets() {
      return this.assets.filter(a => (a.risk_score || 0) >= 70)
    },
    highRiskAssets() {
      return this.assets.filter(a => {
        const s = a.risk_score || 0
        return s >= 40 && s < 70
      })
    },
    mediumRiskAssets() {
      return this.assets.filter(a => {
        const s = a.risk_score || 0
        return s >= 10 && s < 40
      })
    },
    publicByType() {
      const counts = {}
      const max = Math.max(...Object.values(
        this.publicAssets.reduce((acc, a) => {
          acc[a.asset_type] = (acc[a.asset_type] || 0) + 1
          return acc
        }, {})
      ), 1)
      this.publicAssets.forEach(a => {
        counts[a.asset_type] = (counts[a.asset_type] || 0) + 1
      })
      return Object.entries(counts)
        .map(([type, count]) => ({ type, count, pct: Math.round((count / max) * 100) }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
    },
    unencryptedByType() {
      const counts = {}
      this.unencryptedAssets.forEach(a => {
        counts[a.asset_type] = (counts[a.asset_type] || 0) + 1
      })
      const max = Math.max(...Object.values(counts), 1)
      return Object.entries(counts)
        .map(([type, count]) => ({ type, count, pct: Math.round((count / max) * 100) }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
    },
    commonVulns() {
      const vulnCounts = {}
      this.assets.forEach(a => {
        if (a.vulnerabilities) {
          a.vulnerabilities.forEach(v => {
            vulnCounts[v] = (vulnCounts[v] || 0) + 1
          })
        }
      })
      return Object.entries(vulnCounts)
        .map(([cve, count]) => ({ cve, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
    }
  },
  mounted() {
    this.loadData()
    this.interval = setInterval(() => this.loadData(), 15000)
  },
  beforeUnmount() {
    if (this.interval) clearInterval(this.interval)
  },
  methods: {
    async loadData() {
      try {
        const [assetsRes, pathsRes] = await Promise.all([
          axios.get('/api/assets?limit=2000'),
          axios.get('/api/attack-paths'),
        ])
        this.assets = assetsRes.data
        this.attackPaths = pathsRes.data
        this.loading = false
        this.loadingPaths = false
      } catch (err) {
        console.error('Failed to load attack surface data:', err)
        this.loading = false
        this.loadingPaths = false
      }
    },
    formatType(type) {
      return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
    },
    formatPathType(type) {
      return type.replace(/([A-Z])/g, ' $1').trim()
    },
    severityBadge(sev) {
      return { Critical: 'badge-danger', High: 'badge-warning', Medium: 'badge-info', Low: 'badge-muted' }[sev] || 'badge-muted'
    },
    isOpenToWorld(rule) {
      const cidrs = rule.ip_ranges?.map(r => r.cidr_ip) || []
      const cidrsv6 = rule.ipv6_ranges?.map(r => r.cidr_ipv6) || []
      return cidrs.includes('0.0.0.0/0') || cidrsv6.includes('::/0')
    },
    getOpenRules(rules) {
      return (rules || []).filter(r => this.isOpenToWorld(r))
    },
    formatPortRange(rule) {
      if (rule.protocol === '-1') return 'All'
      if (rule.from_port === rule.to_port) return `${rule.from_port}`
      return `${rule.from_port}-${rule.to_port}`
    }
  }
}
</script>

<style scoped>
.main-column { display: flex; flex-direction: column; gap: 1.5rem; }

.clickable-row { cursor: pointer; transition: background-color 0.2s; }
.clickable-row:hover { background-color: #1a1f2e !important; }

.table-footer { margin-top: 0.75rem; font-size: 0.8rem; color: #94a3b8; }
.table-footer a { color: #3b82f6; text-decoration: none; }

.sg-list { display: flex; flex-direction: column; gap: 0.75rem; }
.sg-item { padding: 0.75rem 1rem; background: #0f1419; border-radius: 6px; border: 1px solid #ef444430; cursor: pointer; transition: all 0.2s; }
.sg-item:hover { border-color: #ef4444; background: #1a1f2e; }
.sg-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
.sg-rules { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.rule-tag { background: #7f1d1d; color: #fca5a5; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-family: monospace; }

.breakdown-row { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
.breakdown-label { width: 100px; font-size: 0.8rem; color: #94a3b8; flex-shrink: 0; }
.breakdown-bar-wrap { flex: 1; background: #1a1f2e; border-radius: 4px; height: 8px; overflow: hidden; }
.breakdown-bar { height: 100%; background: #f59e0b; border-radius: 4px; transition: width 0.5s; }
.breakdown-bar-danger { background: #ef4444; }
.breakdown-count { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; min-width: 24px; text-align: right; }

.vuln-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; border-bottom: 1px solid #1a1f2e; font-size: 0.8rem; }
.vuln-item strong { color: #e2e8f0; }
.vuln-count { background: #7f1d1d; color: #fca5a5; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; }

.gradient-yellow { background: linear-gradient(135deg, #78350f 0%, #f59e0b 100%); }

.attack-path-item { padding: 1rem 1.25rem; border-radius: 8px; border: 1px solid #2d3548; margin-bottom: 0.75rem; background: #0f1419; }
.attack-path-item.severity-critical { border-color: #ef444470; }
.attack-path-item.severity-high { border-color: #f59e0b70; }
.attack-path-item.severity-medium { border-color: #3b82f670; }
.attack-path-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
.attack-path-type { font-size: 0.8rem; color: #94a3b8; font-weight: 600; }
.attack-path-asset { font-size: 0.9rem; font-weight: 600; }
.attack-path-ports { font-size: 0.75rem; color: #94a3b8; font-family: monospace; }
.attack-path-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0 0 0.5rem; }
.attack-path-evidence { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.5rem; }
.evidence-tag { background: #1a1f2e; color: #94a3b8; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.72rem; }
.attack-path-remediation { font-size: 0.78rem; color: #94a3b8; margin-top: 0.4rem; }
.attack-path-downstream { font-size: 0.78rem; color: #94a3b8; margin-top: 0.4rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.as-grid-3 { grid-template-columns: repeat(3, 1fr) !important; }
.badge-info { background: #0ea5e9; color: white; }
.badge-muted { background: #374151; color: #9ca3af; }
</style>

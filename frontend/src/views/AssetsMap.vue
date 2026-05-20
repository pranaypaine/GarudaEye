<template>
  <div class="assets-map-view">
    <div class="page-header">
      <div>
        <h2>Assets Relationship Map</h2>
        <p>Visualize connections between your cloud assets</p>
      </div>
      <div class="page-actions">
        <label class="toggle-labels">
          <input type="checkbox" v-model="showEdgeLabels" />
          Show edge labels
        </label>
        <button @click="resetLayout" class="btn btn-secondary" title="Re-run layout">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg>
          Reset Layout
        </button>
        <button @click="loadGraph" class="btn btn-primary" :disabled="loading">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Refresh
        </button>
      </div>
    </div>

    <div class="card graph-card">
      <div class="card-body p0">

        <!-- Filter bar -->
        <div class="filter-bar">
          <div class="filter-group">
            <label>Asset Type</label>
            <select v-model="filterType">
              <option value="">All Types</option>
              <option v-for="t in assetTypes" :key="t" :value="t">{{ formatType(t) }}</option>
            </select>
          </div>
          <div class="filter-group">
            <label>Provider</label>
            <select v-model="filterProvider">
              <option value="">All Providers</option>
              <option v-for="p in providers" :key="p" :value="p">{{ p.toUpperCase() }}</option>
            </select>
          </div>
          <div class="filter-group">
            <label>Relationship Type</label>
            <select v-model="filterRelType">
              <option value="">All Relationships</option>
              <option v-for="r in relationshipTypes" :key="r" :value="r">{{ formatType(r) }}</option>
            </select>
          </div>
          <div class="filter-group">
            <label>Visibility</label>
            <select v-model="filterPublic">
              <option value="">All</option>
              <option value="public">Public only</option>
              <option value="private">Private only</option>
            </select>
          </div>
          <div class="filter-stats">
            <span>{{ visibleNodes.length }} nodes</span>
            <span class="sep">·</span>
            <span>{{ visibleEdges.length }} edges</span>
          </div>
        </div>

        <div v-if="loading" class="loading">
          <div class="spinner"></div>
          Loading asset relationships…
        </div>
        <div v-else-if="nodes.length === 0" class="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/>
            <line x1="12" y1="9" x2="17.5" y2="6.5"/><line x1="12" y1="15" x2="6.5" y2="17.5"/>
          </svg>
          <p>No assets with relationships found</p>
          <small>Run a collection scan to discover assets and their connections</small>
        </div>

        <div v-else class="graph-wrap">
          <!-- SVG canvas -->
          <svg
            ref="graphSvg"
            class="graph-svg"
            :viewBox="`0 0 ${graphWidth} ${graphHeight}`"
            preserveAspectRatio="xMidYMid meet"
            @wheel.prevent="onWheel"
            @mousedown="onSvgMousedown"
            @mousemove="onMousemove"
            @mouseup="onMouseup"
            @mouseleave="onMouseup"
          >
            <defs>
              <!-- Arrow markers for each edge colour -->
              <marker v-for="rt in relationshipTypes" :key="'mk-'+rt"
                :id="'arrow-' + rt" markerWidth="8" markerHeight="8"
                refX="18" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" :fill="edgeColor(rt)" />
              </marker>
              <marker id="arrow-default" markerWidth="8" markerHeight="8" refX="18" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
              </marker>
            </defs>

            <g :transform="`translate(${pan.x},${pan.y}) scale(${zoom})`">
              <!-- Edges -->
              <g class="edges">
                <g v-for="edge in visibleEdges" :key="edge.id" class="edge-group">
                  <line
                    :x1="getPos(edge.source).x"
                    :y1="getPos(edge.source).y"
                    :x2="getPos(edge.target).x"
                    :y2="getPos(edge.target).y"
                    :stroke="edgeColor(edge.relationship_type)"
                    :stroke-dasharray="edgeDash(edge.relationship_type)"
                    :marker-end="`url(#arrow-${edge.relationship_type})`"
                    class="edge-line"
                    stroke-width="1.5"
                    opacity="0.7"
                  />
                  <text
                    v-if="showEdgeLabels"
                    :x="(getPos(edge.source).x + getPos(edge.target).x) / 2"
                    :y="(getPos(edge.source).y + getPos(edge.target).y) / 2 - 4"
                    class="edge-label"
                    text-anchor="middle"
                  >{{ formatType(edge.relationship_type) }}</text>
                </g>
              </g>

              <!-- Nodes -->
              <g class="nodes">
                <g
                  v-for="node in visibleNodes"
                  :key="node.id"
                  :transform="`translate(${node.x},${node.y})`"
                  :class="['node', { 'node-selected': selectedNode === node.id }]"
                  @click.stop="selectNode(node)"
                  @mousedown.stop="startDrag(node, $event)"
                  style="cursor:pointer"
                >
                  <!-- Glow ring for public assets -->
                  <circle
                    v-if="node.public_access"
                    :r="nodeRadius(node) + 5"
                    fill="none"
                    stroke="#f59e0b"
                    stroke-width="1.5"
                    opacity="0.5"
                    stroke-dasharray="3,3"
                  />
                  <!-- Selection ring -->
                  <circle
                    v-if="selectedNode === node.id"
                    :r="nodeRadius(node) + 7"
                    fill="none"
                    stroke="#3b82f6"
                    stroke-width="2.5"
                  />
                  <!-- Main circle -->
                  <circle
                    :r="nodeRadius(node)"
                    :fill="nodeColor(node)"
                    :stroke="nodeStroke(node)"
                    stroke-width="2"
                  />
                  <!-- Type icon letter -->
                  <text
                    text-anchor="middle"
                    dominant-baseline="central"
                    :font-size="nodeRadius(node) * 0.75"
                    font-weight="700"
                    fill="#fff"
                    pointer-events="none"
                  >{{ nodeIcon(node.asset_type) }}</text>
                  <!-- Label below -->
                  <text
                    :y="nodeRadius(node) + 13"
                    text-anchor="middle"
                    class="node-label"
                    pointer-events="none"
                  >{{ truncate(node.label, 18) }}</text>
                  <text
                    :y="nodeRadius(node) + 25"
                    text-anchor="middle"
                    class="node-type-label"
                    pointer-events="none"
                  >{{ formatType(node.asset_type) }}</text>
                </g>
              </g>
            </g>
          </svg>

          <!-- Zoom controls -->
          <div class="zoom-controls">
            <button @click="zoom = Math.min(3, zoom + 0.15)" title="Zoom in">+</button>
            <span>{{ Math.round(zoom * 100) }}%</span>
            <button @click="zoom = Math.max(0.2, zoom - 0.15)" title="Zoom out">−</button>
            <button @click="resetView" title="Fit to screen">⊡</button>
          </div>

          <!-- Color legend -->
          <div class="legend">
            <div class="legend-section">
              <div class="legend-title">Asset Types</div>
              <div class="legend-grid">
                <div v-for="[type, color] in nodeColorMap" :key="type" class="legend-node-item">
                  <svg width="14" height="14"><circle cx="7" cy="7" r="7" :fill="color"/></svg>
                  <span>{{ formatType(type) }}</span>
                </div>
              </div>
            </div>
            <div class="legend-section">
              <div class="legend-title">Relationships</div>
              <div class="legend-rel-list">
                <div v-for="rt in relationshipTypes" :key="'leg-'+rt" class="legend-rel-item">
                  <svg width="28" height="10">
                    <line x1="0" y1="5" x2="28" y2="5"
                      :stroke="edgeColor(rt)"
                      :stroke-dasharray="edgeDash(rt)"
                      stroke-width="2"/>
                  </svg>
                  <span>{{ formatType(rt) }}</span>
                </div>
              </div>
            </div>
            <div class="legend-section">
              <div class="legend-title">Indicators</div>
              <div class="legend-indicator">
                <svg width="22" height="22"><circle cx="11" cy="11" r="9" fill="none" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="3,3"/></svg>
                <span>Public access</span>
              </div>
              <div class="legend-indicator">
                <svg width="22" height="22"><circle cx="11" cy="11" r="9" fill="none" stroke="#3b82f6" stroke-width="2.5"/></svg>
                <span>Selected</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Asset Details Sidebar -->
    <transition name="slide">
      <div v-if="selectedNode" class="asset-details-panel">
        <div class="panel-header">
          <div class="panel-header-left">
            <span class="panel-type-dot" :style="`background:${nodeColor(selectedAsset)}`"></span>
            <h3>{{ truncate(selectedAsset.label, 28) }}</h3>
          </div>
          <button @click="selectedNode = null" class="close-btn">×</button>
        </div>
        <div class="panel-body">
          <div class="detail-row">
            <span class="detail-key">Type</span>
            <span class="badge">{{ formatType(selectedAsset.asset_type) }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Provider</span>
            <span :class="['badge', 'badge-' + selectedAsset.provider]">{{ selectedAsset.provider.toUpperCase() }}</span>
          </div>
          <div v-if="selectedAsset.region" class="detail-row">
            <span class="detail-key">Region</span>
            <span class="detail-val">{{ selectedAsset.region }}</span>
          </div>
          <div v-if="selectedAsset.service" class="detail-row">
            <span class="detail-key">Service</span>
            <span class="detail-val">{{ selectedAsset.service }}</span>
          </div>
          <div v-if="selectedAsset.vpc_id" class="detail-row">
            <span class="detail-key">VPC</span>
            <span class="detail-val code">{{ selectedAsset.vpc_id }}</span>
          </div>
          <div v-if="selectedAsset.subnet_id" class="detail-row">
            <span class="detail-key">Subnet</span>
            <span class="detail-val code">{{ selectedAsset.subnet_id }}</span>
          </div>
          <div v-if="selectedAsset.public_access !== null && selectedAsset.public_access !== undefined" class="detail-row">
            <span class="detail-key">Public Access</span>
            <span :class="['badge', selectedAsset.public_access ? 'badge-warning' : 'badge-success']">
              {{ selectedAsset.public_access ? 'Yes' : 'No' }}
            </span>
          </div>
          <div v-if="selectedAsset.encryption_enabled !== null && selectedAsset.encryption_enabled !== undefined" class="detail-row">
            <span class="detail-key">Encryption</span>
            <span :class="['badge', selectedAsset.encryption_enabled ? 'badge-success' : 'badge-danger']">
              {{ selectedAsset.encryption_enabled ? 'Enabled' : 'Disabled' }}
            </span>
          </div>

          <div class="connections-section">
            <h4>Connections <span class="conn-count">{{ nodeConnections(selectedNode).length }}</span></h4>
            <div v-if="nodeConnections(selectedNode).length === 0" class="no-connections">No connections</div>
            <div v-for="conn in nodeConnections(selectedNode)" :key="conn.id" class="connection-item">
              <span class="conn-rel" :style="`color:${edgeColor(conn.relationship_type)}`">{{ formatType(conn.relationship_type) }}</span>
              <span class="conn-arrow">→</span>
              <span class="conn-target">{{ truncate(conn.targetLabel, 22) }}</span>
            </div>
          </div>
        </div>
      </div>
    </transition>

    <!-- Bottom stats strip -->
    <div class="stats-strip">
      <div class="stat-card" v-for="s in assetTypeCounts.slice(0, 8)" :key="s.name">
        <span class="stat-dot" :style="`background:${nodeColorByType(s.name)}`"></span>
        <span class="stat-label">{{ formatType(s.name) }}</span>
        <span class="stat-val">{{ s.count }}</span>
      </div>
      <div class="stat-card stat-card-total">
        <span class="stat-label">Relationships</span>
        <span class="stat-val">{{ edges.length }}</span>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const NODE_COLORS = {
  ip_address:     '#ef4444',
  load_balancer:  '#f97316',
  domain:         '#eab308',
  cdn:            '#a3e635',
  api_gateway:    '#22d3ee',
  lambda:         '#a78bfa',
  database:       '#60a5fa',
  cache:          '#34d399',
  s3_bucket:      '#fb923c',
  cluster:        '#818cf8',
  container:      '#c084fc',
  queue:          '#4ade80',
  topic:          '#2dd4bf',
  table:          '#38bdf8',
  vpc:            '#64748b',
  subnet:         '#475569',
  security_group: '#94a3b8',
}
const DEFAULT_NODE_COLOR = '#6b7280'

const EDGE_COLORS = {
  uses:           '#3b82f6',
  member_of:      '#8b5cf6',
  attached_to:    '#10b981',
  routes_to:      '#f59e0b',
  triggers:       '#ef4444',
  connected_to:   '#06b6d4',
  depends_on:     '#6366f1',
  backed_by:      '#ec4899',
  authorized_by:  '#14b8a6',
  monitored_by:   '#a855f7',
  encrypted_by:   '#22c55e',
}
const DEFAULT_EDGE_COLOR = '#475569'

const EDGE_DASH = {
  uses: '',
  member_of: '6,3',
  attached_to: '10,4',
  routes_to: '4,4',
  triggers: '8,3',
  connected_to: '',
  depends_on: '14,4',
  backed_by: '3,3',
  authorized_by: '10,3,2,3',
  monitored_by: '5,2',
  encrypted_by: '8,2',
}

const ICON = {
  ip_address: 'IP', load_balancer: 'LB', domain: 'DN', cdn: 'CF',
  api_gateway: 'AG', lambda: 'λ', database: 'DB', cache: '⚡',
  s3_bucket: 'S3', cluster: 'CL', container: 'CO', queue: 'SQ',
  topic: 'SN', table: 'DY', vpc: 'VP', subnet: 'SN', security_group: 'SG',
}

export default {
  name: 'AssetsMap',
  data() {
    return {
      nodes: [],
      edges: [],
      loading: true,
      selectedNode: null,
      filterType: '',
      filterProvider: '',
      filterRelType: '',
      filterPublic: '',
      graphWidth: 1400,
      graphHeight: 800,
      showEdgeLabels: false,
      // drag
      draggedNode: null,
      dragOffset: { x: 0, y: 0 },
      // pan
      panning: false,
      panStart: { x: 0, y: 0 },
      pan: { x: 0, y: 0 },
      zoom: 1,
      autoRefreshInterval: null,
    }
  },
  computed: {
    nodeColorMap() {
      const types = [...new Set(this.nodes.map(n => n.asset_type))].sort()
      return types.map(t => [t, NODE_COLORS[t] || DEFAULT_NODE_COLOR])
    },
    visibleNodes() {
      return this.nodes.filter(n => {
        if (this.filterType && n.asset_type !== this.filterType) return false
        if (this.filterProvider && n.provider !== this.filterProvider) return false
        if (this.filterPublic === 'public' && !n.public_access) return false
        if (this.filterPublic === 'private' && n.public_access) return false
        // If filtering by rel type, only show nodes that have at least one matching edge
        if (this.filterRelType) {
          const has = this.edges.some(e =>
            e.relationship_type === this.filterRelType &&
            (e.source === n.id || e.target === n.id)
          )
          if (!has) return false
        }
        return true
      })
    },
    visibleEdges() {
      const ids = new Set(this.visibleNodes.map(n => n.id))
      return this.edges.filter(e => {
        if (!ids.has(e.source) || !ids.has(e.target)) return false
        if (this.filterRelType && e.relationship_type !== this.filterRelType) return false
        return true
      })
    },
    assetTypes() {
      return [...new Set(this.nodes.map(n => n.asset_type))].sort()
    },
    providers() {
      return [...new Set(this.nodes.map(n => n.provider))].sort()
    },
    relationshipTypes() {
      return [...new Set(this.edges.map(e => e.relationship_type))].sort()
    },
    assetTypeCounts() {
      const c = {}
      this.nodes.forEach(n => { c[n.asset_type] = (c[n.asset_type] || 0) + 1 })
      return Object.entries(c).map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
    },
    selectedAsset() {
      return this.nodes.find(n => n.id === this.selectedNode)
    },
  },
  mounted() {
    this.loadGraph()
    this.autoRefreshInterval = setInterval(this.loadGraph, 30000)
    document.addEventListener('mousemove', this.onMousemove)
    document.addEventListener('mouseup', this.onMouseup)
  },
  beforeUnmount() {
    clearInterval(this.autoRefreshInterval)
    document.removeEventListener('mousemove', this.onMousemove)
    document.removeEventListener('mouseup', this.onMouseup)
  },
  methods: {
    // ── Data ─────────────────────────────────────────────────────────────────
    async loadGraph() {
      try {
        const res = await axios.get('/api/graph')
        this.nodes = res.data.nodes
        this.edges = res.data.edges
        this.initLayout()
        this.loading = false
      } catch (err) {
        console.error('Failed to load graph:', err)
        this.loading = false
      }
    },
    // ── Layout ────────────────────────────────────────────────────────────────
    initLayout() {
      const cx = this.graphWidth / 2
      const cy = this.graphHeight / 2
      const r  = Math.min(cx, cy) * 0.65

      const groups = {}
      this.nodes.forEach(n => { (groups[n.asset_type] = groups[n.asset_type] || []).push(n) })
      const keys = Object.keys(groups)
      const step = (2 * Math.PI) / keys.length

      keys.forEach((type, ti) => {
        const baseAngle = ti * step
        const groupR = r + (ti % 3) * 90
        groups[type].forEach((node, ni) => {
          const a = baseAngle + (ni / groups[type].length) * step * 0.85
          node.x = cx + groupR * Math.cos(a)
          node.y = cy + groupR * Math.sin(a)
        })
      })

      for (let i = 0; i < 60; i++) this.forceStep()
    },
    resetLayout() {
      this.initLayout()
      this.resetView()
    },
    forceStep() {
      const repulsion = 6000
      const spring = 0.08
      this.nodes.forEach(a => {
        let fx = 0, fy = 0
        this.nodes.forEach(b => {
          if (a.id === b.id) return
          const dx = a.x - b.x, dy = a.y - b.y
          const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
          const f = repulsion / (d * d)
          fx += (dx / d) * f; fy += (dy / d) * f
        })
        this.edges.forEach(e => {
          let other = null
          if (e.source === a.id) other = this.nodes.find(n => n.id === e.target)
          else if (e.target === a.id) other = this.nodes.find(n => n.id === e.source)
          if (other) { fx += (other.x - a.x) * spring; fy += (other.y - a.y) * spring }
        })
        a.x = Math.max(60, Math.min(this.graphWidth  - 60, a.x + fx * 0.1))
        a.y = Math.max(60, Math.min(this.graphHeight - 60, a.y + fy * 0.1))
      })
    },
    // ── Node helpers ─────────────────────────────────────────────────────────
    nodeRadius(node) {
      const conns = this.edges.filter(e => e.source === node.id || e.target === node.id).length
      return Math.max(16, Math.min(32, 16 + conns * 2))
    },
    nodeColor(node) {
      return NODE_COLORS[node.asset_type] || DEFAULT_NODE_COLOR
    },
    nodeColorByType(type) {
      return NODE_COLORS[type] || DEFAULT_NODE_COLOR
    },
    nodeStroke(node) {
      if (node.encryption_enabled === false) return '#ef4444'
      if (node.public_access) return '#f59e0b'
      return '#1e293b'
    },
    nodeIcon(type) { return ICON[type] || '?' },
    getPos(id) {
      return this.nodes.find(n => n.id === id) || { x: 0, y: 0 }
    },
    // ── Edge helpers ─────────────────────────────────────────────────────────
    edgeColor(type) { return EDGE_COLORS[type] || DEFAULT_EDGE_COLOR },
    edgeDash(type)  { return EDGE_DASH[type]  ?? '' },
    // ── Interaction ──────────────────────────────────────────────────────────
    selectNode(node) {
      this.selectedNode = this.selectedNode === node.id ? null : node.id
    },
    startDrag(node, evt) {
      this.draggedNode = node
      const svgRect = this.$refs.graphSvg.getBoundingClientRect()
      this.dragOffset = {
        x: (evt.clientX - svgRect.left - this.pan.x) / this.zoom - node.x,
        y: (evt.clientY - svgRect.top  - this.pan.y) / this.zoom - node.y,
      }
      evt.preventDefault()
    },
    onSvgMousedown(evt) {
      if (evt.target === this.$refs.graphSvg || evt.target.tagName === 'svg') {
        this.panning = true
        this.panStart = { x: evt.clientX - this.pan.x, y: evt.clientY - this.pan.y }
      }
    },
    onMousemove(evt) {
      if (this.draggedNode) {
        const svgRect = this.$refs.graphSvg?.getBoundingClientRect()
        if (!svgRect) return
        const x = (evt.clientX - svgRect.left - this.pan.x) / this.zoom - this.dragOffset.x
        const y = (evt.clientY - svgRect.top  - this.pan.y) / this.zoom - this.dragOffset.y
        this.draggedNode.x = Math.max(60, Math.min(this.graphWidth  - 60, x))
        this.draggedNode.y = Math.max(60, Math.min(this.graphHeight - 60, y))
      } else if (this.panning) {
        this.pan.x = evt.clientX - this.panStart.x
        this.pan.y = evt.clientY - this.panStart.y
      }
    },
    onMouseup() {
      this.draggedNode = null
      this.panning = false
    },
    onWheel(evt) {
      const factor = evt.deltaY < 0 ? 1.1 : 0.9
      this.zoom = Math.max(0.2, Math.min(3, this.zoom * factor))
    },
    resetView() {
      this.zoom = 1
      this.pan = { x: 0, y: 0 }
    },
    // ── Sidebar ──────────────────────────────────────────────────────────────
    nodeConnections(nodeId) {
      if (!nodeId) return []
      return this.edges
        .filter(e => e.source === nodeId)
        .map(e => ({
          id: e.id,
          relationship_type: e.relationship_type,
          targetLabel: (this.nodes.find(n => n.id === e.target) || {}).label || 'Unknown',
        }))
    },
    // ── Utils ─────────────────────────────────────────────────────────────────
    formatType(t) {
      return (t || '').split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
    },
    truncate(s, n) {
      if (!s) return ''
      return s.length > n ? s.slice(0, n) + '…' : s
    },
  },
}
</script>

<style scoped>
.assets-map-view {
  padding: 2rem;
  max-width: 1700px;
  margin: 0 auto;
}

/* ── Page header ────────────────────────────────────────────────── */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
  gap: 1rem;
  flex-wrap: wrap;
}
.page-header h2 { margin: 0; font-size: 1.75rem; color: #e2e8f0; }
.page-header p  { margin: 0.35rem 0 0; color: #94a3b8; }

.page-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.toggle-labels {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.82rem;
  color: #94a3b8;
  cursor: pointer;
  user-select: none;
}
.toggle-labels input { accent-color: #3b82f6; }

/* ── Card & padding ─────────────────────────────────────────────── */
.graph-card { margin-bottom: 1.5rem; overflow: hidden; }
.p0 { padding: 0 !important; }

/* ── Filter bar ─────────────────────────────────────────────────── */
.filter-bar {
  display: flex;
  align-items: flex-end;
  gap: 1.25rem;
  padding: 1rem 1.25rem;
  background: #151b2a;
  border-bottom: 1px solid #1e293b;
  flex-wrap: wrap;
}
.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}
.filter-group label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #64748b;
  font-weight: 600;
}
.filter-group select {
  background: #0f1623;
  border: 1px solid #2d3548;
  color: #e2e8f0;
  padding: 0.4rem 0.7rem;
  border-radius: 6px;
  font-size: 0.82rem;
  min-width: 150px;
  cursor: pointer;
}
.filter-group select:focus { outline: none; border-color: #3b82f6; }

.filter-stats {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.82rem;
  color: #64748b;
  align-self: flex-end;
  padding-bottom: 0.4rem;
}
.sep { color: #334155; }

/* ── States ─────────────────────────────────────────────────────── */
.loading, .empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 5rem 2rem;
  color: #64748b;
  gap: 1rem;
}
.empty-state p  { margin: 0; font-size: 1rem; color: #94a3b8; }
.empty-state small { font-size: 0.82rem; }
.spinner {
  width: 36px; height: 36px;
  border: 3px solid #1e293b;
  border-top-color: #3b82f6;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Graph wrap ─────────────────────────────────────────────────── */
.graph-wrap {
  position: relative;
}

.graph-svg {
  display: block;
  width: 100%;
  height: 700px;
  background: #0e1422;
  cursor: grab;
}
.graph-svg:active { cursor: grabbing; }

/* ── Edge / node SVG ────────────────────────────────────────────── */
.edge-line { pointer-events: none; }
.edge-label {
  fill: #64748b;
  font-size: 0.68rem;
  pointer-events: none;
}
.node-label {
  fill: #cbd5e1;
  font-size: 0.72rem;
  font-weight: 500;
}
.node-type-label {
  fill: #475569;
  font-size: 0.62rem;
}

/* ── Zoom controls ──────────────────────────────────────────────── */
.zoom-controls {
  position: absolute;
  right: 1rem;
  bottom: 1rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  background: #151b2a;
  border: 1px solid #2d3548;
  border-radius: 8px;
  padding: 6px;
}
.zoom-controls button {
  width: 28px; height: 28px;
  background: #1e293b;
  border: 1px solid #2d3548;
  color: #e2e8f0;
  border-radius: 5px;
  cursor: pointer;
  font-size: 1rem;
  line-height: 1;
  display: flex; align-items: center; justify-content: center;
  transition: background 0.15s;
}
.zoom-controls button:hover { background: #2d3548; }
.zoom-controls span {
  font-size: 0.68rem;
  color: #64748b;
  min-width: 36px;
  text-align: center;
}

/* ── Legend ─────────────────────────────────────────────────────── */
.legend {
  position: absolute;
  left: 1rem;
  bottom: 1rem;
  background: rgba(15, 22, 35, 0.96);
  border: 1px solid #1e293b;
  border-radius: 10px;
  padding: 0.85rem 1rem;
  display: flex;
  gap: 1.5rem;
  max-width: 680px;
  flex-wrap: wrap;
}
.legend-section { display: flex; flex-direction: column; gap: 0.5rem; min-width: 130px; }
.legend-title {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: #475569;
  font-weight: 700;
  margin-bottom: 0.15rem;
}
.legend-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.35rem 0.75rem;
}
.legend-node-item {
  display: flex; align-items: center; gap: 0.4rem;
  font-size: 0.72rem; color: #94a3b8;
}
.legend-rel-list { display: flex; flex-direction: column; gap: 0.35rem; }
.legend-rel-item {
  display: flex; align-items: center; gap: 0.5rem;
  font-size: 0.72rem; color: #94a3b8;
}
.legend-indicator {
  display: flex; align-items: center; gap: 0.4rem;
  font-size: 0.72rem; color: #94a3b8;
}

/* ── Sidebar ────────────────────────────────────────────────────── */
.asset-details-panel {
  position: fixed;
  right: 0; top: 0;
  width: 360px;
  height: 100vh;
  background: #111827;
  border-left: 1px solid #1e293b;
  z-index: 1000;
  overflow-y: auto;
  box-shadow: -6px 0 24px rgba(0,0,0,0.4);
  display: flex;
  flex-direction: column;
}

.slide-enter-active, .slide-leave-active { transition: transform 0.25s ease; }
.slide-enter-from, .slide-leave-to { transform: translateX(100%); }

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.1rem 1.25rem;
  border-bottom: 1px solid #1e293b;
  background: #0f1623;
  gap: 0.75rem;
}
.panel-header-left {
  display: flex; align-items: center; gap: 0.6rem;
  overflow: hidden;
}
.panel-type-dot {
  width: 10px; height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.panel-header h3 {
  margin: 0;
  font-size: 1rem;
  color: #e2e8f0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.close-btn {
  background: none; border: none;
  color: #64748b; font-size: 1.5rem;
  cursor: pointer; padding: 0;
  width: 28px; height: 28px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 4px;
  flex-shrink: 0;
  transition: all 0.15s;
}
.close-btn:hover { background: #1e293b; color: #e2e8f0; }

.panel-body { padding: 1.25rem; display: flex; flex-direction: column; gap: 0.6rem; }

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0;
  border-bottom: 1px solid #1a2236;
}
.detail-key { font-size: 0.8rem; color: #64748b; }
.detail-val { font-size: 0.82rem; color: #cbd5e1; text-align: right; }
.code {
  font-family: 'Menlo', 'Monaco', monospace;
  font-size: 0.72rem;
  background: #0f1623;
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid #1e293b;
  word-break: break-all;
  text-align: right;
}

.connections-section {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #1e293b;
}
.connections-section h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.conn-count {
  background: #1e293b;
  color: #64748b;
  font-size: 0.72rem;
  padding: 1px 7px;
  border-radius: 99px;
}
.connection-item {
  background: #0f1623;
  border: 1px solid #1a2236;
  border-radius: 6px;
  padding: 0.55rem 0.75rem;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.8rem;
}
.conn-rel   { font-weight: 600; }
.conn-arrow { color: #334155; }
.conn-target { color: #94a3b8; flex: 1; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.no-connections { color: #475569; font-size: 0.82rem; padding: 0.5rem 0; }

/* ── Badges ─────────────────────────────────────────────────────── */
.badge {
  font-size: 0.72rem;
  padding: 2px 8px;
  border-radius: 99px;
  background: #1e293b;
  color: #94a3b8;
  font-weight: 500;
}
.badge-aws     { background: #431a00; color: #fb923c; }
.badge-azure   { background: #001c3d; color: #60a5fa; }
.badge-gcp     { background: #1a2c1a; color: #4ade80; }
.badge-success { background: #052e16; color: #4ade80; }
.badge-warning { background: #2d1b00; color: #fbbf24; }
.badge-danger  { background: #1c0a0a; color: #f87171; }

/* ── Stats strip ─────────────────────────────────────────────────── */
.stats-strip {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-top: 1.5rem;
}
.stat-card {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: #111827;
  border: 1px solid #1e293b;
  border-radius: 8px;
  padding: 0.6rem 1rem;
  flex: 1;
  min-width: 110px;
}
.stat-card-total { border-color: #2d3548; }
.stat-dot {
  width: 10px; height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.stat-label { font-size: 0.78rem; color: #64748b; flex: 1; }
.stat-val   { font-size: 1rem; font-weight: 700; color: #e2e8f0; }

/* ── Responsive ─────────────────────────────────────────────────── */
@media (max-width: 900px) {
  .asset-details-panel { width: 100%; height: auto; position: relative; border-left: none; border-top: 1px solid #1e293b; box-shadow: none; }
  .graph-svg { height: 450px; }
  .legend { display: none; }
}
</style>

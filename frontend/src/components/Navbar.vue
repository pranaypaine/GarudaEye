<template>
  <nav class="navbar">
    <div class="navbar-container">
      <div class="navbar-brand">
        <span class="logo">🦅</span>
        <h1>GarudaEye</h1>
      </div>
      
      <div class="navbar-links">
        <router-link to="/" class="nav-link" active-class="active">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="7" height="7"></rect>
            <rect x="14" y="3" width="7" height="7"></rect>
            <rect x="14" y="14" width="7" height="7"></rect>
            <rect x="3" y="14" width="7" height="7"></rect>
          </svg>
          Dashboard
        </router-link>
        
        <router-link to="/assets" class="nav-link" active-class="active">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 3h18v18H3z"></path>
            <path d="M3 9h18"></path>
            <path d="M9 21V9"></path>
          </svg>
          Assets
        </router-link>
        
        <router-link to="/assets-map" class="nav-link" active-class="active">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="2" y1="12" x2="22" y2="12"></line>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
          </svg>
          Assets Map
        </router-link>
        
        <router-link to="/attack-surface" class="nav-link" active-class="active">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          Attack Surface
        </router-link>
      </div>
      
      <div class="navbar-actions">
        <!-- Shodan Enrich button -->
        <div class="enrich-wrapper">
          <!-- Idle -->
          <button
            v-if="!enriching && !enrichResult"
            @click="$emit('start-enrichment')"
            class="btn-enrich"
            :disabled="collecting"
            title="Run Shodan enrichment on all existing public assets"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            Enrich
          </button>
          <!-- Loading -->
          <button v-else-if="enriching" class="btn-enrich btn-enrich--active" disabled>
            <span class="enrich-spinner"></span>
            Queuing…
          </button>
          <!-- Result toast -->
          <div v-else-if="enrichResult && !enrichResult.error" class="enrich-result">
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            {{ enrichResult.queued_ip + enrichResult.queued_domain }} queued
          </div>
          <div v-else-if="enrichResult && enrichResult.error" class="enrich-result enrich-result--error">
            Failed
          </div>
        </div>

        <!-- Divider -->
        <span class="action-divider"></span>

        <!-- Idle state -->
        <button v-if="!collecting" @click="$emit('start-collection')" class="btn-scan">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"></circle>
            <path d="m21 21-4.35-4.35"></path>
          </svg>
          Start Scan
        </button>

        <!-- Active scanning state -->
        <div v-else class="scan-progress-wrapper">
          <button class="btn-scan btn-scan--active" disabled>
            <span class="scan-pulse"></span>
            <span class="scan-label">Scanning…</span>
            <span class="scan-meta">
              <span v-if="assetCount > 0" class="scan-count">{{ assetCount }} assets</span>
              <span class="scan-time">{{ formattedElapsed }}</span>
            </span>
          </button>
          <!-- Animated progress bar under the button -->
          <div class="scan-bar">
            <div class="scan-bar-fill"></div>
          </div>
        </div>
      </div>
    </div>
  </nav>
</template>

<script>
export default {
  name: 'Navbar',
  props: {
    collecting: {
      type: Boolean,
      default: false
    },
    assetCount: {
      type: Number,
      default: 0
    },
    scanElapsed: {
      type: Number,
      default: 0
    },
    enriching: {
      type: Boolean,
      default: false
    },
    enrichResult: {
      type: Object,
      default: null
    }
  },
  emits: ['start-collection', 'start-enrichment'],
  computed: {
    formattedElapsed() {
      const m = Math.floor(this.scanElapsed / 60)
      const s = this.scanElapsed % 60
      return m > 0
        ? `${m}m ${String(s).padStart(2, '0')}s`
        : `${s}s`
    }
  }
}
</script>

<style scoped>
.navbar-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.action-divider {
  width: 1px;
  height: 20px;
  background: #334155;
  flex-shrink: 0;
}

.enrich-wrapper {
  display: flex;
  align-items: center;
}

.btn-enrich {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.45rem 0.85rem;
  background: transparent;
  color: #94a3b8;
  border: 1px solid #334155;
  border-radius: 7px;
  cursor: pointer;
  font-size: 0.8rem;
  font-weight: 500;
  transition: color 0.2s, border-color 0.2s, background 0.2s;
  white-space: nowrap;
}

.btn-enrich:hover:not(:disabled) {
  color: #e2e8f0;
  border-color: #475569;
  background: #1e293b;
}

.btn-enrich:disabled {
  opacity: 0.4;
  cursor: default;
}

.btn-enrich--active {
  color: #7dd3fc;
  border-color: #1d4ed8;
  background: #0f172a;
}

.enrich-spinner {
  width: 10px;
  height: 10px;
  border: 2px solid #1d4ed8;
  border-top-color: #7dd3fc;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  flex-shrink: 0;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.enrich-result {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.35rem 0.75rem;
  background: #052e16;
  color: #4ade80;
  border: 1px solid #166534;
  border-radius: 7px;
  font-size: 0.78rem;
  font-weight: 600;
  white-space: nowrap;
}

.enrich-result--error {
  background: #1c0a0a;
  color: #f87171;
  border-color: #7f1d1d;
}

.btn-scan {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1.1rem;
  background: #3b82f6;
  color: #fff;
  border: none;
  border-radius: 7px;
  cursor: pointer;
  font-size: 0.85rem;
  font-weight: 600;
  transition: background 0.2s, transform 0.1s;
  white-space: nowrap;
}

.btn-scan:hover:not(:disabled) {
  background: #2563eb;
  transform: translateY(-1px);
}

.btn-scan--active {
  background: #1d4ed8;
  cursor: default;
  padding: 0.45rem 1rem;
  gap: 0.6rem;
}

.scan-pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #93c5fd;
  animation: pulse-dot 1.2s ease-in-out infinite;
  flex-shrink: 0;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.4; transform: scale(0.7); }
}

.scan-label {
  color: #dbeafe;
}

.scan-meta {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.75rem;
  font-weight: 400;
  color: #93c5fd;
  padding-left: 0.35rem;
  border-left: 1px solid #3b82f680;
}

.scan-count {
  font-weight: 600;
  color: #bfdbfe;
}

.scan-progress-wrapper {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.scan-bar {
  height: 3px;
  background: #1e3a5f;
  border-radius: 2px;
  overflow: hidden;
}

.scan-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #3b82f6, #60a5fa, #3b82f6);
  background-size: 200% 100%;
  animation: scan-slide 1.6s linear infinite;
}

@keyframes scan-slide {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
</style>

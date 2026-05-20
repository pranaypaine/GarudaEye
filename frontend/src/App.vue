<template>
  <div id="app">
    <Navbar
      :collecting="collecting"
      :asset-count="assetCount"
      :scan-elapsed="scanElapsed"
      :enriching="enriching"
      :enrich-result="enrichResult"
      @start-collection="startCollection"
      @start-enrichment="startEnrichment"
    />
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script>
import Navbar from './components/Navbar.vue'
import axios from 'axios'

export default {
  name: 'App',
  components: { Navbar },
  data() {
    return {
      collecting: false,
      assetCount: 0,
      scanElapsed: 0,
      _pollInterval: null,
      _elapsedInterval: null,
      enriching: false,
      enrichResult: null,
    }
  },
  methods: {
    async startCollection() {
      if (this.collecting) return
      try {
        this.collecting = true
        this.scanElapsed = 0
        // Snapshot count before the scan
        const before = await axios.get('/api/assets?limit=1').catch(() => ({ data: [] }))
        this.assetCount = 0

        await axios.get('/api/start')

        // Tick elapsed seconds
        this._elapsedInterval = setInterval(() => { this.scanElapsed++ }, 1000)

        // Poll total asset count every 3 seconds so the button shows live progress
        this._pollInterval = setInterval(async () => {
          try {
            const res = await axios.get('/api/dashboard/dashboard')
            this.assetCount = res.data.total_assets || 0
          } catch (_) { /* ignore */ }
        }, 3000)

        // Stop after 3 minutes as a safety guard; pages refresh their own data
        setTimeout(() => this._stopScan(), 180000)
      } catch (err) {
        console.error('Collection failed:', err)
        this._stopScan()
      }
    },
    _stopScan() {
      this.collecting = false
      clearInterval(this._pollInterval)
      clearInterval(this._elapsedInterval)
      this._pollInterval = null
      this._elapsedInterval = null
    },
    async startEnrichment() {
      if (this.enriching || this.collecting) return
      this.enriching = true
      this.enrichResult = null
      try {
        const res = await axios.get('/api/enrich')
        this.enrichResult = res.data
        // Clear the result toast after 6 seconds
        setTimeout(() => { this.enrichResult = null }, 6000)
      } catch (err) {
        console.error('Enrichment failed:', err)
        this.enrichResult = { error: true }
        setTimeout(() => { this.enrichResult = null }, 4000)
      } finally {
        this.enriching = false
      }
    }
  },
  beforeUnmount() {
    this._stopScan()
  }
}
</script>

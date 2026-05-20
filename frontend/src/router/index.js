import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Assets from '../views/Assets.vue'
import AssetDetail from '../views/AssetDetail.vue'
import AssetsMap from '../views/AssetsMap.vue'
import AttackSurface from '../views/AttackSurface.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/assets',
    name: 'Assets',
    component: Assets
  },
  {
    path: '/assets/:id',
    name: 'AssetDetail',
    component: AssetDetail
  },
  {
    path: '/assets-map',
    name: 'AssetsMap',
    component: AssetsMap
  },
  {
    path: '/attack-surface',
    name: 'AttackSurface',
    component: AttackSurface
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

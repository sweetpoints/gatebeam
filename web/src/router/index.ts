import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '../features/auth/store'
import Login from '../features/auth/Login.vue'
import Enroll from '../features/auth/Enroll.vue'
import Recover from '../features/auth/Recover.vue'
import Sites from '../features/sites/Sites.vue'
import Targets from '../features/targets/Targets.vue'
import Releases from '../features/releases/Releases.vue'
import Certificates from '../features/certificates/Certificates.vue'
import Credentials from '../features/credentials/Credentials.vue'
import Overview from '../features/overview/Overview.vue'
import Logs from '../features/logs/Logs.vue'
import Alerts from '../features/alerts/Alerts.vue'
import Backups from '../features/backups/Backups.vue'
import Accounts from '../features/accounts/Accounts.vue'
import Audit from '../features/audit/Audit.vue'
import ConsoleLayout from '../layouts/ConsoleLayout.vue'
export const router = createRouter({ history:createWebHistory(), routes:[
  {path:'/login',component:Login},{path:'/enroll',component:Enroll},{path:'/recover',component:Recover},
  {path:'/',component:ConsoleLayout,meta:{authenticated:true},children:[{path:'console/overview',component:Overview},{path:'console/logs',component:Logs},{path:'console/alerts',component:Alerts},{path:'console/backups',component:Backups},{path:'console/accounts',component:Accounts},{path:'console/audit',component:Audit},{path:'console/certificates',component:Certificates},{path:'console/credentials',component:Credentials},{path:'console/sites',component:Sites},{path:'console/targets',component:Targets},{path:'console/releases',component:Releases}]},
] })
router.beforeEach(async to => {
  if (to.meta.authenticated) {
    try { if (!await useAuth().refresh()) return '/login' }
    catch { return '/login' }
  }
  return true
})

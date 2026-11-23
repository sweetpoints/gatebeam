import { defineConfig } from '@playwright/test'
const aggregateFactor = process.env.GATEBEAM_ACCEPTANCE_EXECUTION === 'software-emulated-vm' ? 12 : 1
export default defineConfig({
  testDir: './tests', timeout: 60000 * aggregateFactor, globalTimeout: 70000 * aggregateFactor, workers: 1, retries: 0,
  reporter: [['list']], outputDir: process.env.GATEBEAM_WEB_RESULTS || '../.work/web-results',
  use: { baseURL: process.env.GATEBEAM_WEB_URL, channel: process.env.GATEBEAM_BROWSER_CHANNEL || undefined,
    actionTimeout: 60000, navigationTimeout: 60000,
    headless: true, trace: 'off', screenshot: 'off', video: 'off' },
})

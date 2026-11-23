import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
const api = process.env.GATEBEAM_DEV_API || 'http://127.0.0.1:8080'
export default defineConfig({ plugins: [vue(), tailwindcss()], server: { host:'127.0.0.1', proxy: Object.fromEntries(['/auth', '/accounts', '/tokens', '/audit', '/livez', '/readyz'].map(path => [path, {target: api}])) }, build: { sourcemap: false } })

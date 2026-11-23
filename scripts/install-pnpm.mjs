// Fixed official package artifact; no mutable npm resolution or global store.
import { createHash } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { setTimeout as sleep } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'

class TemporaryDownloadError extends Error {}
const networkErrors = new Set(['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_SOCKET'])

export async function downloadVerified(url, integrity, { request = fetch, wait = sleep } = {}) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await request(url, { signal: AbortSignal.timeout(30000) })
      if (!response.ok) {
        await response.body?.cancel()
        const message = `pnpm artifact unavailable: HTTP ${response.status}`
        if (response.status === 429 || response.status >= 500) throw new TemporaryDownloadError(message)
        throw new Error(message)
      }
      const bytes = Buffer.from(await response.arrayBuffer())
      if (bytes.length > 16 * 1024 * 1024 || createHash('sha512').update(bytes).digest('base64') !== integrity) throw new Error('pnpm artifact integrity mismatch')
      return bytes
    } catch (error) {
      const retryable = error instanceof TemporaryDownloadError || ['AbortError', 'TimeoutError'].includes(error.name) || networkErrors.has(error.cause?.code ?? error.code)
      if (!retryable || attempt === 3) throw error
      console.warn(`pnpm artifact download attempt ${attempt}/3 failed; retrying`)
      await wait(attempt * 1000)
    }
  }
}

// pnpm 12 ships a shebang-less placeholder. npm installs the exact optional
// native package for this OS/libc and runs the official lifecycle to replace it.
export function installNativeBinary(run = execFileSync) {
  run('npm', ['install', '--prefix', '/opt/pnpm', '--omit=dev', '--include=optional', '--ignore-scripts=false', '--package-lock=false', '--no-audit', '--no-fund', '--registry', 'https://registry.npmmirror.com'], { timeout: 180000, stdio: 'inherit' })
  const version = run('/opt/pnpm/pnpm', ['--version'], { encoding: 'utf8', timeout: 30000 }).trim()
  if (version !== '12.16.1') throw new Error('pnpm executable version mismatch')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const bytes = await downloadVerified('https://registry.npmmirror.com/pnpm/-/pnpm-12.16.1.tgz', 'CR0d7nknV1Zhsl2rPCrjHK/BxU1rce1qZgDPDByxBDSkR+rhQBXxsj4ua+3u1535SpMuIWTSgyKA3OP7MvZW0Q==')
  await mkdir('/opt/pnpm', { recursive: true })
  await writeFile('/tmp/pnpm.tgz', bytes, { mode: 0o600 })
  execFileSync('tar', ['-xzf', '/tmp/pnpm.tgz', '-C', '/opt/pnpm', '--strip-components=1'], { timeout: 10000 })
  installNativeBinary()
}

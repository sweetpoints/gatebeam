import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { downloadVerified, installNativeBinary } from './install-pnpm.mjs'

const bytes = Buffer.from('owned package fixture')
const integrity = createHash('sha512').update(bytes).digest('base64')
const reset = () => new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } })

test('retries connection resets and returns only the verified package', async () => {
  let calls = 0
  const waits = []
  const result = await downloadVerified('https://owned.invalid/package', integrity, {
    request: async () => { if (++calls < 3) throw reset(); return new Response(bytes) },
    wait: async ms => waits.push(ms)
  })
  assert.deepEqual(result, bytes)
  assert.equal(calls, 3)
  assert.deepEqual(waits, [1000, 2000])
})

test('retries a temporary server failure', async () => {
  let calls = 0
  const result = await downloadVerified('https://owned.invalid/package', integrity, {
    request: async () => ++calls === 1 ? new Response('unavailable', { status: 503 }) : new Response(bytes),
    wait: async () => {}
  })
  assert.deepEqual(result, bytes)
  assert.equal(calls, 2)
})

test('rejects a corrupt package without retrying or accepting it', async () => {
  let calls = 0
  await assert.rejects(downloadVerified('https://owned.invalid/package', integrity, {
    request: async () => { calls++; return new Response('corrupt') },
    wait: async () => assert.fail('integrity failures must not retry')
  }), /integrity mismatch/)
  assert.equal(calls, 1)
})

test('does not retry permanent HTTP failures', async () => {
  let calls = 0
  await assert.rejects(downloadVerified('https://owned.invalid/package', integrity, {
    request: async () => { calls++; return new Response('missing', { status: 404 }) },
    wait: async () => assert.fail('permanent failures must not retry')
  }), /404/)
  assert.equal(calls, 1)
})

test('exhausted network failures remain failures after three attempts', async () => {
  let calls = 0
  await assert.rejects(downloadVerified('https://owned.invalid/package', integrity, {
    request: async () => { calls++; throw reset() }, wait: async () => {}
  }), /fetch failed/)
  assert.equal(calls, 3)
})


test('installs optional native executable before invoking pnpm directly', () => {
  let installed = false
  const run = (binary, args) => {
    if (binary === 'npm') {
      assert.ok(args.includes('--include=optional'))
      assert.ok(args.includes('--ignore-scripts=false'))
      assert.ok(args.includes('https://registry.npmmirror.com'))
      installed = true
      return ''
    }
    assert.equal(binary, '/opt/pnpm/pnpm')
    assert.equal(installed, true, 'an unpacked pnpm 12 placeholder is not executable')
    return '12.16.1\n'
  }
  installNativeBinary(run)
})

test('refuses an incompatible executable after installation', () => {
  assert.throws(() => installNativeBinary((binary) => binary === 'npm' ? '' : '12.17.0\n'), /version mismatch/)
})

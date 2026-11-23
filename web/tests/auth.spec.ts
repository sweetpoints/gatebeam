import { test, expect, type Page } from '@playwright/test'
import { readFileSync, writeFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'
// No traces, screenshots or assertion values containing one-time enrollment secrets.
const fixture = JSON.parse(readFileSync(process.env.GATEBEAM_WEB_FIXTURE!, 'utf8'))
function code(uri: string, offset = 0) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of new URL(uri).searchParams.get('secret')!) bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
  const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(v => parseInt(v, 2)))
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset))
  const digest = createHmac('sha1', bytes).update(counter).digest(); const n = digest[digest.length - 1]! & 15
  return ((digest.readUInt32BE(n) & 0x7fffffff) % 1000000).toString().padStart(6, '0')
}
async function login(page: Page, uri: string) {
  await page.goto('/login')
  await page.getByLabel('账号', { exact: true }).fill(fixture.name)
  await page.getByLabel('密码', { exact: true }).fill(fixture.password)
  await page.getByRole('button', { name: '继续验证' }).click()
  await page.getByLabel('动态验证码', { exact: true }).fill(code(uri, 1))
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page.getByRole('heading', { name: '会话概览' })).toBeVisible()
}
test('真实 PostgreSQL：绑定、登录、刷新、CSRF、恢复、禁用和退出边界', async ({ page, context }) => {
  console.log(`Browser acceptance: ${context.browser()?.browserType().name()} ${context.browser()?.version()}`)
  await page.goto('/')
  await expect(page).toHaveURL(/\/login$/)
  // Pending bootstrap cannot authenticate or navigate into the console.
  const pending = await page.request.post('/auth/login', { headers: { Origin: fixture.origin }, data: { name: fixture.name, password: fixture.password } })
  expect(pending.status()).toBe(401)
  await page.goto('/enroll')
  await page.getByLabel('一次性绑定资料').fill(JSON.stringify(fixture.enrollment))
  await page.getByRole('button', { name: '读取绑定资料' }).click()
  await page.getByLabel('设置密码').fill(fixture.password)
  await page.getByLabel('动态验证码', { exact: true }).fill(code(fixture.enrollment.provisioning_uri))
  await page.getByRole('button', { name: '完成绑定' }).click()
  await expect(page.getByRole('heading', { name: '保存恢复码' })).toBeVisible()
  const recovery = await page.getByTestId('recovery-codes').textContent()
  const recoveryCode = recovery!.trim().split(/\s+/)[0]!
  await page.getByRole('button', { name: '已保存，关闭并登录' }).click()
  await login(page, fixture.enrollment.provisioning_uri)
  const cookies = await context.cookies()
  expect(cookies.some(c => c.name === 'gatebeam-dev' && c.httpOnly && c.sameSite === 'Strict')).toBe(true)
  expect(await page.evaluate(() => Object.keys(localStorage).length)).toBe(0)
  expect(await page.evaluate(() => Object.keys(sessionStorage).join(','))).toBe('gatebeam.csrf')
  await page.reload()
  await expect(page.getByRole('heading', { name: '会话概览' })).toBeVisible()
  expect((await page.request.post('/auth/logout', { headers: { Origin: fixture.origin } })).status()).toBe(401)
  expect((await page.request.post('/accounts', { headers: { Origin: fixture.origin }, data: {name:'denied', role:'admin', totp_code:'000000'} })).status()).toBe(401)
  expect((await page.request.post('/auth/logout', { headers: { Origin: 'https://invalid.example' } })).status()).toBe(403)
  const csrf = await page.evaluate(() => sessionStorage.getItem('gatebeam.csrf'))
  await page.evaluate(() => sessionStorage.removeItem('gatebeam.csrf'))
  await page.getByRole('button', { name: '退出登录' }).click()
  await expect(page.getByRole('alert')).toContainText('缺少安全校验资料')
  expect((await page.request.get('/auth/session')).status()).toBe(200)
  await page.evaluate(value => sessionStorage.setItem('gatebeam.csrf', value!), csrf)
  await page.getByRole('button', { name: '退出登录' }).click()
  await expect(page).toHaveURL(/\/login$/)
  expect((await page.request.get('/auth/session')).status()).toBe(401)
  await page.goto('/'); await expect(page).toHaveURL(/\/login$/)
  // Recovery uses the real service response; raw seed never enters a URL.
  await page.goto('/recover')
  await page.getByLabel('账号', { exact: true }).fill(fixture.name)
  await page.getByLabel('密码', { exact: true }).fill(fixture.password)
  await page.getByLabel('恢复码', { exact: true }).fill(recoveryCode)
  await page.getByRole('button', { name: '恢复并重新绑定' }).click()
  await expect(page).toHaveURL(/\/enroll$/)
  const uri = await page.getByTestId('provisioning-uri').textContent()
  await page.getByLabel('设置密码').fill(fixture.password)
  await page.getByLabel('动态验证码', { exact: true }).fill(code(uri!))
  await page.getByRole('button', { name: '完成绑定' }).click()
  await page.getByRole('button', { name: '已保存，关闭并登录' }).click()
  await login(page, uri!)
  // Test fixture changes authoritative DB state without adding product HTTP routes.
  writeFileSync(fixture.disableSignal, 'disable', { mode: 0o600 })
  await expect.poll(async () => (await page.request.get('/auth/session')).status(), {timeout:5000}).toBe(401)
  await page.getByRole('button', { name: '重新验证会话' }).click()
  await expect(page).toHaveURL(/\/login$/)
  await page.goto('/'); await expect(page).toHaveURL(/\/login$/)
})

test('绑定 fragment 立即清除，刷新丢弃秘密且不写浏览器存储', async ({page}) => {
  let leaked = false
  const seed = new URL(fixture.enrollment.provisioning_uri).searchParams.get('secret')!
  page.on('request', req => { if(req.url().includes(seed) || req.url().includes(fixture.enrollment.invite_id)) leaked = true })
  await page.goto('/enroll#bundle='+encodeURIComponent(JSON.stringify(fixture.enrollment)))
  await expect(page).toHaveURL(/\/enroll$/)
  expect(await page.getByTestId('provisioning-uri').count()).toBe(1)
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0)
  await page.reload()
  await expect(page.getByLabel('一次性绑定资料')).toBeVisible()
  expect(await page.getByTestId('provisioning-uri').count()).toBe(0)
  expect(leaked).toBe(false)
})

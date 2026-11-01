import assert from 'node:assert/strict'
import * as crypto from 'node:crypto'
import https from 'node:https'
import { EventEmitter } from 'node:events'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { test } from 'node:test'
import { normalizeApex, runApexProvider } from '../scripts/apex-provider.js'

const b64 = (v) => Buffer.from(v).toString('base64')
const rawPublic = (key) => key.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
function fixture() {
  const configKeys = crypto.generateKeyPairSync('ed25519')
  const subKeys = crypto.generateKeyPairSync('ed25519')
  const apex = {
    xorKey: 'AbCdEfGhIjKlMnOpQrStUvWxYz123456',
    configPublicKey: rawPublic(configKeys.publicKey), subscriptionPublicKey: rawPublic(subKeys.publicKey),
    subscriptionKey: b64(crypto.randomBytes(32)), flag: 'apex', profileId: 1, keyId: 1,
    mtls: Object.fromEntries(['oss', 'api', 'subscription'].map((purpose) => [purpose, {
      version: 1, profile_id: 45, purpose,
      client_cert_pem: `-----BEGIN CERTIFICATE-----\n${purpose}`,
      client_key_pem: `-----BEGIN PRIVATE KEY-----\n${purpose}`,
    }])),
  }
  const cfg = {
    domains: ['https://api.test'], subscribe_domain: ['https://sub.test', 'https://backup.test'], enable_api_path_mapping: true,
    subscribe_path: { '/api/v1/passport/auth/login': '/custom/login', '/api/v1/user/getSubscribe': '/custom/token', '/api/v1/client/subscribe?token=': '/custom/download?key=' },
  }
  const xor = (value) => Buffer.from(Buffer.from(value).map((v, i) => v ^ apex.xorKey.charCodeAt(i % apex.xorKey.length)))
  function configBody(tamper = false) {
    const payload = Buffer.from(JSON.stringify(cfg))
    const signature = crypto.sign(null, Buffer.concat([Buffer.from('apex-config-v1\0'), payload]), configKeys.privateKey)
    if (tamper) signature[0] ^= 1
    return b64(xor(JSON.stringify({ format: 'apex-config-v1', payload: b64(payload), signature: b64(signature) })))
  }
  const plain = 'proxies:\n  - name: fixture\n    type: vless\n'
  function subscription({ tamper = false, wrongAAD = false, id = 1, wrongKey = false } = {}) {
    const header = Buffer.alloc(25)
    header.write('APXS'); header[4] = 2; header.writeUInt32BE(id, 5); header.writeUInt32BE(1, 9)
    crypto.randomBytes(12).copy(header, 13)
    const cipher = crypto.createCipheriv('aes-256-gcm', wrongKey ? crypto.randomBytes(32) : Buffer.from(apex.subscriptionKey, 'base64'), header.subarray(13))
    cipher.setAAD(Buffer.concat([Buffer.from(wrongAAD ? 'wrong-aad\0' : 'apex-sub-v2\0'), header]))
    const body = Buffer.concat([header, cipher.update(plain), cipher.final(), cipher.getAuthTag()])
    const sig = crypto.sign(null, Buffer.concat([Buffer.from('apex-sub-sign-v2\0'), body]), subKeys.privateKey)
    if (tamper) sig[0] ^= 1
    return Buffer.concat([body, sig])
  }
  const config = { cfgUrls: ['https://oss.test/config.json'], headers: { 'User-Agent': 'test.app/v2.4.6' }, username: 'fixture@example.test', password: 'fixture-password', apex }
  return { config, cfg, configBody, subscription, plain, xor }
}
async function runFixture(f, { badConfig = false, subscriptionOptions, urlOnly = false, cached = false, configOverride, missingAPI = false } = {}) {
  const calls = []
  const store = new Map(cached ? [['apex-cache', 'https://sub.test/custom/download?key=private-token&flag=old']] : [])
  const parseCalls = []
  const httpsMock = {
    request(url, options, callback) {
      calls.push({ url: new URL(url), ...options })
      const req = new EventEmitter()
      req.end = () => queueMicrotask(() => {
        const res = new EventEmitter()
        res.statusCode = missingAPI && url.hostname === 'api.test' ? 403 : 200
        res.headers = {}
        callback(res)
        let body
        if (url.hostname === 'oss.test') body = f.configBody(badConfig)
        else if (url.pathname === '/custom/login') body = JSON.stringify({ data: { auth_data: 'fixture-auth' } })
        else if (url.pathname === '/custom/token') body = JSON.stringify({ data: {
          ...(urlOnly ? {} : { token: 'private-token' }),
          subscribe_url: 'apex-url-v2:' + b64(f.xor('https://legacy.test/api/v1/client/subscribe?token=private-token')),
        } })
        else body = f.subscription(subscriptionOptions)
        res.emit('data', Buffer.from(body)); res.emit('end'); req.emit('close')
      })
      req.destroy = (e) => { req.emit('error', e); req.emit('close') }
      return req
    },
  }
  const context = {
    Buffer, URL, setTimeout, clearTimeout,
    process: { env: {}, getBuiltinModule: (name) => name === 'crypto' ? crypto : httpsMock },
    yaml: { parse: () => ({ ...f.config, ...configOverride }) }, $arguments: {},
    $substore: { env: { isNode: true }, read: (k) => k === 'settings' ? {} : store.get(k), write: (v, k) => store.set(k, v), info() {}, error() {} },
    ProxyUtils: { parse: (value) => { parseCalls.push(value); assert.equal(value, f.plain); return [{ type: 'vless', name: 'fixture' }] } },
  }
  vm.createContext(context)
  vm.runInContext(fs.readFileSync('public/provider-api-subscription.js', 'utf8'), context)
  if (cached) {
    // Cache keys include the complete config; capture it from the first run.
    context.$substore.read = (k) => k === 'settings' ? {} : k.includes('apex-url:') ? store.get('apex-cache') : store.get(k)
  }
  return { nodes: await context.operator([], '', { raw: 'fixture' }), calls, store, parseCalls }
}

test('Apex mapped API, wrapped legacy URL, certificate purposes and APXS authentication', async () => {
  const f = fixture()
  const result = await runFixture(f, { urlOnly: true })
  assert.equal(result.nodes.length, 1)
  assert.deepEqual(result.calls.map((c) => c.url.hostname), ['oss.test', 'api.test', 'api.test', 'sub.test'])
  assert.deepEqual(result.calls.map((c) => c.url.pathname), ['/config.json', '/custom/login', '/custom/token', '/custom/download'])
  for (const [i, purpose] of ['oss', 'api', 'api', 'subscription'].entries()) {
    const call = result.calls[i]
    assert.equal(call.cert, f.config.apex.mtls[purpose].client_cert_pem)
    assert.equal(call.key, f.config.apex.mtls[purpose].client_key_pem)
    assert.equal(call.rejectUnauthorized, purpose !== 'subscription')
    assert.equal(call.headers['User-Agent'], f.config.headers['User-Agent'])
  }
  assert.equal(result.calls[2].headers.Authorization, 'fixture-auth')
  assert.equal(result.calls[3].headers.Authorization, undefined)
  assert.equal(result.calls[3].url.searchParams.get('key'), 'private-token')
  assert.equal(result.calls[3].url.searchParams.get('flag'), 'apex')
  assert.equal(result.parseCalls.length, 1)
})

test('Apex cached URL still loads signed domains, uses subscription certificate and normalizes flag', async () => {
  const result = await runFixture(fixture(), { cached: true })
  assert.deepEqual(result.calls.map((c) => c.url.hostname), ['oss.test', 'sub.test'])
  assert.equal(result.calls[1].url.searchParams.get('flag'), 'apex')
})

for (const [label, options, expected] of [
  ['tampered config', { badConfig: true }, /配置.*签名校验失败/],
  ['tampered subscription', { subscriptionOptions: { tamper: true } }, /订阅.*签名校验失败/],
  ['wrong profile ID', { subscriptionOptions: { id: 2 } }, /profile\/key ID 不匹配/],
  ['wrong AAD with a valid signature', { subscriptionOptions: { wrongAAD: true } }, /AES-GCM 认证失败/],
  ['wrong AES key with a valid signature', { subscriptionOptions: { wrongKey: true } }, /AES-GCM 认证失败/],
]) {
  test(`Apex rejects ${label}`, async () => { await assert.rejects(runFixture(fixture(), options), expected) })
}

test('Apex rejects keys from another brand', async () => {
  const f = fixture(); const another = fixture()
  await assert.rejects(runFixture(f, { configOverride: { apex: { ...f.config.apex, subscriptionPublicKey: another.config.apex.subscriptionPublicKey } } }), /签名校验失败/)
})

test('Apex requires Node mTLS capabilities and complete purpose-specific bundles', async () => {
  const f = fixture()
  normalizeApex(f.config.apex)
  const broken = structuredClone(f.config.apex)
  broken.mtls.api.purpose = 'oss'
  assert.throws(() => normalizeApex(broken), /用途错误/)
  await assert.rejects(runApexProvider({ config: f.config, runtime: null }), /mTLS/)
})

test('Apex really presents separate client certificates over local TLS', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apex-mtls-test-'))
  const openssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' })
  let server
  try {
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=Apex test CA')
    const ca = fs.readFileSync(path.join(dir, 'ca.crt'))
    const purposes = ['server', 'oss', 'api', 'subscription']
    const credentials = {}
    fs.writeFileSync(path.join(dir, 'ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    for (const purpose of purposes) {
      openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', `${purpose}.key`, '-out', `${purpose}.csr`, '-subj', `/CN=${purpose}`)
      openssl('x509', '-req', '-in', `${purpose}.csr`, '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${purpose}.crt`, '-days', '1', '-extfile', 'ext')
      credentials[purpose] = { cert: fs.readFileSync(path.join(dir, `${purpose}.crt`)), key: fs.readFileSync(path.join(dir, `${purpose}.key`)) }
    }
    const f = fixture()
    const seen = []
    const origin = await new Promise((resolve) => {
      server = https.createServer({ ...credentials.server, ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
        const purpose = req.socket.getPeerCertificate().subject.CN
        seen.push(purpose)
        if (purpose === 'oss') res.end(f.configBody())
        else if (req.url === '/custom/login') res.end(JSON.stringify({ data: { auth_data: 'tls-auth' } }))
        else if (req.url === '/custom/token') res.end(JSON.stringify({ data: { token: 'tls-token' } }))
        else res.end(f.subscription())
      }).listen(0, '127.0.0.1', () => resolve(`https://127.0.0.1:${server.address().port}`))
    })
    f.cfg.domains = [origin]; f.cfg.subscribe_domain = [origin]; f.config.cfgUrls = [origin + '/config.json']
    for (const purpose of ['oss', 'api', 'subscription']) Object.assign(f.config.apex.mtls[purpose], { client_cert_pem: credentials[purpose].cert.toString(), client_key_pem: credentials[purpose].key.toString() })
    globalThis.$substore = { read() {}, write() {}, info() {} }
    globalThis.ProxyUtils = { parse: (value) => { assert.equal(value, f.plain); return [{ type: 'vless' }] } }
    const runtime = { crypto, Buffer, loadModule: (name) => {
      assert.equal(name, 'https')
      return { request: (url, opts, callback) => https.request(url, { ...opts, ca }, callback) }
    } }
    const nodes = await runApexProvider({ config: f.config, runtime, timeout: 3000, sensitiveValues: [], errorMessage: (e) => e.message, cacheKey: 'local-tls' })
    assert.equal(nodes.length, 1)
    assert.deepEqual(seen, ['oss', 'api', 'api', 'subscription'])
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve))
    fs.rmSync(dir, { recursive: true, force: true })
    delete globalThis.$substore; delete globalThis.ProxyUtils
  }
})

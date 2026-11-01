import assert from 'node:assert/strict'
import * as nodeCrypto from 'node:crypto'
import fs from 'node:fs'
import vm from 'node:vm'
import test from 'node:test'

const source = fs.readFileSync('public/provider-api-subscription.js', 'utf8')
const decrypt = {
  key: '4422a60e08c97f30',
  iv: '8c97f304422a60e0',
}
const subscriptionDecrypt = {
  type: 'aes-256-gcm',
  password: '86f2e72ead6e985e',
}
const configText = JSON.stringify({ hosts: ['https://api.example.com'] })
const gcmSubscription = `proxies:\n  - name: portable-gcm\n    type: ss\n# ${'x'.repeat(44 * 1024)}`
const cbcSubscription = 'proxies:\n  - name: portable-cbc\n    type: ss\n'

function encryptNestedCbc(value) {
  const cipher = nodeCrypto.createCipheriv(
    'aes-128-cbc',
    Buffer.from(decrypt.key),
    Buffer.from(decrypt.iv),
  )
  const innerBase64 = Buffer.from(value, 'utf8').toString('base64')
  return Buffer.concat([cipher.update(Buffer.from(innerBase64)), cipher.final()]).toString(
    'base64',
  )
}

function encryptGcm(value, password = subscriptionDecrypt.password) {
  const nonce = Buffer.from('000102030405060708090a0b', 'hex')
  const key = nodeCrypto
    .createHash('sha256')
    .update(Buffer.from(password, 'utf8'))
    .digest()
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, nonce)
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(value, 'utf8')), cipher.final()])
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString('base64')
}

function createProviderConfig() {
  return {
    cfgUrls: ['https://config.example.com/config.json'],
    username: 'user@example.com',
    password: 'test-password',
    headers: {
      'User-Agent': 'securitynet/v3.1.8 clash-verge Platform/windows',
    },
    decrypt,
    subscriptionDecrypt,
  }
}

for (const format of ['seed GCM', 'mirrored Base64']) {
  test(`decodes the official ${format} subscription fallback`, async () => {
    const config = createProviderConfig()
    config.subscriptionDecrypt.password = '66d570165fad0012ba46077644ac1ba6'
    const standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    const mirrored = 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210/+'
    const subscriptionBody = format === 'seed GCM'
      ? encryptGcm(cbcSubscription, config.subscriptionDecrypt.password)
      : Buffer.from(cbcSubscription).toString('base64').replace(/[A-Za-z0-9+/]/g,
        (char) => mirrored[standard.indexOf(char)])
    const result = await runProvider({
      configBody: Buffer.from(configText).toString('base64'),
      subscriptionBody,
      expectedSubscription: cbcSubscription,
      env: { isNode: false },
      config,
    })
    assert.equal(result.nodes.length, 1)
  })
}

async function runProvider({
  configBody,
  subscriptionBody,
  expectedSubscription,
  env,
  globals = {},
  http = {},
  config = createProviderConfig(),
  store = new Map(),
  operatorContext = { raw: 'ignored' },
  subscriptionUuid = '',
}) {
  const requests = []
  const context = {
    console: { log() {}, info() {}, warn() {}, error() {} },
    $arguments: {},
    yaml: { parse: () => config },
    ProxyUtils: {
      parse: (value) =>
        value === expectedSubscription ? [{ name: expectedSubscription.includes('gcm') ? 'gcm' : 'cbc' }] : [],
    },
    ...globals,
  }
  context.$substore = {
    env,
    read: (key) => (key === 'settings' ? {} : store.get(key) || ''),
    write: (value, key) => store.set(key, value),
    info() {},
    error() {},
    http: {
      get: async (options) => {
        const { url } = options
        requests.push({ method: 'get', ...options })
        if (url.includes('config.example.com')) {
          return { statusCode: 200, body: configBody }
        }
        if (url.endsWith('/user/getSubscribe')) {
          return {
            statusCode: 200,
            body: JSON.stringify({
              data: {
                subscribe_url: 'https://subscribe.example.com/client/subscribe?token=test',
                uuid: subscriptionUuid,
              },
            }),
          }
        }
        return { statusCode: 200, body: subscriptionBody }
      },
      post: async (options) => {
        requests.push({ method: 'post', ...options })
        return {
          statusCode: 200,
          body: JSON.stringify({ data: { auth_data: 'test-auth' } }),
        }
      },
      ...http,
    },
  }

  vm.createContext(context)
  vm.runInContext(source, context)
  const nodes = await context.operator([], '', operatorContext)
  return { context, nodes, requests, store }
}

test('pure JavaScript fallback decrypts encrypted cfgUrl and AES-256-GCM subscription', async () => {
  const outcome = await runProvider({
    configBody: encryptNestedCbc(configText),
    subscriptionBody: encryptGcm(gcmSubscription),
    expectedSubscription: gcmSubscription,
    env: { isNode: false, isSurge: true },
  })

  assert.equal(vm.runInContext('typeof crypto', outcome.context), 'undefined')
  assert.equal(vm.runInContext('typeof Buffer', outcome.context), 'undefined')
  assert.equal(vm.runInContext('typeof process', outcome.context), 'undefined')
  assert.deepEqual(outcome.nodes.map((node) => node.name), ['gcm'])
})

test('pure JavaScript fallback decrypts AES-128-CBC final subscription', async () => {
  const outcome = await runProvider({
    configBody: Buffer.from(configText, 'utf8').toString('base64'),
    subscriptionBody: encryptNestedCbc(cbcSubscription),
    expectedSubscription: cbcSubscription,
    env: { isNode: false, isLoon: true },
  })

  assert.deepEqual(outcome.nodes.map((node) => node.name), ['cbc'])
})

test('WebCrypto backend handles CBC configuration and GCM subscription', async () => {
  const calls = []
  const subtle = nodeCrypto.webcrypto.subtle
  const wrappedSubtle = {
    digest: (...args) => {
      calls.push(String(args[0]))
      return subtle.digest(...args)
    },
    importKey: (...args) => {
      calls.push(String(args[2]?.name))
      return subtle.importKey(...args)
    },
    decrypt: (...args) => {
      calls.push(String(args[0]?.name))
      return subtle.decrypt(...args)
    },
  }
  const outcome = await runProvider({
    configBody: encryptNestedCbc(configText),
    subscriptionBody: encryptGcm(gcmSubscription),
    expectedSubscription: gcmSubscription,
    env: { isNode: false, isQX: true },
    globals: { crypto: { subtle: wrappedSubtle } },
  })

  assert.deepEqual(outcome.nodes.map((node) => node.name), ['gcm'])
  assert.ok(calls.includes('AES-CBC'))
  assert.ok(calls.includes('SHA-256'))
  assert.ok(calls.includes('AES-GCM'))
})

test('Node backend keeps using built-in crypto when available', async () => {
  let builtinModuleCalls = 0
  const outcome = await runProvider({
    configBody: encryptNestedCbc(configText),
    subscriptionBody: encryptGcm(gcmSubscription),
    expectedSubscription: gcmSubscription,
    env: { isNode: true },
    globals: {
      Buffer,
      process: {
        env: {},
        getBuiltinModule(name) {
          builtinModuleCalls++
          assert.equal(name, 'crypto')
          return nodeCrypto
        },
      },
    },
  })

  assert.deepEqual(outcome.nodes.map((node) => node.name), ['gcm'])
  assert.equal(builtinModuleCalls, 1)
})

test('subscription failures retain the primary TLS cause and redact credentials and URL tokens', async () => {
  const config = createProviderConfig()
  const privateToken = 'private-subscription-token'
  const error = new Error(`fetch failed for https://subscribe.example.com/client/subscribe?token=${privateToken}&email=${config.username} ${config.password} Authorization: test-auth token: ${privateToken}`)
  error.cause = Object.assign(new Error('certificate hostname mismatch'), {
    code: 'ERR_TLS_CERT_ALTNAME_INVALID',
  })
  await assert.rejects(runProvider({
    config,
    env: { isNode: false },
    http: {
      get: async ({ url }) => {
        if (url.includes('config.example.com')) {
          return { statusCode: 200, body: Buffer.from(configText).toString('base64') }
        }
        if (url.endsWith('/user/getSubscribe')) {
          return { statusCode: 200, body: JSON.stringify({ data: {
            subscribe_url: `https://subscribe.example.com/client/subscribe?token=${privateToken}`,
            token: privateToken,
          } }) }
        }
        if (url.includes('subscribe.example.com')) throw error
        return { statusCode: 401, body: 'invalid token\n' }
      },
    },
  }), (failure) => {
    assert.match(failure.message, /下载订阅 https:\/\/subscribe\.example\.com/)
    assert.match(failure.message, /ERR_TLS_CERT_ALTNAME_INVALID/)
    assert.match(failure.message, /https:\/\/api\.example\.com.*401/)
    assert.ok(!failure.message.includes(privateToken))
    assert.ok(!failure.message.includes(config.username))
    assert.ok(!failure.message.includes(config.password))
    assert.ok(!failure.message.includes('test-auth'))
    return true
  })
})

test('a primary TLS failure still permits a valid API subscription fallback', async () => {
  const outcome = await runProvider({
    expectedSubscription: cbcSubscription,
    env: { isNode: false },
    http: {
      get: async ({ url }) => {
        if (url.includes('config.example.com')) {
          return { statusCode: 200, body: Buffer.from(configText).toString('base64') }
        }
        if (url.endsWith('/user/getSubscribe')) {
          return { statusCode: 200, body: JSON.stringify({ data: {
            subscribe_url: 'https://subscribe.example.com/client/subscribe?token=test',
            token: 'test',
          } }) }
        }
        if (url.includes('subscribe.example.com')) {
          throw Object.assign(new Error('certificate hostname mismatch'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
        }
        return { statusCode: 200, body: cbcSubscription }
      },
    },
  })
  assert.deepEqual(outcome.nodes.map((node) => node.name), ['cbc'])
})

test('login and getSubscribe failures identify their stage and API origin', async () => {
  await assert.rejects(runProvider({
    env: { isNode: false },
    configBody: Buffer.from(configText).toString('base64'),
    http: { post: async () => ({ statusCode: 403, body: 'forbidden' }) },
  }), /登录 https:\/\/api\.example\.com:.*403/)

  await assert.rejects(runProvider({
    env: { isNode: false },
    http: {
      get: async ({ url }) => url.includes('config.example.com')
        ? { statusCode: 200, body: Buffer.from(configText).toString('base64') }
        : { statusCode: 503, body: 'unavailable' },
    },
  }), /获取订阅地址 https:\/\/api\.example\.com:.*503/)
})

for (const env of [{ isNode: true }, { isNode: false, isSurge: true }, { isNode: false, isLoon: true }]) {
  test(`only subscription downloads ignore TLS verification in ${Object.keys(env).filter((key) => env[key]).join('/')}`, async () => {
    const options = {
      env,
      configBody: Buffer.from(configText).toString('base64'),
      subscriptionBody: cbcSubscription,
      expectedSubscription: cbcSubscription,
    }
    const outcome = await runProvider(options)
    const subscription = outcome.requests.find((request) => request.url.includes('subscribe.example.com'))
    assert.ok(subscription)
    if (env.isNode) {
      assert.equal(subscription.strictSSL, false)
    } else {
      assert.equal(subscription.insecure, true)
    }
    for (const request of outcome.requests.filter((request) => request !== subscription)) {
      assert.equal(request.strictSSL, undefined)
      assert.equal(request.insecure, undefined)
    }
    // A subsequent refresh goes through the same TLS settings on the cache path.
    const cached = await runProvider({ ...options, store: outcome.store })
    assert.equal(cached.requests.length, 1)
    assert.equal(cached.requests[0].url, subscription.url)
    assert.equal(cached.requests[0][env.isNode ? 'strictSSL' : 'insecure'], env.isNode ? false : true)
  })
}

test('automatic traffic queries inherit the subscription TLS setting', async () => {
  const store = new Map([['subs', [{ name: 'local-test', source: 'local', content: 'ignored' }]]])
  await runProvider({
    configBody: Buffer.from(configText).toString('base64'),
    subscriptionBody: cbcSubscription,
    expectedSubscription: cbcSubscription,
    env: { isNode: true },
    store,
    operatorContext: { raw: 'ignored', source: { 'local-test': { source: 'local', content: 'ignored' } } },
  })
  const url = store.get('subs')[0].subUserinfo
  const args = JSON.parse(decodeURIComponent(url.split('#')[1]))
  assert.equal(args.providerScriptAutoSubUserinfo, true)
  assert.equal(args.insecure, true)
})

test('HTTP 200 verification pages are reported before decryption or node parsing', async () => {
  let parseCalls = 0
  await assert.rejects(runProvider({
    configBody: Buffer.from(configText).toString('base64'),
    subscriptionBody: '<!DOCTYPE html><html><body>请完成以下操作，验证您是真人</body></html>',
    env: { isNode: false },
    globals: { ProxyUtils: { parse: () => { parseCalls++; return [] } } },
  }), /HTML 验证页或错误页，未收到节点配置/)
  assert.equal(parseCalls, 0)
})


test('API requests use the official API UA independently of subscription headers', async () => {
  const config = createProviderConfig()
  config.headers['X-Subscription-Header'] = 'download-only'
  const { requests } = await runProvider({
    config,
    configBody: Buffer.from(configText).toString('base64'),
    subscriptionBody: cbcSubscription,
    expectedSubscription: cbcSubscription,
    env: { isNode: false },
  })
  const api = requests.filter(({ url }) => url.includes('api.example.com'))
  assert.equal(api.length, 2)
  for (const { headers } of api) {
    assert.equal(headers['User-Agent'], 'Mozilla/5.0 (dart:io) SuperAccelerator')
    assert.equal(headers.Accept, 'application/json')
    assert.equal(headers['X-Subscription-Header'], undefined)
  }
  const download = requests.find(({ url }) => url.includes('subscribe.example.com'))
  assert.equal(download.headers['User-Agent'], config.headers['User-Agent'])
  assert.equal(download.headers['X-Subscription-Header'], 'download-only')
  assert.equal(download.headers.Authorization, undefined)
})

const sn2Uuid = '0b4e46c5-bde6-4128-a713-29438bd142ae'
const sn2Password = `66d570165fad0012ba46077644ac1ba6${sn2Uuid}`
const sn2Options = {
  configBody: Buffer.from(configText).toString('base64'),
  expectedSubscription: cbcSubscription,
  subscriptionUuid: sn2Uuid,
}
function sn2Body(expiresAt = Math.floor(Date.now() / 1000) + 3600, password = sn2Password) {
  return `SN2.${expiresAt}.${encryptGcm(cbcSubscription, password)}`
}

for (const [runtime, env, globals] of [
  ['pure JavaScript', { isNode: false }, {}],
  ['WebCrypto', { isNode: false }, { crypto: nodeCrypto.webcrypto }],
  ['Node', { isNode: true }, { process, Buffer }],
]) {
  test(`${runtime} decrypts SN2 with account UUID and preserves cached refresh`, async () => {
    const options = { ...sn2Options, subscriptionBody: sn2Body(), env, globals }
    const first = await runProvider(options)
    assert.equal(first.nodes.length, 1)
    const second = await runProvider({ ...options, store: first.store })
    assert.equal(second.nodes.length, 1)
    assert.equal(second.requests.length, 1)
    assert.ok(second.requests[0].url.includes('subscribe.example.com'))
  })
}

test('an old URL cache without UUID refreshes login before decrypting SN2', async () => {
  const options = { ...sn2Options, subscriptionBody: sn2Body(), env: { isNode: false } }
  const first = await runProvider(options)
  for (const key of first.store.keys()) if (key.startsWith('provider-api-subscription:uuid:')) first.store.delete(key)
  const second = await runProvider({ ...options, store: first.store })
  assert.equal(second.nodes.length, 1)
  assert.equal(second.requests.filter(({ method }) => method === 'post').length, 1)
})

test('SN2 uses the extracted seed and trimmed account UUID', async () => {
  const config = createProviderConfig()
  config.subscriptionDecrypt.password = '0123456789abcdef02468ace13579bdf'
  const result = await runProvider({
    ...sn2Options,
    config,
    subscriptionUuid: `  ${sn2Uuid}  `,
    subscriptionBody: sn2Body(undefined, `${config.subscriptionDecrypt.password}${sn2Uuid}`),
    env: { isNode: false },
  })
  assert.equal(result.nodes.length, 1)
})

test('SN2 rejects missing UUID, expired envelopes and corrupted ciphertext', async () => {
  for (const [subscriptionBody, subscriptionUuid, message] of [
    [sn2Body(), '', /SN2.*UUID/],
    [sn2Body(1), sn2Uuid, /SN2.*已过期/],
    ['SN2.invalid.payload', sn2Uuid, /SN2.*封装格式无效/],
    [sn2Body(undefined, 'wrong-account-key'), sn2Uuid, /订阅获取失败/],
  ]) {
    let parseCalls = 0
    await assert.rejects(runProvider({
      ...sn2Options,
      subscriptionBody,
      subscriptionUuid,
      env: { isNode: false },
      globals: { ProxyUtils: { parse: () => { parseCalls++; return [] } } },
    }), (error) => {
      assert.match(error.message, message)
      assert.ok(!error.message.includes(sn2Uuid))
      return true
    })
    assert.equal(parseCalls, 0)
  }
})

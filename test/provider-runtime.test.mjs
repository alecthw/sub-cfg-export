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

function encryptGcm(value) {
  const nonce = Buffer.from('000102030405060708090a0b', 'hex')
  const key = nodeCrypto
    .createHash('sha256')
    .update(Buffer.from(subscriptionDecrypt.password, 'utf8'))
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

async function runProvider({
  configBody,
  subscriptionBody,
  expectedSubscription,
  env,
  globals = {},
}) {
  const requests = []
  const context = {
    console: { log() {}, info() {}, warn() {}, error() {} },
    $arguments: {},
    yaml: { parse: () => createProviderConfig() },
    ProxyUtils: {
      parse: (value) =>
        value === expectedSubscription ? [{ name: expectedSubscription.includes('gcm') ? 'gcm' : 'cbc' }] : [],
    },
    ...globals,
  }
  context.$substore = {
    env,
    read: (key) => (key === 'settings' ? {} : ''),
    write() {},
    info() {},
    error() {},
    http: {
      get: async ({ url, headers = {} }) => {
        requests.push({ url, headers })
        if (url.includes('config.example.com')) {
          return { statusCode: 200, body: configBody }
        }
        if (url.endsWith('/user/getSubscribe')) {
          return {
            statusCode: 200,
            body: JSON.stringify({
              data: {
                subscribe_url: 'https://subscribe.example.com/client/subscribe?token=test',
              },
            }),
          }
        }
        return { statusCode: 200, body: subscriptionBody }
      },
      post: async () => ({
        statusCode: 200,
        body: JSON.stringify({ data: { auth_data: 'test-auth' } }),
      }),
    },
  }

  vm.createContext(context)
  vm.runInContext(source, context)
  const nodes = await context.operator([], '', { raw: 'ignored' })
  return { context, nodes, requests }
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

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { extractInfo } from '../src/lib/extractor.ts'

function unsigned(value) {
  const bytes = []
  while (value > 127) {
    bytes.push(value % 128)
    value = Math.floor(value / 128)
  }
  return [...bytes, value + 128]
}

function signed(value) {
  const bytes = []
  while (value > 63) {
    bytes.push(value % 128)
    value = Math.floor(value / 128)
  }
  return [...bytes, value + 192]
}

function reference(value) {
  const bytes = [value % 128 + 128]
  while ((value = Math.floor(value / 128)) > 0) bytes.unshift(value % 128)
  return bytes
}

const urls = ['tcdn.example.com', 'api.example.com', 'cdno.example.com', 'ocdn.example.com']
  .map((host) => `https://${host}/saos/xmtz_news.json`)
const key = '4422a60e08c97f30'
const iv = '8c97f304422a60e0'

function snapshot({ modern, precedingKeys = modern, invalidPrefix = false, seed }) {
  const numBase = 7
  const stringCount = 128
  const prefixCount = modern ? 3 : 0
  const firstIntegerRef = 1 + numBase + prefixCount + stringCount
  const bytes = []
  if (modern) {
    bytes.push(...signed((61 << 12) | 0x82), ...unsigned(1), ...signed(0))
    bytes.push(...signed(((invalidPrefix ? 999 : 91) << 12) | 0x82), ...unsigned(2))
    bytes.push(...unsigned(0), ...unsigned(0))
  }
  bytes.push(...signed(modern ? (93 << 12) | 0x82 : 2), ...unsigned(stringCount))
  for (let index = 0; index < stringCount; index += 1) bytes.push(...unsigned(1))
  bytes.push(...unsigned(256), ...unsigned(stringCount))
  bytes.push(...signed(modern ? (61 << 12) | 0x82 : 4), ...unsigned(modern ? 255 : 256))
  for (let value = modern ? 1 : 0; value <= 255; value += 1) bytes.push(...signed(value))

  function array(text, mask = 0) {
    bytes.push(...unsigned(text.length), ...reference(1))
    for (const char of text) {
      const value = char.charCodeAt(0) ^ mask
      const ref = modern && value === 0 ? 1 + numBase : firstIntegerRef + value - (modern ? 1 : 0)
      bytes.push(...reference(ref))
    }
  }
  if (precedingKeys) { array(iv); array(key) }
  for (const url of urls) array(url, 46) // '.' XOR 46 references the leading Mint(0).
  if (!precedingKeys) { array(iv); array(key) }
  if (seed) {
    const chars = [...seed].map((char) => char.charCodeAt(0))
    const third = chars.slice(20).map((value, index) => {
      const shift = index % 5 + 1
      return (((value << shift) | (value >>> (8 - shift))) & 255) ^ 0xa7
    })
    const second = chars.slice(10, 20).map((value, index) => (value + 0x3c + index) & 255)
    const first = chars.slice(0, 10).map((value, index) => value ^ 0x5a ^ ((index + 0xc3) & 255))
    for (const part of [third, second, first]) array(String.fromCharCode(...part))
  }
  bytes.push(...new Uint8Array(32))

  const header = Buffer.alloc(52)
  header.set([0xf5, 0xf5, 0xdc, 0xdc])
  header.writeBigInt64LE(2n, 12)
  header.write('0'.repeat(32), 20)
  const payload = Buffer.concat([
    header,
    Buffer.from('product x64 windows no-compressed-pointers\0'),
    Buffer.from([numBase, 1000, 100, 0, 0].flatMap(unsigned)),
    Buffer.from(bytes),
  ])
  payload.writeBigInt64LE(BigInt(payload.length - 4), 4)
  return payload
}

for (const modern of [false, true]) {
  test(`${modern ? 'Dart 3.13' : 'legacy Dart'} extracts split transformed subscription seed`, () => {
    const seed = '0123456789abcdef02468ace13579bdf'
    const payload = snapshot({ modern, seed })
    const expected = { type: 'aes-256-gcm', password: seed }
    assert.deepEqual(extractInfo(new Uint8Array(), payload).subscriptionDecrypt, expected)
    const result = spawnSync('python3', ['-B', '-c', `
import sys, json, getinfo
passwords = []
getinfo._select_snapshot_info(sys.stdin.buffer.read(), passwords)
print(json.dumps(passwords))
`], { input: payload, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), [seed])
  })
}

for (const modern of [false, true]) {
  test(`${modern ? 'Dart 3.13' : 'legacy Dart'} restores XOR URLs and actual key/iv`, () => {
    const payload = snapshot({ modern })
    const info = extractInfo(new Uint8Array(), payload)
    assert.deepEqual(info.cfgUrls, urls)
    assert.deepEqual(info.decrypt, { key, iv })

    // Keep the standalone Python extractor in agreement with the browser.
    const result = spawnSync('python3', ['-c', `
import sys
sys.dont_write_bytecode = True
import getinfo, json
data = sys.stdin.buffer.read()
urls, values = getinfo._select_snapshot_info(data)
selected = getinfo._select_config_urls([], urls)
print(json.dumps({"cfgUrls": selected, "decrypt": getinfo._select_decrypt_values(selected, urls, values)}))
`], { input: payload, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), { cfgUrls: info.cfgUrls, decrypt: info.decrypt })
  })
}

test('Dart 3.13 also supports keys following the URLs', () => {
  assert.deepEqual(extractInfo(new Uint8Array(), snapshot({ modern: true, precedingKeys: false })).decrypt,
    { key, iv })
})

test('unsupported leading clusters fail without guessing reference IDs', () => {
  assert.throws(() => extractInfo(new Uint8Array(), snapshot({ modern: true, invalidPrefix: true })),
    /未找到配置 JSON URL/)
})

test('truncated snapshots do not yield configuration', () => {
  assert.throws(() => extractInfo(new Uint8Array(), snapshot({ modern: true }).subarray(0, 200)),
    /未找到配置 JSON URL/)
})

for (const brand of ['NetFlow', 'SecurityNet', 'securitynet']) {
  test(`preserves ${brand} brand spelling in the client UA`, () => {
    const installer = Buffer.from('ProductVersion\0 3.2.1\0', 'utf16le')
    const payload = Buffer.concat([
      snapshot({ modern: true }),
      Buffer.from(`${brand}\0clash-verge\0Platform/windows\0`),
    ])
    const expected = `${brand}/v3.2.1 clash-verge Platform/windows`
    assert.equal(extractInfo(installer, payload).userAgent, expected)
    const result = spawnSync('python3', ['-B', '-c', `
import sys, getinfo
print(getinfo._extract_user_agent(bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2])) )
`, installer.toString('hex'), payload.toString('hex')], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), expected)
  })
}

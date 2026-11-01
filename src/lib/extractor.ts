import type { DecryptInfo, ExtractedInfo, SubscriptionDecryptInfo } from '../types'

const URL_JSON_RE =
  /https?:\/\/(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?\/[A-Za-z0-9._~!$&()*+,;=:@%/+\-]*?\.json/gi
const FULL_URL_JSON_RE =
  /^https?:\/\/(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?\/[A-Za-z0-9._~!$&()*+,;=:@%/+\-]*?\.json$/i
const HEX16_RE = /^[0-9a-fA-F]{16}$/
const SNAPSHOT_MAGIC = new Uint8Array([0xf5, 0xf5, 0xdc, 0xdc])
const textDecoder = new TextDecoder('windows-1252')
const utf16Decoder = new TextDecoder('utf-16le')
const DEFAULT_USER_AGENT = 'NetFlow/v2.2.4 clash-verge Platform/windows'
const USER_AGENT_BRANDS = [
  { value: 'NetFlow', bytes: new TextEncoder().encode('NetFlow') },
  { value: 'SecurityNet', bytes: new TextEncoder().encode('SecurityNet') },
  { value: 'securitynet', bytes: new TextEncoder().encode('securitynet') },
]
const CLASH_VERGE = new TextEncoder().encode('clash-verge')
const PLATFORM_WINDOWS = new TextEncoder().encode('Platform/windows')
const PLATFORM_LINUX = new TextEncoder().encode('Platform/linux')
const PRODUCT_VERSION_UTF16 = new Uint8Array(
  [...'ProductVersion'].flatMap((character) => [character.charCodeAt(0), 0]),
)

interface SnapshotInfo {
  start: number
  end: number
  clusterPos: number
  numBase: number
  numObjects: number
  numClusters: number
}

interface PositionedValue {
  pos: number
  value: string
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)]
}

function bytesEqualAt(data: Uint8Array, needle: Uint8Array, pos: number): boolean {
  if (pos < 0 || pos + needle.length > data.length) return false
  for (let index = 0; index < needle.length; index += 1) {
    if (data[pos + index] !== needle[index]) return false
  }
  return true
}

export function findSequence(
  data: Uint8Array,
  needle: Uint8Array,
  start = 0,
  end = data.length,
): number {
  const stop = Math.min(end, data.length) - needle.length
  for (let pos = Math.max(0, start); pos <= stop; pos += 1) {
    if (bytesEqualAt(data, needle, pos)) return pos
  }
  return -1
}

function readUnsigned(data: Uint8Array, pos: number, end: number): [number, number] {
  let value = 0
  let shift = 0
  while (pos < end && shift <= 63) {
    const byte = data[pos]
    pos += 1
    if (byte > 0x7f) {
      return [value + (byte - 0x80) * 2 ** shift, pos]
    }
    value += byte * 2 ** shift
    shift += 7
  }
  throw new Error('Dart compact unsigned integer 数据不完整')
}

function readCompactSigned(
  data: Uint8Array,
  pos: number,
  end: number,
  bits: 32 | 64,
): [bigint, number] {
  let value = 0n
  let shift = 0n
  while (pos < end && shift < BigInt(bits)) {
    const byte = data[pos]
    pos += 1
    if (byte > 0x7f) {
      value |= BigInt(byte - 0xc0) << shift
      const width = BigInt(bits)
      const mask = (1n << width) - 1n
      value &= mask
      if ((value & (1n << (width - 1n))) !== 0n) {
        value -= 1n << width
      }
      return [value, pos]
    }
    value |= BigInt(byte) << shift
    shift += 7n
  }
  throw new Error('Dart compact signed integer 数据不完整')
}

function readRefId(data: Uint8Array, pos: number, end: number): [number, number] {
  let value = 0
  for (let count = 0; count < 4; count += 1) {
    if (pos >= end) throw new Error('Dart reference id 数据不完整')
    const byte = data[pos]
    pos += 1
    const signedByte = byte < 0x80 ? byte : byte - 0x100
    value = signedByte + value * 128
    if (signedByte < 0) return [value + 0x80, pos]
  }
  throw new Error('Dart reference id 无效')
}

function readInt64LE(data: Uint8Array, pos: number): bigint {
  const view = new DataView(data.buffer, data.byteOffset + pos, 8)
  return view.getBigInt64(0, true)
}

function extractJsonUrls(data: Uint8Array): string[] {
  const urls: string[] = []
  const chunkSize = 4 * 1024 * 1024
  const overlap = 2048

  for (let start = 0; start < data.length; start += chunkSize) {
    const from = Math.max(0, start - overlap)
    const to = Math.min(data.length, start + chunkSize + overlap)
    const text = textDecoder.decode(data.subarray(from, to))
    URL_JSON_RE.lastIndex = 0
    for (const match of text.matchAll(URL_JSON_RE)) {
      if (!match[0]) continue
      try {
        const parsed = new URL(match[0])
        if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname) {
          urls.push(match[0])
        }
      } catch {
        // Ignore malformed strings from unrelated binary data.
      }
    }
  }

  return unique(urls)
}

function snapshotCandidates(data: Uint8Array): SnapshotInfo[] {
  const candidates: SnapshotInfo[] = []
  let searchPos = 0

  while (searchPos < data.length) {
    const start = findSequence(data, SNAPSHOT_MAGIC, searchPos)
    if (start < 0) break
    searchPos = start + 1

    try {
      if (start + 52 >= data.length) continue
      const storedLength = readInt64LE(data, start + 4)
      const totalLengthBig = storedLength + 4n
      if (totalLengthBig < 128n || totalLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) continue
      const totalLength = Number(totalLengthBig)
      if (start + totalLength > data.length) continue

      const version = textDecoder.decode(data.subarray(start + 20, start + 52))
      if (!/^[0-9a-f]{32}$/.test(version)) continue

      let featuresEnd = -1
      const featureLimit = Math.min(start + 4096, data.length)
      for (let pos = start + 52; pos < featureLimit; pos += 1) {
        if (data[pos] === 0) {
          featuresEnd = pos
          break
        }
      }
      if (featuresEnd < 0) continue

      let pos = featuresEnd + 1
      const values: number[] = []
      for (let index = 0; index < 5; index += 1) {
        const [value, next] = readUnsigned(data, pos, start + totalLength)
        values.push(value)
        pos = next
      }

      const [numBase, numObjects, numClusters] = values
      if (numObjects <= numBase || numClusters <= 0) continue
      candidates.push({
        start,
        end: start + totalLength,
        clusterPos: pos,
        numBase,
        numObjects,
        numClusters,
      })
    } catch {
      // A magic-looking byte sequence in unrelated data is not a snapshot.
    }
  }

  return candidates
}

function parseSmallIntegerRefs(
  data: Uint8Array,
  snapshot: SnapshotInfo,
): [Map<number, number>, number] {
  let pos = snapshot.clusterPos
  const end = snapshot.end

  const [stringTagsBig, afterStringTags] = readCompactSigned(data, pos, end, 32)
  pos = afterStringTags
  let stringTags = Number(stringTagsBig)
  const modernTags = stringTags >= 0x1000
  let firstRef = 1 + snapshot.numBase
  const refValues = new Map<number, number>()

  // Dart 3.13 stores the object-header class ID in bits 12..31. Empty
  // singleton clusters can precede String, including Mint(0); their objects
  // still consume reference IDs and zero is needed for XOR-encoded URLs.
  if (modernTags) {
    const sizedClusters = new Set([23, 24, 25, 26, 27, 28, 30, 90, 91])
    let clusterCount = 0
    while (Math.floor(stringTags / 0x1000) !== 93) {
      if (++clusterCount >= snapshot.numClusters) throw new Error('未找到 Dart String cluster')
      const cid = Math.floor(stringTags / 0x1000)
      if (cid !== 61 && !sizedClusters.has(cid)) throw new Error('不支持的 Dart 前导 cluster')
      let count: number
      ;[count, pos] = readUnsigned(data, pos, end)
      if (count > snapshot.numObjects - firstRef + 1) throw new Error('Dart cluster 对象数量无效')
      for (let index = 0; index < count; index += 1) {
        if (cid === 61) {
          let value: bigint
          ;[value, pos] = readCompactSigned(data, pos, end, 64)
          if (value >= 0n && value <= 255n) refValues.set(firstRef + index, Number(value))
        } else {
          ;[, pos] = readUnsigned(data, pos, end)
        }
      }
      firstRef += count
      let tags: bigint
      ;[tags, pos] = readCompactSigned(data, pos, end, 32)
      stringTags = Number(tags)
    }
  }
  let stringCount: number
  ;[stringCount, pos] = readUnsigned(data, pos, end)
  if (stringCount < 100 || stringCount > snapshot.numObjects) {
    throw new Error('Dart String cluster 不符合预期')
  }

  for (let index = 0; index < stringCount; index += 1) {
    ;[, pos] = readUnsigned(data, pos, end)
  }

  if ((stringTags & 0x02) !== 0) {
    ;[, pos] = readUnsigned(data, pos, end)
    let firstElement: number
    ;[firstElement, pos] = readUnsigned(data, pos, end)
    if (firstElement > stringCount) throw new Error('Dart canonical String layout 无效')
    for (let index = 0; index < stringCount - firstElement; index += 1) {
      ;[, pos] = readUnsigned(data, pos, end)
    }
  }

  let integerTags: bigint
  ;[integerTags, pos] = readCompactSigned(data, pos, end, 32)
  if (modernTags && (Number(integerTags) >>> 12) !== 61) {
    throw new Error('Dart Mint cluster 不符合预期')
  }
  let integerCount: number
  ;[integerCount, pos] = readUnsigned(data, pos, end)
  if (integerCount < 128 || integerCount > snapshot.numObjects) {
    throw new Error('Dart integer cluster 不符合预期')
  }

  firstRef += stringCount
  for (let index = 0; index < integerCount; index += 1) {
    let value: bigint
    ;[value, pos] = readCompactSigned(data, pos, end, 64)
    if (value >= 0n && value <= 255n) {
      refValues.set(firstRef + index, Number(value))
    }
  }

  if (refValues.size < 64) throw new Error('Dart integer cluster 缺少字节字符集')
  return [refValues, pos]
}

function decodeSmiArrays(
  data: Uint8Array,
  snapshot: SnapshotInfo,
): {
  urls: PositionedValue[]
  hexValues: PositionedValue[]
  obfuscatedHexValues: PositionedValue[]
} {
  let refValues: Map<number, number>
  let scanStart: number
  try {
    ;[refValues, scanStart] = parseSmallIntegerRefs(data, snapshot)
  } catch {
    return { urls: [], hexValues: [], obfuscatedHexValues: [] }
  }

  const urls: PositionedValue[] = []
  const hexValues: PositionedValue[] = []
  const obfuscatedHexValues: PositionedValue[] = []
  const end = snapshot.end

  for (let candidatePos = scanStart; candidatePos < end - 12; candidatePos += 1) {
    let length: number
    let pos: number
    try {
      ;[length, pos] = readUnsigned(data, candidatePos, end)
    } catch {
      continue
    }
    if (length < 8 || length > 512) continue

    let typeRef: number
    try {
      ;[typeRef, pos] = readRefId(data, pos, end)
    } catch {
      continue
    }
    if (typeRef <= 0 || typeRef > snapshot.numObjects) continue

    const values = new Uint8Array(length)
    let valid = true
    for (let index = 0; index < length; index += 1) {
      try {
        let refId: number
        ;[refId, pos] = readRefId(data, pos, end)
        const value = refValues.get(refId)
        if (value === undefined) {
          valid = false
          break
        }
        values[index] = value
      } catch {
        valid = false
        break
      }
    }
    if (!valid) continue

    // SecurityNet stores its 32-byte seed as adjacent 12/10/10-byte arrays.
    // Each part uses a different transform; their decoded order is reversed.
    if (length === 12) {
      try {
        const parts: Uint8Array[] = [values]
        let nextPos = pos
        for (let part = 0; part < 2; part += 1) {
          let nextLength: number
          ;[nextLength, nextPos] = readUnsigned(data, nextPos, end)
          if (nextLength !== 10) throw new Error('unexpected seed part')
          let nextType: number
          ;[nextType, nextPos] = readRefId(data, nextPos, end)
          if (nextType <= 0 || nextType > snapshot.numObjects) throw new Error('invalid seed type')
          const bytes = new Uint8Array(10)
          for (let index = 0; index < 10; index += 1) {
            let ref: number
            ;[ref, nextPos] = readRefId(data, nextPos, end)
            const value = refValues.get(ref)
            if (value === undefined) throw new Error('invalid seed byte')
            bytes[index] = value
          }
          parts.push(bytes)
        }
        const first = parts[2].map((value, index) => value ^ 0x5a ^ ((index + 0xc3) & 0xff))
        const second = parts[1].map((value, index) => (value - 0x3c - index) & 0xff)
        const third = parts[0].map((value, index) => {
          const byte = value ^ 0xa7
          const shift = (index % 5) + 1
          return ((byte >>> shift) | (byte << (8 - shift))) & 0xff
        })
        const seed = textDecoder.decode(new Uint8Array([...first, ...second, ...third]))
        if (/^[0-9a-f]{32}$/.test(seed)) obfuscatedHexValues.push({ pos: candidatePos, value: seed })
      } catch {
        // Other 12-byte arrays are unrelated to subscription encryption.
      }
    }

    const masks = new Set([0, values[0] ^ 'h'.charCodeAt(0), values[0] ^ 'H'.charCodeAt(0)])
    for (const mask of masks) {
      const decoded = new Uint8Array(values.length)
      for (let index = 0; index < values.length; index += 1) {
        decoded[index] = values[index] ^ mask
      }
      const text = textDecoder.decode(decoded)
      if (FULL_URL_JSON_RE.test(text)) {
        urls.push({ pos: candidatePos, value: text })
      }
    }

    if (length === 16) {
      const text = textDecoder.decode(values)
      if (HEX16_RE.test(text) && text.toLowerCase() !== '0123456789abcdef') {
        hexValues.push({ pos: candidatePos, value: text.toLowerCase() })
      }

      const decodedCandidates: string[] = []
      for (let mask = 1; mask <= 0xff; mask += 1) {
        const decoded = new Uint8Array(values.length)
        for (let index = 0; index < values.length; index += 1) {
          decoded[index] = values[index] ^ mask
        }
        const decodedText = textDecoder.decode(decoded)
        if (HEX16_RE.test(decodedText)) decodedCandidates.push(decodedText.toLowerCase())
      }
      const decodedHexValues = unique(decodedCandidates)
      if (decodedHexValues.length === 1) {
        obfuscatedHexValues.push({ pos: candidatePos, value: decodedHexValues[0] })
      }
    }
  }

  return { urls, hexValues, obfuscatedHexValues }
}

function selectSnapshotInfo(data: Uint8Array): {
  urls: PositionedValue[]
  hexValues: PositionedValue[]
  obfuscatedHexValues: PositionedValue[]
} {
  const snapshots = snapshotCandidates(data).sort(
    (left, right) =>
      right.numClusters - left.numClusters || right.numObjects - left.numObjects,
  )
  for (const snapshot of snapshots) {
    if (snapshot.numClusters < 100) continue
    const result = decodeSmiArrays(data, snapshot)
    if (result.urls.length > 0) return result
  }
  return { urls: [], hexValues: [], obfuscatedHexValues: [] }
}

function basename(url: string): string {
  const path = new URL(url).pathname
  return path.slice(path.lastIndexOf('/') + 1).toLowerCase()
}

function selectConfigUrls(allUrls: string[], dartUrls: PositionedValue[]): string[] {
  const preferred = dartUrls.map((item) => item.value)
  const source = preferred.length > 0 ? preferred : allUrls
  if (source.length === 0) throw new Error('未找到配置 JSON URL')

  const groups = new Map<string, string[]>()
  for (const url of source) {
    const name = basename(url)
    const list = groups.get(name) ?? []
    list.push(url)
    groups.set(name, list)
  }

  const scored = [...groups.entries()].sort(([leftName, leftUrls], [rightName, rightUrls]) => {
    const leftHosts = new Set(leftUrls.map((url) => new URL(url).hostname)).size
    const rightHosts = new Set(rightUrls.map((url) => new URL(url).hostname)).size
    const leftHint = /config|news|oss/.test(leftName) ? 1 : 0
    const rightHint = /config|news|oss/.test(rightName) ? 1 : 0
    return (
      rightHosts - leftHosts ||
      unique(rightUrls).length - unique(leftUrls).length ||
      rightHint - leftHint ||
      rightName.length - leftName.length
    )
  })

  let selected = unique(scored[0][1])
  const originalRank = new Map(selected.map((url, index) => [url, index]))
  const hostRank = new Map<string, number>()
  for (const url of selected) {
    const host = new URL(url).hostname
    if (!hostRank.has(host)) hostRank.set(host, hostRank.size)
  }

  selected.sort((left, right) => {
    const leftUrl = new URL(left)
    const rightUrl = new URL(right)
    return (
      (hostRank.get(leftUrl.hostname) ?? 0) - (hostRank.get(rightUrl.hostname) ?? 0) ||
      (leftUrl.protocol === 'http:' ? 0 : 1) - (rightUrl.protocol === 'http:' ? 0 : 1) ||
      (originalRank.get(left) ?? 0) - (originalRank.get(right) ?? 0)
    )
  })

  const hosts = selected.map((url) => new URL(url).hostname)
  if (
    selected.length === 4 &&
    hosts.some((host) => host.startsWith('tcdn.')) &&
    hosts.some((host) => host.startsWith('api')) &&
    hosts.some((host) => host.startsWith('cdno')) &&
    hosts.some((host) => host.startsWith('ocdn'))
  ) {
    const priority = (url: string) => {
      const host = new URL(url).hostname
      if (host.startsWith('tcdn.')) return 0
      if (host.startsWith('api')) return 1
      if (host.startsWith('cdno')) return 2
      if (host.startsWith('ocdn')) return 3
      return 4
    }
    selected = [...selected].sort((left, right) => priority(left) - priority(right))
  }

  return selected
}

function selectDecryptValues(
  selectedUrls: string[],
  dartUrls: PositionedValue[],
  hexValues: PositionedValue[],
): DecryptInfo | null {
  const selectedSet = new Set(selectedUrls)
  const positions = dartUrls
    .filter((item) => selectedSet.has(item.value))
    .map((item) => item.pos)
  if (positions.length === 0) return null

  const liteFamily =
    selectedUrls.length === 4 &&
    selectedUrls.every((url) => /\/saos\/(?:xjkp|xmtz)_news\.json$/i.test(new URL(url).pathname))
  if (liteFamily) {
    const lastUrlPos = Math.max(...positions)
    const nearby = hexValues
      .filter(
        (item) =>
          item.pos - lastUrlPos > 0 &&
          item.pos - lastUrlPos <= 64 * 1024,
      )
      .sort((left, right) => left.pos - right.pos)
    const iv = nearby[0]?.value
    const key = nearby[1]?.value
    if (iv && key && iv !== key) return { key, iv }
  }

  // Newer lite builds use the same preceding IV/key layout as other clients.
  const firstUrlPos = Math.min(...positions)
  const nearby = hexValues
    .filter((item) => firstUrlPos - item.pos > 0 && firstUrlPos - item.pos <= 4096)
    .sort((left, right) => left.pos - right.pos)
  const iv = nearby.at(-2)?.value
  const key = nearby.at(-1)?.value
  if (!iv || !key || iv === key) return null
  return { key, iv }
}

function selectSubscriptionDecrypt(
  obfuscatedHexValues: PositionedValue[],
): SubscriptionDecryptInfo | null {
  const passwords = unique(obfuscatedHexValues.map((item) => item.value))
  if (passwords.length !== 1) return null
  return { type: 'aes-256-gcm', password: passwords[0] }
}

function extractProductVersion(installer: Uint8Array): string | null {
  let searchPos = 0
  while (searchPos < installer.length) {
    const markerPos = findSequence(installer, PRODUCT_VERSION_UTF16, searchPos)
    if (markerPos < 0) return null
    const text = utf16Decoder.decode(
      installer.subarray(markerPos, Math.min(installer.length, markerPos + 512)),
    )
    const version = text.match(/\d+\.\d+\.\d+/)?.[0]
    if (version) return version
    searchPos = markerPos + PRODUCT_VERSION_UTF16.length
  }
  return null
}

function extractUserAgent(installer: Uint8Array, payload: Uint8Array): string {
  const brand = USER_AGENT_BRANDS.find(({ bytes }) => findSequence(payload, bytes) >= 0)?.value
  const version = extractProductVersion(installer)
  const hasClashVerge = findSequence(payload, CLASH_VERGE) >= 0
  const platform =
    findSequence(payload, PLATFORM_WINDOWS) >= 0
      ? 'windows'
      : findSequence(payload, PLATFORM_LINUX) >= 0
        ? 'linux'
        : null
  if (!brand || !version || !hasClashVerge || !platform) return DEFAULT_USER_AGENT
  return `${brand}/v${version} clash-verge Platform/${platform}`
}

function extractApex(data: Uint8Array, installer: Uint8Array): ExtractedInfo | null {
  if (findSequence(data, new TextEncoder().encode('apex-config-v1')) < 0) return null
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  for (const snapshot of snapshotCandidates(data).sort((a, b) => b.numClusters - a.numClusters)) {
    if (snapshot.numClusters < 100) continue
    const end = snapshot.end
    let pos = snapshot.clusterPos
    let tags: bigint
    ;[tags, pos] = readCompactSigned(data, pos, end, 32)
    if (Number(tags >> 12n) !== 93) continue
    let count: number
    ;[count, pos] = readUnsigned(data, pos, end)
    if (count > snapshot.numObjects) continue
    const image = Math.ceil(end / 64) * 64
    const strings = new Map<number, string>()
    let offset = 0
    for (let index = 0; index < count; index++) {
      let delta: number
      ;[delta, pos] = readUnsigned(data, pos, end)
      offset += delta * 16
      const address = image + offset
      if (address + 16 > data.length) throw new Error('Apex Dart 字符串地址越界')
      const cid = view.getUint32(address, true) >>> 12
      const length = Number(view.getBigUint64(address + 8, true) / 2n)
      const width = cid === 94 ? 1 : 2
      if (![94, 95].includes(cid) || length > 100000 || address + 16 + length * width > data.length) {
        throw new Error('Apex Dart 字符串对象无效')
      }
      const value = (width === 1 ? textDecoder : utf16Decoder).decode(data.subarray(address + 16, address + 16 + length * width))
      strings.set(snapshot.numBase + 1 + index, value)
    }
    let best: Array<string | undefined> = []
    pos = snapshot.clusterPos
    while (pos < end) {
      const start = pos
      const refs: Array<string | undefined> = []
      try {
        while (pos < end) {
          const bits = data[pos++]
          const type = bits & 15
          const behavior = bits >>> 5
          let ref: number | undefined
          if (![0, 1, 2].includes(type)) throw new Error('pool end')
          if (!behavior) {
            if (type === 1) {
              ;[ref, pos] = readRefId(data, pos, end)
              if (ref <= 0 || ref > snapshot.numObjects) throw new Error('pool ref')
            } else if (type === 0) {
              ;[, pos] = readCompactSigned(data, pos, end, 64)
            }
          }
          refs.push(ref === undefined ? undefined : strings.get(ref))
        }
      } catch { /* End of a candidate pool. */ }
      if (refs.length > best.length) best = refs
      pos = Math.max(start + 1, pos)
    }
    const ci = best.indexOf('apex-config-v1')
    const si = best.indexOf('apex-sub-sign-v2\0')
    if (ci < 0 || si < 3) continue
    const keys = unique(best.filter((v): v is string => typeof v === 'string' && /^[A-Za-z0-9]{32}$/.test(v) && (v.match(/[0-9]/g)?.length ?? 0) >= 2 && /[A-Z]/.test(v) && /[a-z]/.test(v)))
    if (keys.length !== 1) throw new Error('Apex XOR 密钥不唯一，无法可靠提取')
    const mtls = {} as import('../types').ApexInfo['mtls']
    for (const value of strings.values()) {
      if (!value.startsWith('eyJ') || value.length < 500) continue
      try {
        const bundle = JSON.parse(atob(value))
        if (bundle.version === 1 && ['oss', 'api', 'subscription'].includes(bundle.purpose)) {
          mtls[bundle.purpose as keyof typeof mtls] = bundle
        }
      } catch { /* Other Base64 constants are unrelated. */ }
    }
    if (Object.keys(mtls).length !== 3 || new Set(Object.values(mtls).map((v) => v.profile_id)).size !== 1) {
      throw new Error('Apex 客户端证书不完整或品牌不一致')
    }
    const apex: import('../types').ApexInfo = {
      xorKey: keys[0], configPublicKey: best[ci + 1] ?? '',
      subscriptionPublicKey: best[si - 2] ?? '', subscriptionKey: best[si - 3] ?? '',
      flag: 'apex', profileId: 1, keyId: 1, mtls,
    }
    for (const field of ['configPublicKey', 'subscriptionPublicKey', 'subscriptionKey'] as const) {
      if (atob(apex[field]).length !== 32) throw new Error('Apex 密钥长度无效')
    }
    const cfgUrls = unique(best.filter((v): v is string => typeof v === 'string' && FULL_URL_JSON_RE.test(v) && v.includes('_apex')))
    if (!cfgUrls.length) throw new Error('Apex 配置 URL 缺失')
    const packages = unique([...strings.values()].filter((v) => /^ua\.net\.[a-z0-9]+\.app\.apex$/.test(v)))
    const version = extractProductVersion(installer)
    if (packages.length !== 1 || !version) throw new Error('Apex 应用标识或版本缺失')
    return { cfgUrls, userAgent: `${packages[0]}/v${version}`, decrypt: null, subscriptionDecrypt: null, apex }
  }
  throw new Error('未找到有效的 Apex Dart 常量池')
}

function yamlScalar(value: string): string {
  if (/^[A-Za-z0-9:/?&=._~%+\-]+$/.test(value)) return value
  return `'${value.replaceAll("'", "''")}'`
}

export function renderYaml(info: ExtractedInfo): string {
  const lines = ['cfgUrls:']
  for (const url of info.cfgUrls) lines.push(`  - ${yamlScalar(url)}`)
  lines.push('username:')
  lines.push('password:')
  lines.push('headers:')
  lines.push(`  User-Agent: ${info.userAgent}`)
  if (info.decrypt) {
    lines.push('decrypt:')
    lines.push(`  key: ${yamlScalar(info.decrypt.key)}`)
    lines.push(`  iv: ${yamlScalar(info.decrypt.iv)}`)
  } else {
    lines.push('decrypt: null')
  }
  if (info.subscriptionDecrypt) {
    lines.push('subscriptionDecrypt:')
    lines.push(`  type: ${info.subscriptionDecrypt.type}`)
    lines.push(`  password: ${yamlScalar(info.subscriptionDecrypt.password)}`)
  }
  if (info.apex) lines.push(`apex: ${JSON.stringify(info.apex)}`)
  return `${lines.join('\n')}\n`
}

export function extractInfo(installer: Uint8Array, payload: Uint8Array): ExtractedInfo {
  const apex = extractApex(payload, installer)
  if (apex) return apex
  const rawUrls = extractJsonUrls(installer)
  const payloadUrls = extractJsonUrls(payload)
  const { urls: dartUrls, hexValues, obfuscatedHexValues } = selectSnapshotInfo(payload)
  const cfgUrls = selectConfigUrls(unique([...rawUrls, ...payloadUrls]), dartUrls)
  const decrypt = selectDecryptValues(cfgUrls, dartUrls, hexValues)
  const subscriptionDecrypt = selectSubscriptionDecrypt(obfuscatedHexValues)
  const userAgent = extractUserAgent(installer, payload)
  return { cfgUrls, userAgent, decrypt, subscriptionDecrypt }
}

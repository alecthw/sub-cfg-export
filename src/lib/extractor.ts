import type { DecryptInfo, ExtractedInfo } from '../types'

const URL_JSON_RE =
  /https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/[A-Za-z0-9._~!$&()*+,;=:@%/+\-]*?\.json/gi
const FULL_URL_JSON_RE =
  /^https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/[A-Za-z0-9._~!$&()*+,;=:@%/+\-]*?\.json$/i
const HEX16_RE = /^[0-9a-fA-F]{16}$/
const SNAPSHOT_MAGIC = new Uint8Array([0xf5, 0xf5, 0xdc, 0xdc])
const textDecoder = new TextDecoder('windows-1252')

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
  const stringTags = Number(stringTagsBig)
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

  ;[, pos] = readCompactSigned(data, pos, end, 32)
  let integerCount: number
  ;[integerCount, pos] = readUnsigned(data, pos, end)
  if (integerCount < 128 || integerCount > snapshot.numObjects) {
    throw new Error('Dart integer cluster 不符合预期')
  }

  const firstRef = 1 + snapshot.numBase + stringCount
  const refValues = new Map<number, number>()
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
): { urls: PositionedValue[]; hexValues: PositionedValue[] } {
  let refValues: Map<number, number>
  let scanStart: number
  try {
    ;[refValues, scanStart] = parseSmallIntegerRefs(data, snapshot)
  } catch {
    return { urls: [], hexValues: [] }
  }

  const urls: PositionedValue[] = []
  const hexValues: PositionedValue[] = []
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
    }
  }

  return { urls, hexValues }
}

function selectSnapshotInfo(data: Uint8Array): {
  urls: PositionedValue[]
  hexValues: PositionedValue[]
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
  return { urls: [], hexValues: [] }
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

  const firstUrlPos = Math.min(...positions)
  const nearby = hexValues
    .filter((item) => firstUrlPos - item.pos > 0 && firstUrlPos - item.pos <= 4096)
    .sort((left, right) => left.pos - right.pos)
  if (nearby.length < 2) return null

  const iv = nearby.at(-2)?.value
  const key = nearby.at(-1)?.value
  if (!iv || !key || iv === key) return null
  return { key, iv }
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
  lines.push('  User-Agent: NetFlow/v3.0.6 clash-verge Platform/linux')
  if (info.decrypt) {
    lines.push('decrypt:')
    lines.push(`  key: ${yamlScalar(info.decrypt.key)}`)
    lines.push(`  iv: ${yamlScalar(info.decrypt.iv)}`)
  } else {
    lines.push('decrypt: null')
  }
  return `${lines.join('\n')}\n`
}

export function extractInfo(installer: Uint8Array, payload: Uint8Array): ExtractedInfo {
  const rawUrls = extractJsonUrls(installer)
  const payloadUrls = extractJsonUrls(payload)
  const { urls: dartUrls, hexValues } = selectSnapshotInfo(payload)
  const cfgUrls = selectConfigUrls(unique([...rawUrls, ...payloadUrls]), dartUrls)
  const decrypt = selectDecryptValues(cfgUrls, dartUrls, hexValues)
  return { cfgUrls, decrypt }
}

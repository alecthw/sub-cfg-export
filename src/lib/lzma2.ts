import { createUnxz, initModule } from 'node-liblzma/wasm'

export interface Lzma2Stream {
  compressed: Uint8Array
  uncompressedSize: number
}

const XZ_MAGIC = new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
const STREAM_FLAGS = new Uint8Array([0x00, 0x00])
const FOOTER_MAGIC = new Uint8Array([0x59, 0x5a])

let crcTable: Uint32Array | undefined

function getCrcTable(): Uint32Array {
  if (crcTable) return crcTable
  crcTable = new Uint32Array(256)
  for (let index = 0; index < 256; index += 1) {
    let value = index
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    }
    crcTable[index] = value >>> 0
  }
  return crcTable
}

function crc32(data: Uint8Array): number {
  const table = getCrcTable()
  let value = 0xffffffff
  for (const byte of data) value = table[(value ^ byte) & 0xff] ^ (value >>> 8)
  return (value ^ 0xffffffff) >>> 0
}

function uint32Le(value: number): Uint8Array {
  const output = new Uint8Array(4)
  new DataView(output.buffer).setUint32(0, value >>> 0, true)
  return output
}

function encodeVli(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('XZ VLI 数值无效')
  const bytes: number[] = []
  do {
    let byte = value % 128
    value = Math.floor(value / 128)
    if (value > 0) byte |= 0x80
    bytes.push(byte)
  } while (value > 0)
  return Uint8Array.from(bytes)
}

function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0)
  const output = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function padding(length: number): Uint8Array {
  return new Uint8Array((4 - (length % 4)) % 4)
}

export function readLzma2Stream(data: Uint8Array, start: number): Lzma2Stream {
  let pos = start
  let uncompressedSize = 0

  while (pos < data.length) {
    const control = data[pos]
    pos += 1

    if (control === 0x00) {
      return { compressed: data.subarray(start, pos), uncompressedSize }
    }

    if (control === 0x01 || control === 0x02) {
      if (pos + 2 > data.length) throw new Error('LZMA2 未压缩块头不完整')
      const chunkSize = (data[pos] << 8) + data[pos + 1] + 1
      pos += 2
      if (pos + chunkSize > data.length) throw new Error('LZMA2 未压缩块数据不完整')
      pos += chunkSize
      uncompressedSize += chunkSize
      continue
    }

    if (control < 0x80) throw new Error(`无效的 LZMA2 control byte: ${control}`)
    if (pos + 4 > data.length) throw new Error('LZMA2 压缩块头不完整')

    const chunkUncompressedSize =
      ((control & 0x1f) << 16) + (data[pos] << 8) + data[pos + 1] + 1
    const chunkCompressedSize = (data[pos + 2] << 8) + data[pos + 3] + 1
    pos += 4

    if (control >= 0xc0) {
      if (pos >= data.length) throw new Error('LZMA2 properties 缺失')
      pos += 1
    }
    if (pos + chunkCompressedSize > data.length) throw new Error('LZMA2 压缩块数据不完整')

    pos += chunkCompressedSize
    uncompressedSize += chunkUncompressedSize
    if (!Number.isSafeInteger(uncompressedSize)) throw new Error('LZMA2 解压大小超出安全范围')
  }

  throw new Error('LZMA2 stream 未找到结束标记')
}

export function wrapRawLzma2AsXz(
  compressed: Uint8Array,
  property: number,
  uncompressedSize: number,
): Uint8Array {
  if (property < 0 || property > 40) throw new Error(`无效的 LZMA2 property: ${property}`)

  const streamHeader = concat([XZ_MAGIC, STREAM_FLAGS, uint32Le(crc32(STREAM_FLAGS))])

  const blockHeaderBody = new Uint8Array([0x02, 0x00, 0x21, 0x01, property, 0, 0, 0])
  const blockHeader = concat([blockHeaderBody, uint32Le(crc32(blockHeaderBody))])
  const unpaddedBlockSize = blockHeader.length + compressed.length
  const blockPadding = padding(unpaddedBlockSize)

  let indexBody = concat([
    new Uint8Array([0x00]),
    encodeVli(1),
    encodeVli(unpaddedBlockSize),
    encodeVli(uncompressedSize),
  ])
  indexBody = concat([indexBody, padding(indexBody.length)])
  const index = concat([indexBody, uint32Le(crc32(indexBody))])

  const backwardSize = uint32Le(index.length / 4 - 1)
  const footerBody = concat([backwardSize, STREAM_FLAGS])
  const footer = concat([uint32Le(crc32(footerBody)), footerBody, FOOTER_MAGIC])

  return concat([streamHeader, blockHeader, compressed, blockPadding, index, footer])
}

export async function decompressRawLzma2(
  compressed: Uint8Array,
  property: number,
  uncompressedSize: number,
): Promise<Uint8Array> {
  await initModule()
  const xz = wrapRawLzma2AsXz(compressed, property, uncompressedSize)
  const inputChunkSize = 1024 * 1024
  let inputOffset = 0

  const source = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (inputOffset >= xz.length) {
        controller.close()
        return
      }
      const end = Math.min(xz.length, inputOffset + inputChunkSize)
      controller.enqueue(xz.subarray(inputOffset, end))
      inputOffset = end
    },
  })

  const output = new Uint8Array(uncompressedSize)
  const reader = source.pipeThrough(createUnxz()).getReader()
  let outputOffset = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (outputOffset + value.length > output.length) {
      await reader.cancel('LZMA2 解压数据超过预期大小')
      throw new Error('LZMA2 解压数据超过预期大小')
    }
    output.set(value, outputOffset)
    outputOffset += value.length
  }

  if (outputOffset !== output.length) throw new Error('LZMA2 解压数据小于预期大小')
  return output
}

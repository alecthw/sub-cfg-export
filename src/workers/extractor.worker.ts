/// <reference lib="webworker" />

import { extractInfo, findSequence, renderYaml } from '../lib/extractor'
import { decompressRawLzma2, readLzma2Stream } from '../lib/lzma2'
import type {
  ExtractionResult,
  ProgressMessage,
  WorkerRequest,
  WorkerResponse,
} from '../types'

const context: DedicatedWorkerGlobalScope = self as unknown as DedicatedWorkerGlobalScope
const INNO_MARKER = new Uint8Array([0x7a, 0x6c, 0x62, 0x1a])
const MAX_PAYLOAD_SIZE = 768 * 1024 * 1024

function postProgress(payload: ProgressMessage) {
  const response: WorkerResponse = { type: 'progress', payload }
  context.postMessage(response)
}

async function decodeAt(installer: Uint8Array, markerPos: number): Promise<Uint8Array> {
  const propertyPos = markerPos + INNO_MARKER.length
  if (propertyPos >= installer.length) throw new Error('LZMA2 property 缺失')

  const property = installer[propertyPos]
  const stream = readLzma2Stream(installer, propertyPos + 1)
  if (stream.uncompressedSize > MAX_PAYLOAD_SIZE) {
    throw new Error('解压数据超过 768 MiB 安全限制')
  }

  postProgress({
    stage: 'decompressing',
    percent: 18,
    message: '已定位 LZMA2 数据流，正在通过 WASM 解压…',
  })
  const decoded = await decompressRawLzma2(
    stream.compressed,
    property,
    stream.uncompressedSize,
  )
  if (decoded.length !== stream.uncompressedSize) throw new Error('LZMA2 解压后大小校验失败')
  if (decoded.length < 1024) throw new Error('解压后的 payload 过小')
  return decoded
}

async function decompressInnoPayload(installer: Uint8Array): Promise<Uint8Array> {
  const markerPositions: number[] = []
  let searchPos = 0
  while (searchPos < installer.length) {
    const markerPos = findSequence(installer, INNO_MARKER, searchPos)
    if (markerPos < 0) break
    markerPositions.push(markerPos)
    searchPos = markerPos + 1
  }
  if (markerPositions.length === 0) throw new Error('未找到 Inno Setup LZMA2 数据块')

  let lastError: unknown
  for (const markerPos of markerPositions) {
    try {
      return await decodeAt(installer, markerPos)
    } catch (error) {
      lastError = error
    }
  }

  const reason = lastError instanceof Error ? lastError.message : String(lastError)
  throw new Error(`Inno Setup 数据块解压失败：${reason}`)
}

function outputName(fileName: string): string {
  return fileName.replace(/\.exe$/i, '') + '.yaml'
}

async function handleExtract(file: File): Promise<ExtractionResult> {
  const startedAt = performance.now()
  postProgress({ stage: 'reading', percent: 2, message: '正在读取本地文件…' })
  const installer = new Uint8Array(await file.arrayBuffer())

  postProgress({
    stage: 'decompressing',
    percent: 8,
    message: '已读取文件，正在定位 Inno Setup LZMA2 数据块…',
  })
  const payload = await decompressInnoPayload(installer)

  postProgress({
    stage: 'analyzing',
    percent: 78,
    message: '正在扫描配置 URL 与 Dart Snapshot…',
  })
  const info = extractInfo(installer, payload)

  postProgress({ stage: 'rendering', percent: 96, message: '正在生成 YAML…' })
  const yaml = renderYaml(info)

  return {
    info,
    yaml,
    outputName: outputName(file.name),
    stats: {
      inputBytes: installer.byteLength,
      payloadBytes: payload.byteLength,
      elapsedMs: Math.round(performance.now() - startedAt),
    },
  }
}

context.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  if (event.data.type !== 'extract') return
  try {
    const result = await handleExtract(event.data.file)
    const response: WorkerResponse = { type: 'result', payload: result }
    context.postMessage(response)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const response: WorkerResponse = { type: 'error', payload: { message } }
    context.postMessage(response)
  }
}

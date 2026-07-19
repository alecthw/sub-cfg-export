export type ExtractionStage =
  | 'idle'
  | 'reading'
  | 'decompressing'
  | 'analyzing'
  | 'rendering'
  | 'done'
  | 'error'

export interface ProgressMessage {
  stage: ExtractionStage
  percent: number
  message: string
}

export interface DecryptInfo {
  key: string
  iv: string
}

export interface SubscriptionDecryptInfo {
  type: 'aes-256-gcm'
  password: string
}

export interface ExtractedInfo {
  cfgUrls: string[]
  userAgent: string
  decrypt: DecryptInfo | null
  subscriptionDecrypt: SubscriptionDecryptInfo | null
}

export interface ExtractionStats {
  inputBytes: number
  payloadBytes: number
  elapsedMs: number
}

export interface ExtractionResult {
  info: ExtractedInfo
  yaml: string
  outputName: string
  stats: ExtractionStats
}

export type WorkerRequest = {
  type: 'extract'
  file: File
}

export type WorkerResponse =
  | { type: 'progress'; payload: ProgressMessage }
  | { type: 'result'; payload: ExtractionResult }
  | { type: 'error'; payload: { message: string } }

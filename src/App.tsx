import {
  CheckCircleFilled,
  CopyOutlined,
  DeleteOutlined,
  FileSearchOutlined,
  GithubOutlined,
  InfoCircleOutlined,
  InboxOutlined,
  MobileOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
} from '@ant-design/icons'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Flex,
  Input,
  Modal,
  Progress,
  Row,
  Space,
  Steps,
  Tag,
  Tooltip,
  Typography,
  Upload,
  type UploadProps,
} from 'antd'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import subStoreLogo from './assets/sub-store-logo.png'
import UsageGuide from './components/UsageGuide'
import type {
  ExtractionResult,
  ExtractionStage,
  ProgressMessage,
  WorkerRequest,
  WorkerResponse,
} from './types'

const { Dragger } = Upload
const { Title, Paragraph, Text } = Typography
const DISCLAIMER_STORAGE_KEY = 'sub-cfg-export:disclaimer:v1'
const ISSUE_TEMPLATE_URL =
  'https://github.com/alecthw/sub-cfg-export/issues/new?template=extraction-failure.md'

interface IssuePrompt {
  fileName: string
  message: string
}

const STAGE_INDEX: Record<ExtractionStage, number> = {
  idle: 0,
  reading: 0,
  decompressing: 1,
  analyzing: 2,
  rendering: 3,
  done: 4,
  error: 0,
}

function hasAcceptedDisclaimer(): boolean {
  try {
    return localStorage.getItem(DISCLAIMER_STORAGE_KEY) === 'accepted'
  } catch {
    return false
  }
}

function rememberDisclaimerAcceptance(): void {
  try {
    localStorage.setItem(DISCLAIMER_STORAGE_KEY, 'accepted')
  } catch {
    // The current session can continue even when browser storage is unavailable.
  }
}

function isLikelyMobileDevice(): boolean {
  const navigatorWithUaData = navigator as Navigator & {
    userAgentData?: { mobile?: boolean }
  }
  if (navigatorWithUaData.userAgentData?.mobile) return true
  if (/Android|iPhone|iPad|iPod|Mobile|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
    return true
  }
  return window.innerWidth <= 768 && window.matchMedia('(pointer: coarse)').matches
}

function buildIssueUrl(fileName: string): string {
  const title = `[提取失败] ${fileName}`
  return `${ISSUE_TEMPLATE_URL}&title=${encodeURIComponent(title)}`
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes / 1024
  let unit = units[0]
  for (let index = 1; index < units.length && value >= 1024; index += 1) {
    value /= 1024
    unit = units[index]
  }
  return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${unit}`
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds} ms`
  return `${(milliseconds / 1000).toFixed(2)} s`
}

export default function App() {
  const { message } = AntdApp.useApp()
  const workerRef = useRef<Worker | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [stage, setStage] = useState<ExtractionStage>('idle')
  const [progress, setProgress] = useState(0)
  const [statusText, setStatusText] = useState('选择安装包后将自动开始解析')
  const [result, setResult] = useState<ExtractionResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [disclaimerOpen, setDisclaimerOpen] = useState(() => !hasAcceptedDisclaimer())
  const [mobileWarningOpen, setMobileWarningOpen] = useState(isLikelyMobileDevice)
  const [issuePrompt, setIssuePrompt] = useState<IssuePrompt | null>(null)

  const processing = !['idle', 'done', 'error'].includes(stage)

  const acceptDisclaimer = useCallback(() => {
    rememberDisclaimerAcceptance()
    setDisclaimerOpen(false)
  }, [])

  const rejectDisclaimer = useCallback(() => {
    window.close()
    window.setTimeout(() => {
      if (!window.closed) window.location.replace('about:blank')
    }, 80)
  }, [])

  const stopWorker = useCallback(() => {
    workerRef.current?.terminate()
    workerRef.current = null
  }, [])

  useEffect(() => stopWorker, [stopWorker])

  const startExtraction = useCallback(
    (selectedFile: File) => {
      stopWorker()
      setFile(selectedFile)
      setResult(null)
      setError(null)
      setIssuePrompt(null)
      setStage('reading')
      setProgress(1)
      setStatusText('正在启动本地解析 Worker…')

      const worker = new Worker(new URL('./workers/extractor.worker.ts', import.meta.url), {
        type: 'module',
      })
      workerRef.current = worker

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        if (event.data.type === 'progress') {
          const payload: ProgressMessage = event.data.payload
          setStage(payload.stage)
          setProgress(payload.percent)
          setStatusText(payload.message)
          return
        }

        if (event.data.type === 'result') {
          setResult(event.data.payload)
          setStage('done')
          setProgress(100)
          setStatusText('解析完成，YAML 已在浏览器本地生成')
          worker.terminate()
          if (workerRef.current === worker) workerRef.current = null
          void message.success('配置提取完成')
          return
        }

        setError(event.data.payload.message)
        setIssuePrompt({ fileName: selectedFile.name, message: event.data.payload.message })
        setStage('error')
        setProgress(0)
        setStatusText('解析失败')
        worker.terminate()
        if (workerRef.current === worker) workerRef.current = null
      }

      worker.onerror = (event) => {
        const errorMessage = event.message || 'Worker 运行失败'
        setError(errorMessage)
        setIssuePrompt({ fileName: selectedFile.name, message: errorMessage })
        setStage('error')
        setProgress(0)
        setStatusText('解析失败')
        worker.terminate()
        if (workerRef.current === worker) workerRef.current = null
      }

      const request: WorkerRequest = { type: 'extract', file: selectedFile }
      worker.postMessage(request)
    },
    [message, stopWorker],
  )

  const cancel = useCallback(() => {
    stopWorker()
    setStage('idle')
    setProgress(0)
    setStatusText('处理已取消，可重新选择安装包')
    void message.info('已取消处理')
  }, [message, stopWorker])

  const reset = useCallback(() => {
    stopWorker()
    setFile(null)
    setResult(null)
    setError(null)
    setIssuePrompt(null)
    setStage('idle')
    setProgress(0)
    setStatusText('选择安装包后将自动开始解析')
  }, [stopWorker])

  const beforeUpload: UploadProps['beforeUpload'] = (selectedFile) => {
    if (!selectedFile.name.toLowerCase().endsWith('.exe')) {
      void message.error('请选择 Windows EXE 安装包')
      return Upload.LIST_IGNORE
    }
    if (selectedFile.size > 512 * 1024 * 1024) {
      void message.error('输入文件不能超过 512 MiB')
      return Upload.LIST_IGNORE
    }
    startExtraction(selectedFile)
    return Upload.LIST_IGNORE
  }

  const copyYaml = useCallback(async () => {
    if (!result) return
    await navigator.clipboard.writeText(result.yaml)
    void message.success('YAML 已复制')
  }, [message, result])

  const providerScriptUrl = useMemo(
    () => new URL('provider-api-subscription.js', document.baseURI).href,
    [],
  )

  const copyProviderScriptUrl = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(providerScriptUrl)
      void message.success('脚本 URL 已复制')
    } catch {
      void message.error('复制失败，请手动复制脚本 URL')
    }
  }, [message, providerScriptUrl])

  const stepItems = useMemo(
    () => [
      { title: '读取文件' },
      { title: 'LZMA2 解压' },
      { title: '解析配置' },
      { title: '生成 YAML' },
      { title: '完成' },
    ],
    [],
  )

  return (
    <>
      <Modal
        open={mobileWarningOpen}
        title={
          <Space size={10}>
            <MobileOutlined className="disclaimer-title-icon" />
            <span>移动端使用提示</span>
          </Space>
        }
        centered
        closable={false}
        maskClosable={false}
        keyboard={false}
        footer={
          <Button type="primary" onClick={() => setMobileWarningOpen(false)}>
            我知道了
          </Button>
        }
      >
        <Alert
          type="warning"
          showIcon
          message="手机浏览器可能由于内存不足导致解析失败，请换 PC 端使用。"
        />
      </Modal>

      <Modal
        open={disclaimerOpen && !mobileWarningOpen}
        title={
          <Space size={10}>
            <SafetyCertificateOutlined className="disclaimer-title-icon" />
            <span>免责声明与使用须知</span>
          </Space>
        }
        centered
        width={640}
        closable={false}
        maskClosable={false}
        keyboard={false}
        footer={
          <Space wrap>
            <Button danger onClick={rejectDisclaimer}>
              拒绝并关闭
            </Button>
            <Button type="primary" onClick={acceptDisclaimer}>
              同意并继续
            </Button>
          </Space>
        }
      >
        <div className="disclaimer-content">
          <Alert
            type="warning"
            showIcon
            message="请在继续使用前阅读并确认以下内容"
          />
          <Paragraph>
            本工具并非用于破解软件，也不提供绕过授权、访问控制或技术保护的能力。
            本工具仅用于学习和研究，不得用于任何商业目的、非法用途或侵犯第三方合法权益。
          </Paragraph>
          <Paragraph>
            本工具基于 WebAssembly（WASM）开发。安装包读取、解压、分析和 YAML
            生成均在当前浏览器本地完成，不会向任何服务器上传您选择的文件、提取结果或其他处理数据。
          </Paragraph>
          <ul className="disclaimer-list">
            <li>您只能处理自己拥有或已获得合法授权分析的客户端文件。</li>
            <li>您应遵守所在地法律法规、软件许可协议及相关服务条款。</li>
            <li>提取结果仅供研究参考；因使用本工具产生的风险和责任由使用者自行承担。</li>
            <li>本工具不对结果的准确性、完整性、兼容性或持续可用性作任何保证。</li>
          </ul>
          <Text strong className="disclaimer-confirm">
            点击“同意并继续”即表示您已阅读、理解并同意以上内容。
          </Text>
        </div>
      </Modal>

      <Modal
        open={issuePrompt !== null}
        title="提取失败，是否提交 Issue？"
        centered
        width={600}
        onCancel={() => setIssuePrompt(null)}
        footer={
          <Space wrap>
            <Button onClick={() => setIssuePrompt(null)}>暂不提交</Button>
            <Button
              type="primary"
              icon={<GithubOutlined />}
              href={issuePrompt ? buildIssueUrl(issuePrompt.fileName) : ISSUE_TEMPLATE_URL}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setIssuePrompt(null)}
            >
              提交 Issue
            </Button>
          </Space>
        }
      >
        <div className="issue-prompt-content">
          <Alert
            type="error"
            showIcon
            message={issuePrompt?.message ?? '未能从安装包中提取配置信息'}
          />
          <Paragraph>
            如果该安装包来自仍在使用的机场/梯子客户端，可前往项目提交 Issue，帮助完善兼容性。
            提交前请勿包含 AFF、邀请链接、订阅地址、密钥或客户端安装包。
          </Paragraph>
          {issuePrompt && <Text type="secondary">文件名：{issuePrompt.fileName}</Text>}
        </div>
      </Modal>

      <main className="app-shell">
      <section className="hero">
        <div className="hero-glow hero-glow-one" />
        <div className="hero-glow hero-glow-two" />
        <nav className="hero-links" aria-label="项目链接">
          <Tooltip title="sub cfg export GitHub">
            <a
              className="hero-link-button"
              href="https://github.com/alecthw/sub-cfg-export"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="打开 sub cfg export GitHub 项目主页"
            >
              <GithubOutlined />
            </a>
          </Tooltip>
          <Tooltip title="Sub-Store GitHub">
            <a
              className="hero-link-button"
              href="https://github.com/sub-store-org"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="打开 Sub-Store GitHub 项目主页"
            >
              <img src={subStoreLogo} alt="" />
            </a>
          </Tooltip>
        </nav>
        <div className="hero-content">
          <Space orientation="vertical" size={14}>
            <Tag color="blue" variant="filled" className="project-tag">
              LOCAL-FIRST TOOL
            </Tag>
            <Title level={1}>封端机场导出Sub-Store订阅</Title>
            <Paragraph className="hero-description">
              从封端机场/梯子的 Windows 客户端中提取配置 URL、key 和 iv，
              生成的 YAML 可在新版 Sub-Store 导入从而获取订阅。
            </Paragraph>
            <Space wrap>
              <Tag icon={<SafetyCertificateOutlined />} color="success">
                文件不上传
              </Tag>
              <Tag color="processing">Web Worker</Tag>
              <Tag color="purple">LZMA2 WASM</Tag>
              <Tag>GitHub Pages</Tag>
            </Space>
          </Space>
        </div>
      </section>

      <section className="content-grid">
        <Card className="upload-card" variant="borderless">
          <Flex justify="space-between" align="flex-start" gap={20} wrap>
            <div className="upload-heading">
              <div className="upload-title-row">
                <Tag color="blue" className="flow-step-tag">
                  第 1 步
                </Tag>
                <Title level={3}>选择安装包</Title>
              </div>
              <div className="installer-source-note">
                <InfoCircleOutlined />
                <span>
                  <strong>说明：</strong>
                  从机场/梯子控制台下载 Windows 版本；如为压缩包，请先提取其中的 xxx-setup.exe 文件。
                </span>
              </div>
              <Paragraph type="secondary">
                支持当前提取器兼容的 Windows Inno Setup EXE。选择后自动开始处理。
              </Paragraph>
            </div>
            {file && (
              <Button icon={<DeleteOutlined />} onClick={reset} disabled={processing}>
                清除
              </Button>
            )}
          </Flex>

          <Dragger
            accept=".exe,application/x-msdownload"
            beforeUpload={beforeUpload}
            showUploadList={false}
            disabled={processing}
            className="installer-dragger"
          >
            <p className="ant-upload-drag-icon">
              <InboxOutlined />
            </p>
            <p className="ant-upload-text">点击或拖入客户端安装包</p>
            <p className="ant-upload-hint">整个解析过程仅在当前浏览器标签页中完成</p>
          </Dragger>

          {file && (
            <div className="selected-file">
              <Flex align="center" gap={14}>
                <div className="file-icon">
                  <FileSearchOutlined />
                </div>
                <div className="file-meta">
                  <Text strong ellipsis title={file.name}>
                    {file.name}
                  </Text>
                  <Text type="secondary">{formatBytes(file.size)}</Text>
                </div>
                {processing && (
                  <Button danger icon={<StopOutlined />} onClick={cancel}>
                    取消
                  </Button>
                )}
              </Flex>
            </div>
          )}

          <Divider />

          <Steps
            size="small"
            responsive
            current={STAGE_INDEX[stage]}
            status={stage === 'error' ? 'error' : stage === 'done' ? 'finish' : 'process'}
            items={stepItems}
          />

          <div className="progress-block">
            <Flex justify="space-between" align="center" gap={16}>
              <Text>{statusText}</Text>
              <Text type="secondary">{progress}%</Text>
            </Flex>
            <Progress
              percent={progress}
              showInfo={false}
              status={stage === 'error' ? 'exception' : stage === 'done' ? 'success' : 'active'}
            />
          </div>

          {error && (
            <Alert
              type="error"
              showIcon
              message="无法完成提取"
              description={error}
              action={
                file ? (
                  <Button size="small" onClick={() => startExtraction(file)}>
                    重试
                  </Button>
                ) : undefined
              }
            />
          )}

        </Card>

        <Card className="privacy-card" variant="borderless">
          <Space orientation="vertical" size={18}>
            <div className="privacy-icon">
              <SafetyCertificateOutlined />
            </div>
            <div>
              <Title level={4}>本地处理</Title>
              <Paragraph type="secondary">
                安装包通过 File API 交给同源 Worker，页面不会执行上传请求，也不需要后台服务。
              </Paragraph>
            </div>
            <Descriptions
              size="small"
              column={1}
              items={[
                { key: 'runtime', label: '运行方式', children: '浏览器 + WASM' },
                { key: 'upload', label: '文件上传', children: '无' },
                { key: 'output', label: '输出格式', children: 'YAML' },
              ]}
            />
          </Space>
        </Card>
      </section>

      {result && (
        <section className="result-section">
          <Card className="result-card" variant="borderless">
            <Flex justify="space-between" align="center" gap={20} wrap>
              <Space>
                <CheckCircleFilled className="success-icon" />
                <div>
                  <Tag color="success" className="result-step-tag">
                    第 1 步完成
                  </Tag>
                  <Title level={3}>配置已导出</Title>
                  <Text type="secondary">{result.outputName}</Text>
                </div>
              </Space>
              <Space wrap>
                <Button icon={<CopyOutlined />} onClick={() => void copyYaml()}>
                  复制
                </Button>
              </Space>
            </Flex>

            <Row gutter={[16, 16]} className="stats-row">
              <Col xs={24} sm={8}>
                <div className="stat-box">
                  <Text type="secondary">安装包</Text>
                  <Text strong>{formatBytes(result.stats.inputBytes)}</Text>
                </div>
              </Col>
              <Col xs={24} sm={8}>
                <div className="stat-box">
                  <Text type="secondary">解压数据</Text>
                  <Text strong>{formatBytes(result.stats.payloadBytes)}</Text>
                </div>
              </Col>
              <Col xs={24} sm={8}>
                <div className="stat-box">
                  <Text type="secondary">处理耗时</Text>
                  <Text strong>{formatDuration(result.stats.elapsedMs)}</Text>
                </div>
              </Col>
            </Row>

            <Input.TextArea
              className="yaml-preview"
              value={result.yaml}
              readOnly
              autoSize={{ minRows: 14, maxRows: 28 }}
              spellCheck={false}
            />

            <UsageGuide
              scriptUrl={providerScriptUrl}
              onCopyScriptUrl={() => void copyProviderScriptUrl()}
            />
          </Card>
        </section>
      )}

      <footer>
        <Text type="secondary">封端机场导出Sub-Store订阅 · static local extractor</Text>
      </footer>
      </main>
    </>
  )
}

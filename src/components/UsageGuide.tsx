import { CopyOutlined, ExportOutlined } from '@ant-design/icons'
import { Button, Image, Space, Typography } from 'antd'
import localSubImage from '../assets/local-sub.jpg'
import nodeOperationScriptImage from '../assets/node-operation-script.jpg'

const { Title, Paragraph, Text } = Typography

interface UsageGuideProps {
  scriptUrl: string
  onCopyScriptUrl: () => void
}

export default function UsageGuide({ scriptUrl, onCopyScriptUrl }: UsageGuideProps) {
  return (
    <div
      className="result-next-steps"
      role="region"
      aria-labelledby="substore-next-steps-title"
    >
      <div className="result-next-header">
        <Title id="substore-next-steps-title" level={3}>
          接下来：在 Sub-Store 中使用导出的配置
        </Title>
        <Paragraph type="secondary">
          配置已经导出，请继续完成本地订阅和节点脚本操作。
        </Paragraph>
      </div>

      <div className="workflow-details">
        <article className="workflow-step">
          <div className="workflow-step-heading">
            <div className="workflow-step-number">2</div>
            <Title level={4}>创建本地订阅</Title>
          </div>
          <Paragraph>
            在 Sub-Store 中新建
            <Text strong className="workflow-keyword">
              单条订阅
            </Text>
            ，类型选择
            <Text strong className="workflow-keyword">
              本地订阅
            </Text>
            。将上方导出的 YAML 完整粘贴到本地订阅内容中，并填写
            <Text strong className="workflow-keyword">
              用户名
            </Text>
            和
            <Text strong className="workflow-keyword">
              密码
            </Text>
            后保存。
          </Paragraph>
          <Image
            className="workflow-screenshot"
            src={localSubImage}
            alt="Sub-Store 新建本地订阅操作示例"
            width="100%"
            loading="lazy"
            preview={{ mask: '查看大图' }}
          />
        </article>

        <article className="workflow-step">
          <div className="workflow-step-heading">
            <div className="workflow-step-number">3</div>
            <Title level={4}>添加节点脚本操作</Title>
          </div>
          <Paragraph>
            在该订阅的
            <Text strong className="workflow-keyword">
              节点操作
            </Text>
            中新增
            <Text strong className="workflow-keyword">
              脚本操作
            </Text>
            ，选择 URL 方式并填入以下脚本地址，然后保存并更新订阅。
          </Paragraph>

          <div className="provider-script-box">
            <code className="provider-script-url">{scriptUrl}</code>
            <Space size={8} wrap>
              <Button type="primary" size="small" icon={<CopyOutlined />} onClick={onCopyScriptUrl}>
                复制脚本 URL
              </Button>
              <Button
                size="small"
                icon={<ExportOutlined />}
                href={scriptUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                打开脚本
              </Button>
            </Space>
          </div>

          <Image
            className="workflow-screenshot"
            src={nodeOperationScriptImage}
            alt="Sub-Store 节点操作添加脚本 URL 示例"
            width="100%"
            loading="lazy"
            preview={{ mask: '查看大图' }}
          />
          <Text type="secondary" className="workflow-tip">
            首次成功获取订阅后，如需显示订阅流量信息，请刷新一次 Sub-Store 页面。
          </Text>
        </article>
      </div>
    </div>
  )
}

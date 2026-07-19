import { chromium, expect, test as base, type Page } from '@playwright/test'

const test = base.extend<{ page: Page }>({
  page: async ({}, use) => {
    const browser = await chromium.launch()
    const page = await browser.newPage()
    try {
      await use(page)
    } finally {
      await browser.close()
    }
  },
})
import path from 'node:path'

const root = process.cwd()

async function openApp(page: import('@playwright/test').Page) {
  await page.goto('/')
  const acceptButton = page.getByRole('button', { name: '同意并继续' })
  await expect(acceptButton).toBeVisible()
  await acceptButton.click()
}

async function selectInstaller(page: import('@playwright/test').Page, fileName: string) {
  await page.locator('input[type="file"]').setInputFiles(path.join(root, fileName))
  await expect(page.getByText('配置已导出')).toBeVisible()
  return page.locator('textarea.yaml-preview').inputValue()
}

test('globalcloud exports complete YAML without decrypt block', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, 'globalcloud-2.2.3-windows-amd64-setup.exe')
  await expect(page.locator('input[type="file"]')).toHaveCount(0)
  await expect(page.getByText('第 1 步完成')).toBeVisible()
  const guide = page.getByRole('region', { name: '接下来：在 Sub-Store 中使用导出的配置' })
  await expect(guide).toBeVisible()
  await expect(guide.getByRole('heading', { name: '创建本地订阅' })).toBeVisible()
  await expect(guide.getByRole('heading', { name: '添加节点脚本操作' })).toBeVisible()
  await expect(guide.getByText('本地订阅', { exact: true })).toBeVisible()
  await expect(guide.getByText('脚本操作', { exact: true })).toBeVisible()
  await expect(guide.getByAltText('Sub-Store 新建本地订阅操作示例')).toBeVisible()
  await expect(guide.getByAltText('Sub-Store 节点操作添加脚本 URL 示例')).toBeVisible()
  const scriptUrl = await guide.locator('.provider-script-url').textContent()
  expect(scriptUrl).toBe('http://127.0.0.1:43217/provider-api-subscription.js')
  const scriptResponse = await page.request.get(scriptUrl!)
  expect(scriptResponse.ok()).toBe(true)
  const providerScript = await scriptResponse.text()
  expect(providerScript).toContain('async function operator')
  expect(providerScript).toContain('decryptOssConfig')
  expect(providerScript).not.toContain('searchParams.set("flag"')
  expect(providerScript).toContain('decryptAesBase64(content, config.decrypt)')
  expect(providerScript).not.toContain('SUBSCRIPTION_USER_AGENT')
  expect(yaml).toBe(
    [
      'cfgUrls:',
      '  - http://ossconfig.gcvipaff.cc/oss/ConFigOss.json',
      '  - https://ossconfig.gcvipaff.cc/oss/ConFigOss.json',
      '  - https://download.guangsap1.com/qqy/ConFigOss.json',
      '  - https://down-apps.oss-cn-hongkong.aliyuncs.com/qqy/ConFigOss.json',
      'username:',
      'password:',
      'headers:',
      '  User-Agent: NetFlow/v2.2.4 clash-verge Platform/windows',
      'decrypt: null',
      '',
    ].join('\n'),
  )

  await page.getByRole('button', { name: '清除' }).click()
  await expect(page.locator('input[type="file"]')).toHaveCount(1)
  await expect(page.getByText('点击或拖入客户端安装包')).toBeVisible()
})

test('provider downloads only the original URL with the configured User-Agent', async ({ page }) => {
  const scriptResponse = await page.request.get('/provider-api-subscription.js')
  const script = await scriptResponse.text()
  const outcome = await page.evaluate(async (source) => {
    const scope = globalThis as any
    const subscriptionRequests: Array<{ url: string; headers: Record<string, string> }> = []
    scope.$arguments = { noCache: true }
    scope.$options = {}
    scope.yaml = {
      parse: () => ({
        cfgUrls: ['https://config.example.com/config.json'],
        username: 'test@example.com',
        password: 'test-password',
        headers: { 'User-Agent': 'UnitTest/v1.0 clash-verge Platform/windows' },
        decrypt: null,
      }),
    }
    scope.b64d = (value: string) => atob(value)
    scope.$substore = {
      env: { isNode: false },
      read: (key: string) => (key === 'settings' ? {} : ''),
      write: () => undefined,
      info: () => undefined,
      error: () => undefined,
      http: {
        get: async ({
          url,
          headers = {},
        }: {
          url: string
          headers?: Record<string, string>
        }) => {
          if (url.includes('config.example.com')) {
            return {
              statusCode: 200,
              body: btoa(JSON.stringify({ hosts: ['https://api.example.com'] })),
            }
          }
          if (url.includes('/user/getSubscribe')) {
            return {
              statusCode: 200,
              body: JSON.stringify({
                data: {
                  subscribe_url:
                    'https://subscribe.example.com/api/v1/client/subscribe?token=test',
                },
              }),
            }
          }
          subscriptionRequests.push({ url, headers })
          return { statusCode: 200, body: 'node-ok' }
        },
        post: async () => ({
          statusCode: 200,
          body: JSON.stringify({ data: { auth_data: 'test-auth' } }),
        }),
      },
    }
    scope.ProxyUtils = {
      parse: (content: string) => (content === 'node-ok' ? [{ name: 'node' }] : []),
    }
    ;(0, eval)(`${source}\nglobalThis.__providerOperator = operator;`)
    const nodes = await scope.__providerOperator([], '', { raw: 'ignored' })
    return {
      nodeCount: nodes.length,
      requestCount: subscriptionRequests.length,
      hasFlag: new URL(subscriptionRequests[0].url).searchParams.has('flag'),
      userAgent: subscriptionRequests[0].headers['User-Agent'],
    }
  }, script)

  expect(outcome).toEqual({
    nodeCount: 1,
    requestCount: 1,
    hasFlag: false,
    userAgent: 'UnitTest/v1.0 clash-verge Platform/windows',
  })
})

test('xmtz restores XOR URLs and decrypt values', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, 'xmtzapp-lite.exe')
  expect(yaml).toContain('https://tcdn.getxlx.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://apisa.cnossfile.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://cdno01.llguanglisf.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://ocdn01.llguangli25o.com:59991/saos/xmtz_news.json')
  expect(yaml).toContain('User-Agent: NetFlow/v3.0.6 clash-verge Platform/windows')
  expect(yaml).toContain('key: c8c1dac7d3fff76b')
  expect(yaml).toContain('iv: c705c9b7f56412d8')
})

test('xjkp restores URLs and verified decrypt values', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, 'xjkpapp-lite.exe')
  expect(yaml).toContain('https://tcdn.getxlx.com/saos/xjkp_news.json')
  expect(yaml).toContain('https://apisa.cnossfile.com/saos/xjkp_news.json')
  expect(yaml).toContain('https://cdno01.llguanglisf.com/saos/xjkp_news.json')
  expect(yaml).toContain('https://ocdn01.llguangli25o.com:59991/saos/xjkp_news.json')
  expect(yaml).toContain('User-Agent: NetFlow/v3.0.6 clash-verge Platform/windows')
  expect(yaml).toContain('key: 10b78659c06ec08a')
  expect(yaml).toContain('iv: e8be417610d21adc')
})

test('jilianyun exports all configuration URLs', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, 'jilianyun-2.2.3-windows-amd64-setup.exe')
  expect(yaml).toContain('http://config.jlyvipaff.cc/oss/ConFigOss.json')
  expect(yaml).toContain('https://config.jlyvipaff.cc/oss/ConFigOss.json')
  expect(yaml).toContain('https://down-apps.oss-cn-hongkong.aliyuncs.com/jly/ConFigOss.json')
  expect(yaml).toContain('https://download.guangsap1.com/jly/ConFigOss.json')
  expect(yaml).toContain('User-Agent: NetFlow/v2.2.4 clash-verge Platform/windows')
  expect(yaml).toContain('decrypt: null')
})

test('securitynet exports the branded client User-Agent', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, '3.1.8-windows-amd64-setup.exe')
  expect(yaml).toContain(
    'User-Agent: securitynet/v3.1.8 clash-verge Platform/windows',
  )
  expect(yaml).toContain(
    'https://shanhaioss-1426331524.cos.ap-guangzhou.myqcloud.com/ConFigOss.json',
  )
  expect(yaml).toContain('key: 4422a60e08c97f30')
  expect(yaml).toContain('iv: 8c97f304422a60e0')
})

test('removes legacy COI worker without reloading the page', async ({ page }) => {
  await page.addInitScript(() => {
    const state = globalThis as typeof globalThis & { legacyWorkerUnregistered?: boolean }
    state.legacyWorkerUnregistered = false
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: {
        getRegistrations: async () => [
          {
            installing: null,
            waiting: null,
            active: { scriptURL: 'https://example.test/coi-serviceworker.js' },
            unregister: async () => {
              state.legacyWorkerUnregistered = true
              return true
            },
          },
        ],
      },
    })
  })

  let navigationCount = 0
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigationCount += 1
  })

  await openApp(page)
  await expect.poll(() => page.evaluate(() => {
    const state = globalThis as typeof globalThis & { legacyWorkerUnregistered?: boolean }
    return state.legacyWorkerUnregistered
  })).toBe(true)
  expect(navigationCount).toBe(1)
})

test('hero exposes GitHub and Sub-Store project links', async ({ page }) => {
  await openApp(page)

  await expect(page).toHaveTitle('在 Sub-Store 中获取封端机场订阅节点')
  await expect(
    page.getByRole('heading', { level: 1, name: '在 Sub-Store 中获取封端机场订阅节点' }),
  ).toBeVisible()
  await expect(page.getByText('当前仅适配 Nextin 系客户端')).toBeVisible()
  await expect(page.getByRole('heading', { level: 3, name: '从安装包获取基础配置' })).toBeVisible()
  await expect(page.getByText('说明：从机场/梯子控制台下载 Windows 版本')).toBeVisible()

  const projectLink = page.getByRole('link', { name: '打开 sub cfg export GitHub 项目主页' })
  await expect(projectLink).toHaveAttribute('href', 'https://github.com/alecthw/sub-cfg-export')
  await expect(projectLink).toHaveAttribute('target', '_blank')
  await expect(projectLink).toHaveAttribute('rel', 'noopener noreferrer')

  const subStoreLink = page.getByRole('link', { name: '打开 Sub-Store GitHub 项目主页' })
  await expect(subStoreLink).toHaveAttribute('href', 'https://github.com/sub-store-org')
  await expect(subStoreLink).toHaveAttribute('target', '_blank')
  await expect(subStoreLink).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(subStoreLink.locator('img')).toBeVisible()

  const telegramLink = page.getByRole('link', { name: '打开 alecthw Telegram' })
  await expect(telegramLink).toHaveAttribute('href', 'https://t.me/alecthw')
  await expect(telegramLink).toHaveAttribute('target', '_blank')
  await expect(telegramLink).toHaveAttribute('rel', 'noopener noreferrer')
})

test('requires disclaimer acceptance only on the first visit', async ({ page }) => {
  await page.goto('/')
  const dialog = page.getByRole('dialog', { name: '免责声明与使用须知' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('不会向任何服务器上传您选择的文件')).toBeVisible()

  await dialog.getByRole('button', { name: '同意并继续' }).click()
  await expect(dialog).toBeHidden()
  expect(await page.evaluate(() => localStorage.getItem('sub-cfg-export:disclaimer:v1'))).toBe(
    'accepted',
  )

  await page.reload()
  await expect(page.getByRole('dialog', { name: '免责声明与使用须知' })).toBeHidden()
})

test('rejecting the disclaimer closes or blanks the tool page', async ({ page }) => {
  await page.goto('/')
  const outcome = new Promise<'closed' | 'blank' | 'timeout'>((resolve) => {
    page.once('close', () => resolve('closed'))
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame() && frame.url() === 'about:blank') resolve('blank')
    })
    setTimeout(() => resolve('timeout'), 2000)
  })

  await page.getByRole('button', { name: '拒绝并关闭' }).click().catch(() => undefined)
  expect(await outcome).not.toBe('timeout')
})

test('offers the extraction failure issue template for unsupported installers', async ({ page }) => {
  await openApp(page)
  await page.locator('input[type="file"]').setInputFiles({
    name: 'unsupported-client.exe',
    mimeType: 'application/x-msdownload',
    buffer: Buffer.from('not an Inno Setup installer'),
  })

  const dialog = page.getByRole('dialog', { name: '提取失败，是否提交 Issue？' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('未找到 Inno Setup LZMA2 数据块')).toBeVisible()
  await expect(dialog.getByText('文件名：unsupported-client.exe')).toBeVisible()

  const issueLink = dialog.locator('a[href*="issues/new"]')
  const href = await issueLink.getAttribute('href')
  expect(href).not.toBeNull()
  const issueUrl = new URL(href!)
  expect(issueUrl.origin + issueUrl.pathname).toBe(
    'https://github.com/alecthw/sub-cfg-export/issues/new',
  )
  expect(issueUrl.searchParams.get('template')).toBe('extraction-failure.md')
  expect(issueUrl.searchParams.get('title')).toBe('[提取失败] unsupported-client.exe')
  await expect(issueLink).toHaveAttribute('target', '_blank')
})

test('shows the mobile memory warning before the disclaimer', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    })
  })

  await page.goto('/')
  const mobileDialog = page.getByRole('dialog', { name: '移动端使用提示' })
  await expect(mobileDialog).toBeVisible()
  await expect(
    mobileDialog.getByText('手机浏览器可能由于内存不足导致解析失败，请换 PC 端使用。'),
  ).toBeVisible()
  await expect(page.getByRole('dialog', { name: '免责声明与使用须知' })).toBeHidden()

  await mobileDialog.getByRole('button', { name: '我知道了' }).click()
  await expect(mobileDialog).toBeHidden()
  await expect(page.getByRole('dialog', { name: '免责声明与使用须知' })).toBeVisible()
})

test('exposes crawlable SEO metadata and discovery files', async ({ page }) => {
  await page.goto('/')

  await expect(page).toHaveTitle('在 Sub-Store 中获取封端机场订阅节点')
  await expect(page.locator('meta[name="description"]')).toHaveAttribute(
    'content',
    /Nextin 系 Windows 客户端安装包/,
  )
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute('content', /index, follow/)
  await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
    'href',
    'https://alecthw.github.io/sub-cfg-export/',
  )
  await expect(page.locator('meta[property="og:title"]')).toHaveAttribute(
    'content',
    '在 Sub-Store 中获取封端机场订阅节点',
  )

  const structuredData = JSON.parse(
    (await page.locator('script[type="application/ld+json"]').textContent())!,
  )
  expect(structuredData['@type']).toBe('WebApplication')
  expect(structuredData.url).toBe('https://alecthw.github.io/sub-cfg-export/')

  const robotsResponse = await page.request.get('http://127.0.0.1:43217/robots.txt')
  expect(robotsResponse.ok()).toBe(true)
  expect(await robotsResponse.text()).toContain(
    'Sitemap: https://alecthw.github.io/sub-cfg-export/sitemap.xml',
  )

  const sitemapResponse = await page.request.get('http://127.0.0.1:43217/sitemap.xml')
  expect(sitemapResponse.ok()).toBe(true)
  expect(await sitemapResponse.text()).toContain(
    '<loc>https://alecthw.github.io/sub-cfg-export/</loc>',
  )

  const manifestResponse = await page.request.get('http://127.0.0.1:43217/site.webmanifest')
  expect(manifestResponse.ok()).toBe(true)
  expect((await manifestResponse.json()).name).toBe('在 Sub-Store 中获取封端机场订阅节点')
})

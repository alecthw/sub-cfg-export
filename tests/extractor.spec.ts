import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
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
      '  User-Agent: NetFlow/v3.0.6 clash-verge Platform/linux',
      'decrypt: null',
      '',
    ].join('\n'),
  )

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: '下载 YAML' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('globalcloud-2.2.3-windows-amd64-setup.yaml')
  const savedPath = await download.path()
  expect(savedPath).not.toBeNull()
  expect(await readFile(savedPath!, 'utf8')).toBe(yaml)
})

test('xmtz restores XOR URLs and decrypt values', async ({ page }) => {
  await openApp(page)
  const yaml = await selectInstaller(page, 'xmtzapp-lite.exe')
  expect(yaml).toContain('https://tcdn.getxlx.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://apisa.cnossfile.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://cdno01.llguanglisf.com/saos/xmtz_news.json')
  expect(yaml).toContain('https://ocdn01.llguangli25o.com:59991/saos/xmtz_news.json')
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

  await expect(page).toHaveTitle('封端机场导出Sub-Store订阅')
  await expect(
    page.getByRole('heading', { level: 1, name: '封端机场导出Sub-Store订阅' }),
  ).toBeVisible()
  await expect(page.getByText('说明：从机场/梯子控制台下载')).toBeVisible()

  const projectLink = page.getByRole('link', { name: '打开 sub cfg export GitHub 项目主页' })
  await expect(projectLink).toHaveAttribute('href', 'https://github.com/alecthw/sub-cfg-export')
  await expect(projectLink).toHaveAttribute('target', '_blank')
  await expect(projectLink).toHaveAttribute('rel', 'noopener noreferrer')

  const subStoreLink = page.getByRole('link', { name: '打开 Sub-Store GitHub 项目主页' })
  await expect(subStoreLink).toHaveAttribute('href', 'https://github.com/sub-store-org')
  await expect(subStoreLink).toHaveAttribute('target', '_blank')
  await expect(subStoreLink).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(subStoreLink.locator('img')).toBeVisible()
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

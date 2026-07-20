# sub cfg export

一个纯浏览器、纯静态的封端机场客户端配置提取工具，配合 Sub-Store 可获得订阅节点。

工具界面有详细的使用引导：<https://alecthw.github.io/sub-cfg-export/>

用户选择 Windows EXE 安装包后，程序会在本地解析 Inno Setup 的 LZMA2 数据、扫描配置 URL，并在存在时提取 decrypt key/iv，最后生成完整 YAML。

文件不会上传，也不需要后台服务，可直接部署到 GitHub Pages。

## 输出格式

```yaml
cfgUrls:
  - https://example.com/config.json

username:
password:
headers:
  User-Agent: NetFlow/v3.0.6 clash-verge Platform/linux
decrypt:
  key: 0123456789abcdef
  iv: fedcba9876543210
subscriptionDecrypt:
  type: aes-256-gcm
  password: 86f2e72ead6e985e
```

找不到 key/iv 时 `decrypt` 输出 `null`；未识别到订阅 AES-GCM 口令时不输出 `subscriptionDecrypt`：

```yaml
decrypt: null
```

## 完整调用与解密流程

### 1. 从安装包到 Sub-Store 节点

```mermaid
flowchart TD
    A["用户选择 Windows EXE 安装包"] --> B["File API 将文件交给 Web Worker"]
    B --> C["扫描 Inno Setup 标记 zlb 0x1A"]
    C --> D["读取 raw LZMA2 chunk、property 与解压大小"]
    D --> E["补全最小 XZ 容器"]
    E --> F["node-liblzma WASM 流式解压"]
    F --> G{"解压大小和 payload 是否有效？"}
    G -- "否" --> X1["终止并提示解析失败"]
    G -- "是" --> H["扫描安装包与 Dart Snapshot"]
    H --> I["提取 cfgUrls"]
    I --> J["提取品牌、版本和平台，组合 User-Agent"]
    J --> J1{"User-Agent 信息完整？"}
    J1 -- "是" --> J2["写入安装包中的 User-Agent"]
    J1 -- "否" --> J3["使用默认值 NetFlow/v2.2.4 clash-verge Platform/windows"]
    J2 --> K["按 URL 邻近关系提取 AES-128-CBC key / iv"]
    J3 --> K
    K --> L["识别异或混淆的订阅 AES-GCM password"]
    L --> M["生成完整 YAML"]
    M --> N["用户填写 username / password"]
    N --> O["粘贴为 Sub-Store 本地订阅"]
    O --> P["节点操作调用 provider-api-subscription.js"]
    P --> Q["获取服务地址、登录并取得订阅原始 URL"]
    Q --> R["下载、按候选分支解密并解析"]
    R --> S{"是否得到至少一个有效节点？"}
    S -- "是" --> T["返回节点并缓存可用订阅 URL"]
    S -- "否" --> X2["尝试下一订阅 URL 或 API 服务；全部失败后抛错"]
```

浏览器侧只负责读取安装包并生成 YAML，不上传文件。网络请求和订阅解密发生在执行脚本的 Sub-Store 后端中。

### 2. Sub-Store API 完整调用链

```mermaid
flowchart TD
    A["Sub-Store 读取本地 YAML"] --> B["调用 provider-api-subscription.js"]
    B --> C["解析并校验 cfgUrls、账号、headers 与解密参数"]
    C --> D["计算完整配置 hash，读取订阅 URL 缓存"]
    D --> E{"存在缓存 URL？"}
    E -- "是" --> F["GET 缓存的原始 URL<br/>使用 YAML headers，不追加 flag"]
    F --> G["构造原文、AES-CBC、AES-GCM 内容候选"]
    G --> H["依次调用 ProxyUtils.parse"]
    H --> I{"得到至少一个节点？"}
    I -- "是" --> OK["返回节点并更新 subUserinfo"]
    I -- "否" --> J["清除失效 URL 缓存和自动 subUserinfo"]
    E -- "否" --> K["进入完整刷新流程"]
    J --> K

    K --> L{"已有相同配置的 refreshTasks 任务？"}
    L -- "是" --> L1["复用并等待同一个 Promise"]
    L1 --> L2{"共享任务成功？"}
    L2 -- "是" --> OK
    L2 -- "否" --> ERR
    L -- "否" --> M["创建刷新任务，并在任务内再次读取缓存"]
    M --> N{"复查到缓存 URL？"}
    N -- "是" --> N1["按缓存链下载并解析"]
    N1 --> N2{"缓存链成功？"}
    N2 -- "是" --> OK
    N2 -- "否" --> ERR
    N -- "否" --> O["并发 GET 每个 cfgUrl<br/>固定配置请求 User-Agent"]
    O --> P["Base64 → JSON<br/>失败时尝试 YAML decrypt 的 AES-CBC 解密"]
    P --> P1{"至少一个 cfgUrl 返回有效 hosts？"}
    P1 -- "否" --> ERR
    P1 -- "是" --> Q["合并 hosts 与 host_source 并去重"]
    Q --> R["规范化为 API base URL 列表"]

    R --> S["取下一个 API base URL"]
    S --> T["POST /passport/auth/login<br/>账号密码 + YAML User-Agent"]
    T --> U{"是否取得 auth_data？"}
    U -- "是" --> V["GET /user/getSubscribe<br/>Authorization + YAML User-Agent"]
    V --> W{"是否取得 subscribe_url 或 token？"}
    W -- "是" --> X["生成并去重候选 URL<br/>subscribe_url 优先；token 与所有 API host 组合回退 URL"]
    X --> Y["取下一个候选 URL"]
    Y --> Z["GET 原始候选 URL<br/>使用完整 YAML headers，不追加 flag"]
    Z --> Z1{"下载成功且内容非空？"}
    Z1 -- "是" --> AA["按原文、AES-CBC、AES-GCM 顺序构造并解析候选"]
    Z1 -- "否" --> AD
    AA --> AB{"得到至少一个节点？"}
    AB -- "是" --> AC["缓存可用 URL，写入 subUserinfo 并返回节点"]
    AB -- "否" --> AD{"还有候选 URL？"}
    AD -- "是" --> Y
    AD -- "否" --> AE{"还有 API base URL？"}
    U -- "否" --> AE
    W -- "否" --> AE
    AE -- "是" --> S
    AE -- "否" --> ERR["抛出最终错误：所有 API 与 URL 均失败"]
```

服务地址规范化规则为：已经以 `/api/v1` 结尾的地址直接使用；以 `/api` 结尾的地址依次尝试原地址和 `/api/v1`；其余地址追加 `/api/v1`。`token` 回退地址固定为 `API host/client/subscribe?token=...`。所有最终订阅请求均使用 YAML `headers` 中的 `User-Agent`，不会追加 `flag=clash-verge` 或 `flag=clash`。

### 3. 配置与订阅解密分支

```mermaid
flowchart TD
    subgraph CONFIG["cfgUrl 配置内容"]
        direction TB
        C0["cfgUrl 响应 body"] --> C1["规范化 Base64：去 BOM、兼容 URL-safe 字符"]
        C1 --> C2["Base64 解码为 UTF-8"]
        C2 --> C3{"能否解析为 JSON？"}
        C3 -- "是" --> C9["读取 hosts 与 host_source"]
        C3 -- "否" --> C4{"YAML decrypt 是否存在？"}
        C4 -- "否" --> CE["该 cfgUrl 失败"]
        C4 -- "是" --> C5["Base64 解码为 AES 密文字节"]
        C5 --> C6["AES-128-CBC 解密<br/>key 与 iv 均按 UTF-8 取 16 字节"]
        C6 --> C7["将解密结果作为 Base64 再解码为 UTF-8"]
        C7 --> C8{"能否解析为 JSON？"}
        C8 -- "是" --> C9
        C8 -- "否" --> CE
    end

    subgraph SUBSCRIPTION["最终订阅内容"]
        direction TB
        S0["使用原始 URL + YAML headers 下载响应"] --> S1["候选列表加入原始响应文本"]
        S1 --> S2{"YAML decrypt 是否存在？"}
        S2 -- "是" --> S3["AES-128-CBC<br/>Base64 → AES 解密 → Base64 → UTF-8"]
        S3 --> S31{"CBC 解密成功？"}
        S31 -- "是" --> S4["将 CBC 明文加入候选列表"]
        S31 -- "否" --> S5["读取 subscriptionDecrypt<br/>缺省时使用内置 AES-GCM 配置"]
        S2 -- "否" --> S5["读取 subscriptionDecrypt<br/>缺省时使用内置 AES-GCM 配置"]
        S4 --> S5
        S5 --> S6["Base64 解码全部密文字节"]
        S6 --> S7["前 12 字节 = nonce<br/>末 16 字节 = authentication tag<br/>中间字节 = ciphertext"]
        S7 --> S8["SHA-256(UTF-8 password) 得到 32 字节 AES key"]
        S8 --> S9["AES-256-GCM 解密<br/>设置 tag，不使用 AAD"]
        S9 --> S10{"Node crypto 可用，且 tag 校验与 UTF-8 输出成功？"}
        S10 -- "是" --> S11["将 GCM 明文加入候选列表"]
        S10 -- "否" --> S12["不加入 GCM 候选"]
        S11 --> P0["按原文、CBC、GCM 顺序调用 ProxyUtils.parse"]
        S12 --> P0
        P0 --> P1{"返回数组且节点数大于 0？"}
        P1 -- "是" --> OK["返回节点、缓存 URL、更新 subUserinfo"]
        P1 -- "否" --> NEXT["尝试下一内容候选；随后尝试下一 URL / API host"]
    end

    C9 -->|"配置提供 API hosts"| S0
    CE -->|"尝试下一个 cfgUrl；全部失败则终止"| STOP["配置获取失败"]
```

两组解密参数彼此独立：

- `decrypt.key` / `decrypt.iv` 使用 **AES-128-CBC**，既可解密加密的 `cfgUrl` 配置，也可生成最终订阅的 CBC 解密候选。两者虽然通常长得像 16 位十六进制字符串，代码实际按 UTF-8 字符串取 16 字节，并非按 hex 转换成 8 字节。
- `subscriptionDecrypt.password` 使用 **AES-256-GCM**，只用于最终订阅。密文布局为 `Base64(nonce[12] + ciphertext + tag[16])`，密钥为 `SHA-256(UTF-8(password))`，不使用 AAD。未输出该字段时，脚本会使用内置口令 `86f2e72ead6e985e` 作为兼容回退。
- 每种解密失败只会丢弃对应候选；原文、CBC 和 GCM 候选按顺序独立交给 `ProxyUtils.parse()`，其中任一候选解析出非空节点数组即成功。
- CBC 与 GCM 均通过 Node.js `crypto` 实现，因此需要运行在 Node.js 后端版 Sub-Store；非 Node.js 运行环境仍可尝试解析无需解密的原始订阅内容。

## 技术方案

- React 19 + Ant Design 6
- Vite 8 + TypeScript 7
- Web Worker 内解析，避免阻塞页面
- `node-liblzma` 提供非线程 liblzma WebAssembly
- File API 本地读取，Blob API 下载 YAML

Inno Setup 内保存的是 raw LZMA2 数据。解析器先读取 LZMA2 chunk 边界与解压大小，再在内存中补成最小 XZ 容器，交给 liblzma WASM 流式解压。liblzma 源码不复制进本项目，由 npm 依赖管理。

## 本地开发

需要 Node.js 22 或更高版本，推荐 Node.js 24。

```bash
npm install
npm run dev
```

生产构建与预览：

```bash
npm run build
npm run preview
```

真实样本端到端测试：

```bash
npx playwright install chromium
npm run test:e2e
```

测试默认读取项目根目录中的：

- `globalcloud-2.2.3-windows-amd64-setup.exe`
- `xmtzapp-lite.exe`

EXE 与生成的 YAML 已加入 `.gitignore`，不会被默认提交。

## GitHub Pages 部署

项目已包含 `.github/workflows/deploy-pages.yml`。将仓库推送到 `main` 后：

1. Workflow 会执行 `npm ci` 和 `npm run build`。
2. 构建结果 `dist/` 会以 orphan commit 发布到 `gh-pages` 分支。
3. 在 GitHub 仓库的 Settings → Pages 中选择 **Deploy from a branch**，分支选择 `gh-pages`，目录选择 `/ (root)`。

也可以在 Actions 页面手动运行 `Deploy GitHub Pages` Workflow。Vite 使用相对 `base`，因此兼容 GitHub Pages 的项目子路径。

## 支持范围与安全限制

- 当前支持包含 `zlb\x1a` Inno Setup raw LZMA2 数据块的兼容安装包。
- 输入仅接受 `.exe`，页面限制为 512 MiB。
- 解压与扫描均在 Worker 中完成；浏览器内存不足时会返回错误，不会上传或回传安装包内容。
- URL 仅选择 HTTP/HTTPS 的 JSON 地址；key/iv 仅在可确认的 Dart Snapshot 邻近数据中输出。

## 第三方组件

liblzma WASM 由 [`node-liblzma`](https://github.com/oorabona/node-liblzma) 提供，其许可证为 LGPL-3.0。详见 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。

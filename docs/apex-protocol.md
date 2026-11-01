# Apex speed 新版分析与适配

样本：xmtz 7.1.1、xjkp 7.2.5。分析日期：2026-11-01。

## 原因

1. Inno Setup 改为多个独立 LZMA2 数据流。第一个约 17 KiB 的 JSON 只是文件清单；原实现直接返回第一段，未读取真正的 Dart 应用。两份样本的 `data/app.so` 均为 17,990,544 字节，解压后 SHA-256 与清单一致。浏览器按流的解压大小筛选后验证文件 hash；Python 按清单大小和 hash 校验。
2. 新版协议由 SecurityNet / SN2 改为 Apex。配置、API、订阅分别要求不同用途的 mTLS 证书。同一 OSS 地址不带证书返回 404，使用 OSS 证书返回完整配置。
3. 两品牌有各自的 XOR 密钥、配置公钥、订阅 AES 密钥、订阅公钥和三类证书，不能互换。证书 profile_id 分别为 16 和 17；APXS 协议头中的 profile/key ID 在这两份样本中均为 1，与证书 profile_id 无关。
4. 实际 UA 是应用包名加 `/v` 和主程序版本。反汇编确认其构造方式，另行解包 Apex.exe 确认主程序版本与安装器一致。仅使用 SDK 回退 UA `Apex-SDK` 时真实 API 返回 Cloudflare 403；使用实际 UA 后登录成功。
5. 远程配置新增 `domains`、`subscribe_domain`、`enable_api_path_mapping` 和 `subscribe_path`。登录 API 仍可能返回旧订阅域名，必须按已验签配置切换域名、路径和查询参数，并设定 `flag=apex`。仅对旧域名忽略 TLS 校验无法解决此问题。
6. APXS 是二进制，提前转换为 UTF-8 会破坏密文。必须先验签、认证解密，之后才交给节点解析器。

## 提取

从独立 ELF 的 Dart Snapshot 恢复 String cluster 和序列化 ObjectPool；以 `apex-config-v1`、`apex-sub-sign-v2` 锚点寻找密钥。订阅锚点之前的两个 32 字节值分别为 AES 密钥、签名公钥，其角色已用真实响应验证。XOR 密钥从唯一符合大小写字母、数字混合的 32 字节候选提取；候选不唯一时明确失败，不猜测品牌常量。证书由内嵌 Base64 JSON 的 version/purpose/profile_id 识别。

## 配置封装

响应 Base64 解码后，以安装包提取的 XOR key 循环异或，得到：

```json
{"format":"apex-config-v1","payload":"<base64>","signature":"<base64>"}
```

Ed25519 消息是 `UTF8("apex-config-v1\0") || Base64Decode(payload)`，其中 `\0` 是一个 NUL 字节。验签成功后才能使用 payload 内的域名和路由。

## APXS v2

| 字节范围 | 含义 |
| --- | --- |
| 0–3 | ASCII `APXS` |
| 4 | 版本 2 |
| 5–8 | uint32 big-endian profile ID |
| 9–12 | uint32 big-endian key ID |
| 13–24 | 12 字节 nonce |
| 25 至倒数第 81 字节 | AES-GCM ciphertext |
| 倒数第 80 至倒数第 65 字节 | 16 字节 GCM tag |
| 最后 64 字节 | Ed25519 signature |

签名消息：`UTF8("apex-sub-sign-v2\0") || blob[:-64]`。

AAD：`UTF8("apex-sub-v2\0") || blob[:25]`。

AES-256-GCM key 直接 Base64 解码为 32 字节，不做 SHA-256 派生。任何签名、ID 或 GCM 认证失败都拒绝解析，不降级到明文或其他解密格式。

本地保存的 `apex-url-v2:` URL 先 Base64 解码，再用 XOR key 还原。请求只使用安装包内的配置地址和已验签配置中的 API / 订阅域名。旧域名仅提供待替换的路径和 token，不作为新版证书请求目标。

## 验证范围

- 两份真实 EXE 的浏览器提取通过；YAML 与 Python 提取逐字节一致，包含 IPv6 配置 URL、品牌密钥和 PEM 换行。
- 两品牌的真实 OSS 配置均通过 mTLS 获取及 Ed25519 验签。
- xmtz 用户授权账号的真实登录、订阅下载、签名和 GCM 认证成功；构建后的公共脚本使用真实 Sub-Store 解析器取得 **32 个 VLESS 节点**，缓存刷新同样取得 32 个。
- xjkp 已使用用户授权账号完成真实登录、订阅下载、APXS 签名及 GCM 认证；首次获取和缓存刷新均由真实 Sub-Store 解析器得到 **42 个 VLESS 节点**。
- 本地真实 TLS 服务验证 OSS / API / subscription 证书分别发送；合成签名样本验证篡改拒绝、错误品牌公钥、ID、AES 密钥与 AAD 拒绝，以及路由映射、旧域名替换、URL 包装和缓存。
- 旧版提取及运行时测试继续通过。测试夹具现场生成密钥及证书，运行 provider 测试需可用的 OpenSSL 命令。

账号密码、订阅令牌、真实节点及客户端证书私钥未写入此说明或测试代码。

## 三品牌兼容性复核（2026-11-01）

用户补充 globalcloud 2.2.3 安装包并授权三品牌使用相同账号后，使用当前构建的 `public/provider-api-subscription.js`、安装包导出的原始配置和真实 Sub-Store 节点解析器完成复核。账号仅在本地实测进程中填写，导出的 YAML 保持账号密码留空。

| 品牌与安装包 | 协议 | 首次获取 | 缓存刷新 | 节点协议 |
| --- | --- | --- | --- | --- |
| xmtz speed 7.1.1 | Apex v2 | 32 个 | 32 个 | VLESS |
| xjkp speed 7.2.5 | Apex v2 | 42 个 | 42 个 | VLESS |
| globalcloud 2.2.3 安装包 | 旧版 provider | 68 个 | 68 个 | VLESS |

Globalcloud 的四个配置镜像、登录、getSubscribe 和订阅下载均返回 200，解析出实际节点。安装包导出的 UA 为 `NetFlow/v2.2.4 clash-verge Platform/windows`；此次验证保持提取器输出，未按安装包文件名改写 UA。新旧协议保持兼容，本轮未修改脚本逻辑。

41 项提取器与 provider 回归测试通过；4 项针对当前真实样本的浏览器测试通过（globalcloud 导出、两品牌 Apex 导出及旧协议请求行为）。这里只验证订阅获取和节点配置解析，未逐节点连接测试。

## Apex 流量信息回写修复

原 Apex 分支在进入下载前清理自动流量链接，下载成功后只返回节点，因此本地订阅缺少 `subUserinfo`，Sub-Store 的流量接口无法显示用量。通用流量查询客户端也不携带新版所需的 mTLS 证书，直接回填订阅 URL 无法可靠解决。

修复后，在 APXS 验签、GCM 认证及节点解析均成功后，优先从 `subscription-userinfo` 响应头提取并校验数字字段，回写 Sub-Store 支持的流量字面量。缺少有效响应头时使用 `getSubscribe` 中的 `u`、`d`、`transfer_enable`、`expired_at`、`reset_day`；缓存刷新仍无流量时保留同一 URL 的有效快照。

流量快照末尾以独立分号片段保留原有自动生成标记，Sub-Store 的流量解析器和下载头规范化函数会忽略该片段。旧自动流量 URL 能自动迁移；用户手填链接、手填流量值及已修改内容的其他订阅不会被覆盖。并发共享下载的每个本地订阅分别回写，失败刷新保留原有效流量信息。

回归测试覆盖首次写入、缓存更新、API 数据回退、自动 URL 迁移、手动配置保护、同账号并发订阅及认证失败保护。真实账号验证使用 Sub-Store 源码中的 `getFlowInfo`、`parseFlowHeaders` 和 `normalizeFlowHeader` 检查流量接口和下载头，确认其数值与真实订阅响应一致。

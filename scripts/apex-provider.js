// Apex v2 is intentionally a separate path: legacy clients keep their original
// portable transports and cipher formats. mTLS requires Node's TLS APIs.
export async function runApexProvider({ config, runtime, timeout, proxy, sensitiveValues, errorMessage, cacheKey }) {
  const process = globalThis.process;
  if (!runtime?.loadModule || !process) {
    throw new Error('Apex 新版需要支持 Node.js 内置模块及 mTLS 的 Sub-Store 后端');
  }
  const { crypto, Buffer: B } = runtime;
  const apex = config.apex;
  const bytes = (v) => B.from(v, 'base64');
  const text = (v) => B.from(v).toString('utf8');
  const maxBytes = 16 * 1024 * 1024 + 105;
  const xor = (v) => {
    const key = B.from(apex.xorKey, 'utf8');
    return B.from(bytes(v).map((byte, i) => byte ^ key[i % key.length]));
  };
  const publicKey = (v) => crypto.createPublicKey({
    key: B.concat([B.from('302a300506032b6570032100', 'hex'), bytes(v)]),
    format: 'der', type: 'spki',
  });
  function verify(key, prefix, payload, signature, label) {
    if (signature.length !== 64 || !crypto.verify(null, B.concat([B.from(prefix), payload]), publicKey(key), signature)) {
      throw new Error(`${label} Ed25519 签名校验失败`);
    }
  }
  function unwrapURL(value) {
    return value.startsWith('apex-url-v2:') ? text(xor(value.slice(12))) : value;
  }
  function httpsURL(value) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Apex 仅允许 HTTPS 服务地址');
    return url;
  }
  async function request(urlValue, purpose, { method = 'GET', auth, body } = {}) {
    const url = httpsURL(urlValue);
    const bundle = apex.mtls[purpose];
    const tls = { cert: bundle.client_cert_pem, key: bundle.client_key_pem, rejectUnauthorized: purpose !== 'subscription' };
    const headers = {
      ...config.headers,
      'User-Agent': Object.entries(config.headers).find(([name]) => name.toLowerCase() === 'user-agent')?.[1] || 'Apex-SDK',
      Accept: '*/*', 'Cache-Control': 'no-cache',
      ...(auth ? { Authorization: auth } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    };
    const encoded = body ? JSON.stringify(body) : undefined;
    let response;
    const envProxy = process.env?.https_proxy || process.env?.HTTPS_PROXY || process.env?.all_proxy || process.env?.ALL_PROXY;
    const selectedProxy = proxy || envProxy;
    if (selectedProxy) {
      // Sub-Store's HTTP wrapper replaces its dispatcher and drops cert/key.
      // Load its installed undici directly so mTLS also reaches proxy tunnels.
      const require = runtime.loadModule('module').createRequire(`${process.cwd()}/package.json`);
      let undici;
      try { undici = require('undici'); } catch { throw new Error('Apex 代理请求需要 Sub-Store 后端安装 undici'); }
      const options = { connect: tls, requestTls: tls };
      let dispatcher;
      if (/^socks5h?:\/\//i.test(selectedProxy)) {
        const { socksDispatcher } = require('fetch-socks');
        const parsed = new URL(selectedProxy);
        dispatcher = socksDispatcher({ type: 5, host: parsed.hostname, port: Number(parsed.port || 1080), userId: decodeURIComponent(parsed.username), password: decodeURIComponent(parsed.password) }, options);
      } else {
        dispatcher = new undici.ProxyAgent({ ...options, uri: selectedProxy });
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const result = await undici.request(url, { dispatcher, method, headers, body: encoded, signal: controller.signal, headersTimeout: timeout, bodyTimeout: timeout, maxRedirections: 0 });
        const chunks = [];
        let length = 0;
        for await (const chunk of result.body) {
          length += chunk.length;
          if (length > maxBytes) { result.body.destroy(); throw new Error('Apex 响应超过大小限制'); }
          chunks.push(B.from(chunk));
        }
        response = { status: result.statusCode, headers: result.headers, body: B.concat(chunks) };
      } finally { clearTimeout(timer); await dispatcher.close(); }
    } else {
      const https = runtime.loadModule('https');
      response = await new Promise((resolve, reject) => {
        const req = https.request(url, { ...tls, method, headers, agent: false }, (res) => {
          const chunks = [];
          let length = 0;
          res.on('data', (chunk) => {
            length += chunk.length;
            if (length > maxBytes) { res.destroy(new Error('Apex 响应超过大小限制')); return; }
            chunks.push(B.from(chunk));
          });
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: B.concat(chunks) }));
          res.on('error', reject);
        });
        const timer = setTimeout(() => req.destroy(new Error('Apex 请求超时')), timeout);
        req.on('close', () => clearTimeout(timer));
        req.on('error', reject);
        req.end(encoded);
      });
    }
    if (response.status !== 200) {
      const cloudflare = /Cloudflare/i.test(text(response.body.subarray(0, 2048))) ? '（Cloudflare 拦截）' : '';
      throw new Error(`Apex ${purpose} HTTP ${response.status}${cloudflare}`);
    }
    return response;
  }
  function decodeConfig(body) {
    const envelope = JSON.parse(text(xor(text(body).trim())));
    if (envelope.format !== 'apex-config-v1') throw new Error('Apex 配置封装格式无效');
    const payload = bytes(envelope.payload);
    verify(apex.configPublicKey, 'apex-config-v1\0', payload, bytes(envelope.signature), 'Apex 配置');
    const cfg = JSON.parse(text(payload));
    if (!Array.isArray(cfg.domains) || !cfg.domains.length) throw new Error('Apex 配置缺少 domains');
    cfg.domains.forEach(httpsURL);
    if (cfg.subscribe_domain != null && !Array.isArray(cfg.subscribe_domain)) throw new Error('Apex subscribe_domain 格式无效');
    (cfg.subscribe_domain || []).forEach(httpsURL);
    return cfg;
  }
  function decryptSubscription(body) {
    if (body.length < 105 || body.length > maxBytes || text(body.subarray(0, 4)) !== 'APXS' || body[4] !== 2) {
      throw new Error('Apex APXS v2 订阅封装无效');
    }
    if (body.readUInt32BE(5) !== apex.profileId || body.readUInt32BE(9) !== apex.keyId) {
      throw new Error('Apex APXS profile/key ID 不匹配');
    }
    verify(apex.subscriptionPublicKey, 'apex-sub-sign-v2\0', body.subarray(0, -64), body.subarray(-64), 'Apex 订阅');
    const decipher = crypto.createDecipheriv('aes-256-gcm', bytes(apex.subscriptionKey), body.subarray(13, 25));
    decipher.setAAD(B.concat([B.from('apex-sub-v2\0'), body.subarray(0, 25)]));
    decipher.setAuthTag(body.subarray(-80, -64));
    try { return text(B.concat([decipher.update(body.subarray(25, -80)), decipher.final()])); }
    catch { throw new Error('Apex APXS AES-GCM 认证失败'); }
  }
  const failures = [];
  let cfg;
  for (const url of config.cfgUrls) {
    try { cfg = decodeConfig((await request(url, 'oss')).body); break; }
    catch (error) { failures.push(`配置 ${httpsURL(url).origin}: ${errorMessage(error)}`); }
  }
  if (!cfg) throw new Error(`Apex 配置获取失败: ${failures.join('；')}`);
  const path = (original) => {
    if (cfg.enable_api_path_mapping !== true) return original;
    const mapped = cfg.subscribe_path?.[original];
    if (typeof mapped !== 'string' || !mapped.startsWith('/') || mapped.startsWith('//') || mapped.includes('#')) {
      throw new Error(`Apex 配置缺少有效 API 路由: ${original}`);
    }
    return mapped;
  };
  const apiURL = (domain, original) => new URL(path(original), httpsURL(domain)).href;
  const domains = [...new Set(cfg.domains)];
  const subscriptionDomains = cfg.subscribe_domain?.length ? cfg.subscribe_domain : domains;
  const allowedOrigins = new Set([...domains, ...subscriptionDomains].map((v) => httpsURL(v).origin));
  function subscriptionURLs(value, token) {
    const urls = [];
    if (value) {
      const url = httpsURL(unwrapURL(value));
      const original = '/api/v1/client/subscribe?token=';
      if (`${url.pathname}?token=` === original && url.searchParams.has('token')) {
        const mapped = new URL(path(original) + encodeURIComponent(url.searchParams.get('token')), url.origin);
        for (const [name, val] of url.searchParams) if (name !== 'token') mapped.searchParams.set(name, val);
        if (allowedOrigins.has(mapped.origin)) urls.push(mapped);
        else for (const domain of subscriptionDomains) urls.push(new URL(mapped.pathname + mapped.search, httpsURL(domain)));
      } else if (allowedOrigins.has(url.origin)) urls.push(url);
      else for (const domain of subscriptionDomains) urls.push(new URL(url.pathname + url.search, httpsURL(domain)));
    }
    if (token) for (const domain of subscriptionDomains) urls.push(new URL(path('/api/v1/client/subscribe?token=') + encodeURIComponent(token), httpsURL(domain)));
    return [...new Set(urls.map((url) => {
      if (!allowedOrigins.has(url.origin)) throw new Error('Apex 订阅地址不在已验签配置的服务域名中');
      url.searchParams.set('flag', apex.flag);
      url.hash = '';
      return url.href;
    }))];
  }
  // Sub-Store's generic flow HTTP client cannot present Apex certificates.
  // Return a validated literal flow snapshot alongside the authenticated nodes.
  function normalizeFlow(values) {
    const numeric = (value) => {
      if (typeof value !== 'number' && typeof value !== 'string') return null;
      if (String(value).trim() === '') return null;
      const number = Number(value);
      return Number.isFinite(number) && number >= 0 ? number : null;
    };
    const upload = values.upload == null ? 0 : numeric(values.upload);
    const download = numeric(values.download);
    const total = numeric(values.total);
    if (upload == null || download == null || total == null) return '';
    const fields = [`upload=${upload}`, `download=${download}`, `total=${total}`];
    const expire = numeric(values.expire);
    const resetDay = numeric(values.reset_day);
    if (expire > 0) fields.push(`expire=${expire}`);
    if (resetDay != null) fields.push(`reset_day=${resetDay}`);
    return fields.join('; ');
  }
  function responseFlow(headers) {
    const header = Object.entries(headers || {}).find(([name]) => name.toLowerCase() === 'subscription-userinfo')?.[1];
    if (typeof header !== 'string') return '';
    const fields = Object.create(null);
    for (const part of header.split(';')) {
      const index = part.indexOf('=');
      if (index > 0) fields[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).trim();
    }
    return normalizeFlow(fields);
  }
  const flowCacheKey = `${cacheKey}:userinfo`;
  const download = async (url, apiUserinfo = '') => {
    const response = await request(url, 'subscription');
    const nodes = ProxyUtils.parse(decryptSubscription(response.body));
    if (!Array.isArray(nodes) || !nodes.length) throw new Error('Apex 订阅未解析到有效节点');
    const cachedFlow = $substore.read(flowCacheKey);
    const userinfo = responseFlow(response.headers) || apiUserinfo ||
      (cachedFlow?.url === url ? cachedFlow.userinfo : '') || '';
    $substore.write(url, cacheKey);
    if (userinfo) $substore.write({ url, userinfo }, flowCacheKey);
    return { nodes, userinfo };
  };
  const cached = $substore.read(cacheKey);
  if (cached) {
    try { for (const url of subscriptionURLs(cached)) return await download(url); }
    catch (error) { $substore.write('', cacheKey); $substore.info(`Apex 缓存失效，重新登录: ${errorMessage(error)}`); }
  }
  for (const domain of domains) {
    let stage = '登录';
    try {
      const login = JSON.parse(text((await request(apiURL(domain, '/api/v1/passport/auth/login'), 'api', { method: 'POST', body: { email: config.username, password: config.password } })).body));
      const auth = login?.data?.auth_data;
      if (typeof auth !== 'string' || !auth) throw new Error('Apex 登录响应缺少 auth_data');
      sensitiveValues.push(auth);
      stage = '获取订阅地址';
      const sub = JSON.parse(text((await request(apiURL(domain, '/api/v1/user/getSubscribe'), 'api', { auth })).body))?.data;
      if (!sub || (!sub.subscribe_url && !sub.token)) throw new Error('Apex getSubscribe 缺少 subscribe_url/token');
      if (sub.token) sensitiveValues.push(sub.token);
      const userinfo = normalizeFlow({ upload: sub.u, download: sub.d, total: sub.transfer_enable, expire: sub.expired_at, reset_day: sub.reset_day });
      stage = '下载订阅';
      for (const url of subscriptionURLs(sub.subscribe_url, sub.token)) {
        try { return await download(url, userinfo); }
        catch (error) { failures.push(`下载订阅 ${httpsURL(url).origin}: ${errorMessage(error)}`); }
      }
    } catch (error) { failures.push(`${stage} ${httpsURL(domain).origin}: ${errorMessage(error)}`); }
  }
  throw new Error(`Apex 订阅获取失败: ${[...new Set(failures)].join('；')}`);
}

export function normalizeApex(value) {
  if (value == null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('provider 参数 apex 必须为对象');
  for (const name of ['configPublicKey', 'subscriptionPublicKey', 'subscriptionKey']) {
    if (typeof value[name] !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value[name])) throw new Error(`Apex ${name} 必须为 32 字节 Base64`);
  }
  if (typeof value.xorKey !== 'string' || !/^[A-Za-z0-9]{32}$/.test(value.xorKey)) throw new Error('Apex xorKey 无效');
  if (!/^[a-z][a-z0-9]*$/.test(value.flag) || !Number.isInteger(value.profileId) || !Number.isInteger(value.keyId) || value.profileId < 1 || value.keyId < 1) throw new Error('Apex flag/profileId/keyId 无效');
  const ids = new Set();
  for (const purpose of ['oss', 'api', 'subscription']) {
    const bundle = value.mtls?.[purpose];
    if (bundle?.version !== 1 || bundle.purpose !== purpose || !Number.isInteger(bundle.profile_id) || !bundle.client_cert_pem?.startsWith('-----BEGIN CERTIFICATE-----') || !bundle.client_key_pem?.startsWith('-----BEGIN PRIVATE KEY-----')) throw new Error(`Apex ${purpose} 客户端证书缺失或用途错误`);
    ids.add(bundle.profile_id);
  }
  if (ids.size !== 1) throw new Error('Apex 三组客户端证书品牌不一致');
  return value;
}

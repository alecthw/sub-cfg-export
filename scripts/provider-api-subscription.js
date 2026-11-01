import { runApexProvider, normalizeApex } from "./apex-provider.js";
import { AES_CBC } from "asmcrypto.js/dist_es8/aes/cbc.js";
import { AES_GCM } from "asmcrypto.js/dist_es8/aes/gcm.js";
import { Sha256 } from "asmcrypto.js/dist_es8/hash/sha256/sha256.js";

/**
 * Sub-Store Script Operator: provider API subscription
 *
 * Usage:
 * 1. Create a local subscription and paste the provider YAML into its content.
 * 2. Add a "Script Operator" and fill in the public URL of this script.
 * 3. After the first successful run, refresh the Sub-Store page to display
 *    subscription traffic information.
 *
 * Local subscription content example:
 *
 * cfgUrls:
 *   - https://example.com/config.json
 * username:
 * password:
 * headers:
 *   User-Agent: NetFlow/v3.0.6 clash-verge Platform/linux
 * decrypt: null
 * subscriptionDecrypt:
 *   type: aes-256-gcm
 *   password: example-password
 */

async function operator(proxies, targetPlatform, context) {
  const CFG_USER_AGENT = "Mozilla/5.0 (dart:io) SuperAccelerator";
  const DEFAULT_SUBSCRIPTION_DECRYPT = Object.freeze({
    type: "aes-256-gcm",
    password: "86f2e72ead6e985e",
  });
  const CACHE_PREFIX = "provider-api-subscription:";
  const SUBSCRIBE_URL_CACHE_PREFIX =
    "#sub-store-cached-provider-script-subscribe-url-";
  const BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let nodeRuntime;
  let nodeRuntimeResolved = false;

  const raw = Array.isArray(context?.raw)
    ? context.raw.filter((item) => item != null).join("\n")
    : context?.raw == null
    ? ""
    : String(context.raw);
  const sensitiveValues = [];
  const config = parseConfig(raw);
  sensitiveValues.push(config.username, config.password);
  const activeSubscriptionHeaders = config.headers;
  const configHash = getHash(stableStringify(config));
  const subscribeUrlCacheKey = `${SUBSCRIBE_URL_CACHE_PREFIX}${configHash}`;
  const subscribeUuidCacheKey = `${CACHE_PREFIX}uuid:${configHash}`;
  let subscriptionUuid = normalizeString($substore.read(subscribeUuidCacheKey)).trim();
  if (subscriptionUuid) sensitiveValues.push(subscriptionUuid);
  const settings = $substore.read("settings") || {};
  const timeout = positiveNumber($arguments?.timeout)
    ? Number($arguments.timeout)
    : settings.defaultTimeout || 8000;
  const proxy =
    $arguments?.proxy ||
    settings.defaultProxy ||
    globalThis.process?.env?.SUB_STORE_BACKEND_DEFAULT_PROXY;

  if (config.apex) {
    const key = Symbol.for("sub-store.provider-api-subscription.refresh-tasks");
    const tasks = globalThis[key] instanceof Map ? globalThis[key] : (globalThis[key] = new Map());
    const refreshKey = `${CACHE_PREFIX}apex-refresh:${configHash}`;
    let task = tasks.get(refreshKey);
    if (!task) {
      task = runApexProvider({ config, runtime: getNodeRuntime(), timeout, proxy,
        sensitiveValues, errorMessage, cacheKey: `${CACHE_PREFIX}apex-url:${configHash}` });
      tasks.set(refreshKey, task);
    }
    try {
      const { nodes, userinfo } = await task;
      persistApexSubUserinfo(userinfo);
      return nodes;
    } finally {
      if (tasks.get(refreshKey) === task) tasks.delete(refreshKey);
    }
  }

  const fetchAndParse = async (subscribeUrl) => {
    let lastError;
    const requestUrl = normalizeString(subscribeUrl).split("#")[0].trim();
    try {
      const content = await fetchSubscriptionContent(requestUrl);
      const candidates = [content];
      const isSn2 = content.trim().startsWith("SN2.");
      if (isSn2) {
        candidates.splice(0, 1, await decryptSn2Subscription(content));
      }
      if (!isSn2 && config.decrypt) {
        try {
          candidates.push(await decryptAesBase64(content, config.decrypt));
        } catch (error) {
          lastError = error;
        }
      }
      if (!isSn2 && config.subscriptionDecrypt) {
        try {
          candidates.push(
            await decryptSubscriptionContent(content, config.subscriptionDecrypt)
          );
        } catch (error) {
          lastError = error;
        }
      }
      if (!isSn2) {
        try {
          // Official fallback maps the mirrored alphabet back to standard
          // Base64 before decoding the subscription text.
          const mirrored = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210/+";
          const normalized = content.trim().replace(/[A-Za-z0-9+/]/g,
            (char) => BASE64_ALPHABET[mirrored.indexOf(char)]);
          candidates.push(bytesToUtf8(base64ToBytes(normalized)));
        } catch {
          // Plain subscriptions and other encrypted formats remain candidates.
        }
      }
      for (const candidate of candidates) {
        try {
          const parsed = ProxyUtils.parse(candidate);
          if (!Array.isArray(parsed) || parsed.length === 0) {
            throw new Error("provider API 订阅未解析到有效节点");
          }
          return parsed;
        } catch (error) {
          lastError = error;
        }
      }
    } catch (error) {
      lastError = error;
    }
    throw lastError || new Error("provider API 订阅未解析到有效节点");
  };

  const cachedSubscribeUrl = normalizeString(
    $substore.read(subscribeUrlCacheKey)
  ).trim();
  if (cachedSubscribeUrl) {
    try {
      const parsed = await fetchAndParse(cachedSubscribeUrl);
      persistSubUserinfo(cachedSubscribeUrl);
      return parsed;
    } catch (error) {
      $substore.info(
        `provider API 缓存的订阅地址已失效，将重新获取: ${errorMessage(error)}`
      );
      $substore.write("", subscribeUrlCacheKey);
      $substore.write("", subscribeUuidCacheKey);
      subscriptionUuid = "";
      clearAutoSubUserinfo();
    }
  }

  const refreshTasksKey = Symbol.for(
    "sub-store.provider-api-subscription.refresh-tasks"
  );
  const refreshTasks =
    globalThis[refreshTasksKey] instanceof Map
      ? globalThis[refreshTasksKey]
      : (globalThis[refreshTasksKey] = new Map());
  const refreshKey = `${CACHE_PREFIX}refresh:${configHash}`;
  if (refreshTasks.has(refreshKey)) return refreshTasks.get(refreshKey);

  const task = (async () => {
    const refreshedCachedUrl = normalizeString(
      $substore.read(subscribeUrlCacheKey)
    ).trim();
    if (refreshedCachedUrl) {
      subscriptionUuid = normalizeString($substore.read(subscribeUuidCacheKey)).trim();
      if (subscriptionUuid) sensitiveValues.push(subscriptionUuid);
      const parsed = await fetchAndParse(refreshedCachedUrl);
      persistSubUserinfo(refreshedCachedUrl);
      return parsed;
    }

    const baseURLs = await fetchBaseURLs();
    // The official API interceptor uses its own UA; the client brand/version
    // in config.headers is reserved for subscription downloads.
    const authHeaders = {
      "User-Agent": CFG_USER_AGENT,
      Accept: "application/json",
    };

    const failures = [];
    for (const baseURL of baseURLs) {
      let stage = "登录";
      try {
        const authData = await login(baseURL, authHeaders);
        sensitiveValues.push(authData);
        stage = "获取订阅地址";
        const { subscribeUrl, token, uuid } = await getSubscribe(
          baseURL,
          authData,
          authHeaders
        );
        if (token) sensitiveValues.push(token);
        subscriptionUuid = uuid;
        if (uuid) sensitiveValues.push(uuid);
        const candidates = [subscribeUrl];
        if (token) {
          for (const fallbackBaseURL of baseURLs) {
            candidates.push(fallbackSubscribeURL(fallbackBaseURL, token));
          }
        }

        for (const candidate of unique(candidates.filter(Boolean))) {
          try {
            const parsed = await fetchAndParse(candidate);
            $substore.write(candidate, subscribeUrlCacheKey);
            $substore.write(subscriptionUuid, subscribeUuidCacheKey);
            persistSubUserinfo(candidate);
            return parsed;
          } catch (error) {
            failures.push(
              `下载订阅 ${requestOrigin(candidate)}: ${errorMessage(error)}`
            );
          }
        }
      } catch (error) {
        failures.push(`${stage} ${requestOrigin(baseURL)}: ${errorMessage(error)}`);
      }
    }
    throw new Error(
      `provider API 订阅获取失败: ${unique(failures).join("；") || "无可用订阅地址"}`
    );
  })();

  refreshTasks.set(refreshKey, task);
  try {
    return await task;
  } finally {
    refreshTasks.delete(refreshKey);
  }

  function parseConfig(content) {
    let value;
    try {
      const parse = yaml.parse || yaml.safeLoad || yaml.load;
      value = parse.call(yaml, normalizeString(content));
    } catch (error) {
      throw new Error(`provider 参数 YAML 解析失败: ${errorMessage(error)}`);
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("provider 参数 YAML 必须为对象");
    }

    const cfgUrls = (
      Array.isArray(value.cfgUrls)
        ? value.cfgUrls
        : value.cfgUrls == null
        ? []
        : [value.cfgUrls]
    )
      .map((url) => normalizeString(url).trim())
      .filter(Boolean);
    if (cfgUrls.length === 0) {
      throw new Error("provider 参数 cfgUrls 不能为空");
    }

    return {
      cfgUrls,
      apex: normalizeApex(value.apex),
      username: normalizeString(value.username),
      password: normalizeString(value.password),
      headers: normalizeHeaders(value.headers),
      decrypt: normalizeDecrypt(value.decrypt),
      subscriptionDecrypt: normalizeSubscriptionDecrypt(
        value.subscriptionDecrypt
      ) || DEFAULT_SUBSCRIPTION_DECRYPT,
    };
  }

  function normalizeDecrypt(decrypt) {
    if (decrypt == null) return null;
    if (typeof decrypt !== "object" || Array.isArray(decrypt)) {
      throw new Error("provider 参数 decrypt 必须为 null 或对象");
    }
    return {
      key: normalizeString(decrypt.key),
      iv: normalizeString(decrypt.iv),
    };
  }

  function normalizeSubscriptionDecrypt(decrypt) {
    if (decrypt == null) return null;
    if (typeof decrypt !== "object" || Array.isArray(decrypt)) {
      throw new Error("provider 参数 subscriptionDecrypt 必须为 null 或对象");
    }
    const type = normalizeString(decrypt.type).trim().toLowerCase();
    const password = normalizeString(decrypt.password).trim();
    if (type !== "aes-256-gcm") {
      throw new Error("provider 参数 subscriptionDecrypt.type 仅支持 aes-256-gcm");
    }
    if (!password) {
      throw new Error("provider 参数 subscriptionDecrypt.password 不能为空");
    }
    return { type, password };
  }

  async function fetchBaseURLs() {
    const results = await Promise.all(
      config.cfgUrls.map(async (cfgUrl) => {
        try {
          return await fetchConfigHosts(cfgUrl);
        } catch (error) {
          $substore.error(
            `provider cfgUrl ${requestOrigin(cfgUrl)} 获取失败: ${errorMessage(error)}`
          );
          return [];
        }
      })
    );
    const candidates = results
      .flat()
      .flatMap((host) => baseURLCandidates(host));
    const baseURLs = unique(candidates);
    if (baseURLs.length === 0) {
      throw new Error("provider cfgUrl 未返回可用的服务地址");
    }
    return baseURLs;
  }

  async function fetchConfigHosts(cfgUrl) {
    const response = await request("get", cfgUrl, {
      headers: { "User-Agent": CFG_USER_AGENT },
    });
    let cfg;
    try {
      cfg = JSON.parse(decodeBase64Text(response.body));
    } catch (plainError) {
      if (!config.decrypt) {
        throw new Error(`cfgUrl 内容解析失败: ${errorMessage(plainError)}`);
      }
      try {
        cfg = JSON.parse(await decryptOssConfig(response.body, config.decrypt));
      } catch (decryptError) {
        throw new Error(
          `cfgUrl 内容解密失败: ${errorMessage(decryptError)}`
        );
      }
    }
    const hosts = [
      ...(Array.isArray(cfg?.hosts) ? cfg.hosts : []),
      cfg?.host_source,
    ]
      .map((host) => normalizeString(host).trim())
      .filter(Boolean);
    if (hosts.length === 0) throw new Error("cfgUrl 未返回可用 hosts");
    return hosts;
  }

  async function login(baseURL, headers) {
    const response = await request("post", `${baseURL}/passport/auth/login`, {
      headers: {
        ...headers,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: config.username,
        password: config.password,
      }),
    });
    const data = parseJSON(response.body, "登录响应");
    const authData = normalizeString(data?.data?.auth_data).trim();
    if (!authData) throw new Error("登录响应缺少 auth_data");
    return authData;
  }

  async function getSubscribe(baseURL, authData, headers) {
    const response = await request("get", `${baseURL}/user/getSubscribe`, {
      headers: { ...headers, Authorization: authData },
    });
    const data = parseJSON(response.body, "getSubscribe 响应")?.data || {};
    const subscribeUrl = normalizeString(data.subscribe_url).trim();
    const token = normalizeString(data.token).trim();
    const uuid = normalizeString(data.uuid).trim();
    if (!subscribeUrl && !token) {
      throw new Error("getSubscribe 响应缺少 subscribe_url 或 token");
    }
    return { subscribeUrl, token, uuid };
  }

  async function fetchSubscriptionContent(subscribeUrl) {
    const response = await request("get", subscribeUrl, {
      headers: config.headers,
      encoding: null,
      // Subscription CDN certificates may not cover the advertised hostname.
      // Match Sub-Store's runtime-specific option without weakening API TLS.
      ...($substore.env?.isNode ? { strictSSL: false } : { insecure: true }),
    });
    const content = bodyToText(response.body);
    if (!content.trim()) throw new Error("provider API 订阅内容为空");
    if (/^\s*(?:<!doctype\s+html\b|<html\b)/i.test(content)) {
      throw new Error("订阅地址返回 HTML 验证页或错误页，未收到节点配置");
    }
    return content;
  }

  async function decryptOssConfig(body, decrypt) {
    return decryptAesBase64(body, decrypt);
  }

  async function decryptSubscriptionContent(body, decrypt) {
    const encrypted = base64ToBytes(bodyToText(body));
    if (encrypted.length <= 28) {
      throw new Error("AES-GCM 订阅密文长度无效");
    }
    const nonce = encrypted.subarray(0, 12);
    const tag = encrypted.subarray(encrypted.length - 16);
    const ciphertext = encrypted.subarray(12, encrypted.length - 16);
    const sealed = encrypted.subarray(12);
    const password = utf8ToBytes(decrypt.password);
    const runtime = getNodeRuntime();

    if (runtime) {
      try {
        const key = runtime.crypto
          .createHash("sha256")
          .update(runtime.Buffer.from(password))
          .digest();
        const decipher = runtime.crypto.createDecipheriv(
          "aes-256-gcm",
          key,
          runtime.Buffer.from(nonce)
        );
        decipher.setAuthTag(runtime.Buffer.from(tag));
        const plainText = runtime.Buffer.concat([
          decipher.update(runtime.Buffer.from(ciphertext)),
          decipher.final(),
        ]);
        return plainText.toString("utf8");
      } catch {
        // Continue with WebCrypto or the bundled pure JavaScript fallback.
      }
    }

    const webCryptoPlainText = await tryWebCryptoGcm(password, nonce, sealed);
    if (webCryptoPlainText) return bytesToUtf8(webCryptoPlainText);

    const hasher = new Sha256();
    const key = hasher.process(password).finish().result;
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("AES-GCM SHA-256 密钥派生失败");
    }
    return bytesToUtf8(AES_GCM.decrypt(sealed, key, nonce, undefined, 16));
  }

  async function decryptSn2Subscription(body) {
    const parts = body.trim().split(".");
    const expiresAt = Number(parts[1]);
    if (parts.length !== 3 || !/^\d+$/.test(parts[1]) || !Number.isSafeInteger(expiresAt)) {
      throw new Error("SN2 订阅封装格式无效");
    }
    if (Math.floor(Date.now() / 1000) > expiresAt) {
      throw new Error("SN2 订阅已过期，请重新获取");
    }
    if (!subscriptionUuid) {
      throw new Error("SN2 订阅解密缺少账号 UUID，getSubscribe 未返回 uuid");
    }
    // SecurityNet 3.2.1: SHA-256(fixed 32-byte seed || UTF-8(account UUID)),
    // followed by the same nonce/ciphertext/tag layout as legacy AES-GCM.
    const seed = /^[0-9a-f]{32}$/.test(config.subscriptionDecrypt?.password)
      ? config.subscriptionDecrypt.password
      : "66d570165fad0012ba46077644ac1ba6";
    return decryptSubscriptionContent(parts[2], {
      password: `${seed}${subscriptionUuid}`,
    });
  }

  async function decryptAesBase64(body, decrypt) {
    const key = utf8ToBytes(decrypt.key);
    const iv = utf8ToBytes(decrypt.iv);
    if (key.length !== 16 || iv.length !== 16) {
      throw new Error("AES key 和 iv 必须均为 16 字节");
    }
    const encrypted = base64ToBytes(bodyToText(body));
    const runtime = getNodeRuntime();

    if (runtime) {
      try {
        const decipher = runtime.crypto.createDecipheriv(
          "aes-128-cbc",
          runtime.Buffer.from(key),
          runtime.Buffer.from(iv)
        );
        const plainText = runtime.Buffer.concat([
          decipher.update(runtime.Buffer.from(encrypted)),
          decipher.final(),
        ]);
        return decodeNestedBase64(
          new Uint8Array(plainText.buffer, plainText.byteOffset, plainText.byteLength)
        );
      } catch {
        // Continue with WebCrypto or the bundled pure JavaScript fallback.
      }
    }

    const webCryptoPlainText = await tryWebCryptoCbc(key, iv, encrypted);
    if (webCryptoPlainText) {
      try {
        return decodeNestedBase64(webCryptoPlainText);
      } catch {
        // Some host WebCrypto implementations handle CBC padding differently.
      }
    }

    return decodeNestedBase64(AES_CBC.decrypt(encrypted, key, true, iv));
  }

  function decodeNestedBase64(value) {
    return bytesToUtf8(base64ToBytes(bytesToUtf8(value).trim()));
  }

  function getNodeRuntime() {
    if (nodeRuntimeResolved) return nodeRuntime;
    nodeRuntimeResolved = true;
    nodeRuntime = null;
    if (!$substore.env?.isNode) return nodeRuntime;
    try {
      const loadModule = globalThis.process?.getBuiltinModule
        ? (name) => globalThis.process.getBuiltinModule(name)
        : typeof require === "function" ? (name) => require(name) : null;
      const crypto = loadModule?.("crypto");
      const NodeBuffer = globalThis.Buffer;
      if (
        typeof crypto?.createDecipheriv === "function" &&
        typeof crypto?.createHash === "function" &&
        typeof NodeBuffer?.from === "function"
      ) {
        nodeRuntime = { crypto, Buffer: NodeBuffer, loadModule };
      }
    } catch {
      nodeRuntime = null;
    }
    return nodeRuntime;
  }

  function getWebCryptoSubtle(requiredMethods) {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) return null;
    return requiredMethods.every((method) => typeof subtle[method] === "function")
      ? subtle
      : null;
  }

  async function tryWebCryptoCbc(key, iv, encrypted) {
    const subtle = getWebCryptoSubtle(["importKey", "decrypt"]);
    if (!subtle) return null;
    try {
      const cryptoKey = await subtle.importKey(
        "raw",
        key,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
      );
      const plainText = await subtle.decrypt(
        { name: "AES-CBC", iv },
        cryptoKey,
        encrypted
      );
      return new Uint8Array(plainText);
    } catch {
      return null;
    }
  }

  async function tryWebCryptoGcm(password, nonce, sealed) {
    const subtle = getWebCryptoSubtle(["digest", "importKey", "decrypt"]);
    if (!subtle) return null;
    try {
      const keyBytes = new Uint8Array(await subtle.digest("SHA-256", password));
      const cryptoKey = await subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      const plainText = await subtle.decrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        cryptoKey,
        sealed
      );
      return new Uint8Array(plainText);
    } catch {
      return null;
    }
  }

  function decodeBase64Text(value) {
    return bytesToUtf8(base64ToBytes(value));
  }

  function normalizeBase64(value) {
    return normalizeString(value)
      .trim()
      .replace(/^\uFEFF/, "")
      .replace(/\s+/g, "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");
  }

  function base64ToBytes(value) {
    const normalized = normalizeBase64(value);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
      throw new Error("Base64 内容包含无效字符");
    }
    const input = normalized.replace(/=+$/, "");
    if (input.length % 4 === 1) throw new Error("Base64 内容长度无效");

    const output = new Uint8Array(Math.floor((input.length * 6) / 8));
    let accumulator = 0;
    let bits = 0;
    let outputPos = 0;
    for (let index = 0; index < input.length; index++) {
      const digit = BASE64_ALPHABET.indexOf(input[index]);
      if (digit < 0) throw new Error("Base64 内容包含无效字符");
      accumulator = (accumulator << 6) | digit;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        output[outputPos++] = (accumulator >>> bits) & 0xff;
        accumulator &= (1 << bits) - 1;
      }
    }
    return output;
  }

  function utf8ToBytes(value) {
    const text = normalizeString(value);
    if (typeof TextEncoder !== "undefined") {
      try {
        return new TextEncoder().encode(text);
      } catch {
        // Fall through to the portable encoder.
      }
    }
    const bytes = [];
    for (let index = 0; index < text.length; index++) {
      let codePoint = text.charCodeAt(index);
      if (codePoint >= 0xd800 && codePoint <= 0xdbff && index + 1 < text.length) {
        const next = text.charCodeAt(index + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (next - 0xdc00);
          index++;
        }
      }
      if (codePoint <= 0x7f) {
        bytes.push(codePoint);
      } else if (codePoint <= 0x7ff) {
        bytes.push(0xc0 | (codePoint >>> 6), 0x80 | (codePoint & 0x3f));
      } else if (codePoint <= 0xffff) {
        bytes.push(
          0xe0 | (codePoint >>> 12),
          0x80 | ((codePoint >>> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      } else {
        bytes.push(
          0xf0 | (codePoint >>> 18),
          0x80 | ((codePoint >>> 12) & 0x3f),
          0x80 | ((codePoint >>> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      }
    }
    return Uint8Array.from(bytes);
  }

  function bytesToUtf8(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    if (typeof TextDecoder !== "undefined") {
      try {
        return new TextDecoder("utf-8").decode(bytes);
      } catch {
        // Fall through to the portable decoder.
      }
    }
    let output = "";
    for (let index = 0; index < bytes.length; ) {
      const first = bytes[index++];
      let codePoint;
      let continuationCount;
      if (first <= 0x7f) {
        codePoint = first;
        continuationCount = 0;
      } else if ((first & 0xe0) === 0xc0) {
        codePoint = first & 0x1f;
        continuationCount = 1;
      } else if ((first & 0xf0) === 0xe0) {
        codePoint = first & 0x0f;
        continuationCount = 2;
      } else if ((first & 0xf8) === 0xf0) {
        codePoint = first & 0x07;
        continuationCount = 3;
      } else {
        throw new Error("UTF-8 内容无效");
      }
      for (let offset = 0; offset < continuationCount; offset++) {
        const next = bytes[index++];
        if (next === undefined || (next & 0xc0) !== 0x80) {
          throw new Error("UTF-8 内容无效");
        }
        codePoint = (codePoint << 6) | (next & 0x3f);
      }
      if (codePoint <= 0xffff) {
        output += String.fromCharCode(codePoint);
      } else {
        codePoint -= 0x10000;
        output += String.fromCharCode(
          0xd800 | (codePoint >>> 10),
          0xdc00 | (codePoint & 0x3ff)
        );
      }
    }
    return output;
  }

  function bodyToText(value) {
    if ($substore.env?.isNode && typeof Buffer !== "undefined") {
      if (
        Buffer.isBuffer(value) ||
        value instanceof ArrayBuffer ||
        ArrayBuffer.isView(value)
      ) {
        return toBuffer(value).toString("utf8");
      }
    }
    return normalizeString(value);
  }

  async function request(method, url, options = {}) {
    const requestOptions = {
      url,
      timeout,
      ...options,
      ...(proxy ? getProxyOptions(proxy) : {}),
    };
    const response = await $substore.http[method](requestOptions);
    if (!response || response.statusCode !== 200 || response.body == null) {
      throw new Error(
        `provider API 请求返回状态码 ${response?.statusCode ?? "unknown"}`
      );
    }
    return response;
  }

  function getProxyOptions(selectedProxy) {
    const options = { proxy: selectedProxy };
    if ($substore.env?.isLoon) options.node = selectedProxy;
    if ($substore.env?.isQX) options.opts = { policy: selectedProxy };
    return options;
  }

  function buildSubUserinfoUrl(url, headers) {
    return buildUrlArguments(url, headers, {
      providerScriptAutoSubUserinfo: true,
      insecure: true,
    });
  }

  function buildUrlArguments(url, headers, extraArguments = {}) {
    const baseUrl = normalizeString(url).split("#")[0];
    const argumentsObject = { ...extraArguments };
    if (Object.keys(headers).length > 0) {
      argumentsObject.headers = JSON.stringify(headers);
    }
    if (Object.keys(argumentsObject).length === 0) return baseUrl;
    return `${baseUrl}#${encodeURIComponent(JSON.stringify(argumentsObject))}`;
  }

  function persistSubUserinfo(subscribeUrl) {
    updateStoredSubscriptions((sub) => {
      if (sub.subUserinfo && !isAutoSubUserinfo(sub.subUserinfo)) return false;
      const nextValue = buildSubUserinfoUrl(subscribeUrl, activeSubscriptionHeaders);
      if (sub.subUserinfo === nextValue) return false;
      sub.subUserinfo = nextValue;
      return true;
    });
  }

  function persistApexSubUserinfo(userinfo) {
    if (!userinfo) return;
    // A separate semicolon-delimited marker reuses legacy auto-ownership
    // detection; Sub-Store ignores it when normalizing numeric flow headers.
    const marker = encodeURIComponent(JSON.stringify({ providerScriptAutoSubUserinfo: true }));
    const nextValue = `${userinfo}; #${marker}`;
    updateStoredSubscriptions((sub) => {
      if (sub.subUserinfo && !isAutoSubUserinfo(sub.subUserinfo)) return false;
      if (sub.subUserinfo === nextValue) return false;
      sub.subUserinfo = nextValue;
      return true;
    });
  }

  function clearAutoSubUserinfo() {
    updateStoredSubscriptions((sub) => {
      if (!isAutoSubUserinfo(sub.subUserinfo)) return false;
      delete sub.subUserinfo;
      return true;
    });
  }

  function updateStoredSubscriptions(update) {
    const source = context?.source;
    if (!source || typeof source !== "object" || Array.isArray(source)) return;
    const sourceEntries = Object.entries(source).filter(
      ([name, sub]) =>
        !name.startsWith("_") &&
        sub &&
        typeof sub === "object" &&
        sub.source === "local"
    );
    if (sourceEntries.length === 0) return;

    const allSubs = $substore.read("subs");
    if (!Array.isArray(allSubs)) return;
    let changed = false;
    for (const [name, sourceSub] of sourceEntries) {
      const sub = allSubs.find((item) => item?.name === name);
      if (!sub || sub.source !== "local") continue;
      if (sub.content !== sourceSub.content) continue;
      if (update(sub)) changed = true;
    }
    if (changed) $substore.write(allSubs, "subs");
  }

  function isAutoSubUserinfo(value) {
    const fragment = normalizeString(value).split("#")[1];
    if (!fragment) return false;
    try {
      const argumentsObject = JSON.parse(decodeURIComponent(fragment));
      return argumentsObject?.providerScriptAutoSubUserinfo === true;
    } catch (error) {
      return false;
    }
  }

  function baseURLCandidates(baseURL) {
    const normalized = normalizeBaseURL(baseURL);
    if (!normalized) return [];
    if (normalized.endsWith("/api/v1")) return [normalized];
    if (normalized.endsWith("/api")) {
      return [normalized, `${normalized}/v1`];
    }
    return [`${normalized}/api/v1`];
  }

  function fallbackSubscribeURL(baseURL, token) {
    return `${normalizeBaseURL(
      baseURL
    )}/client/subscribe?token=${encodeURIComponent(token)}`;
  }

  function normalizeBaseURL(value) {
    return normalizeString(value).trim().replace(/\/+$/, "");
  }

  function normalizeHeaders(headers) {
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
      return {};
    }
    return Object.fromEntries(
      Object.entries(headers)
        .filter(([key, value]) => key && value != null)
        .map(([key, value]) => [String(key), String(value)])
    );
  }

  function getHeader(headers, name) {
    const target = name.toLowerCase();
    const entry = Object.entries(headers).find(
      ([key]) => key.toLowerCase() === target
    );
    return entry?.[1];
  }

  function stableStringify(value) {
    if (Array.isArray(value)) {
      return `[${value.map(stableStringify).join(",")}]`;
    }
    if (value && typeof value === "object") {
      return `{${Object.keys(value)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
        .join(",")}}`;
    }
    return JSON.stringify(value);
  }

  function getHash(value) {
    if (typeof ProxyUtils.hex_md5 === "function") {
      return ProxyUtils.hex_md5(value);
    }
    let hash = 2166136261;
    for (let index = 0; index < value.length; index++) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function parseJSON(value, label) {
    try {
      return JSON.parse(normalizeString(value));
    } catch (error) {
      throw new Error(`${label} JSON 解析失败: ${errorMessage(error)}`);
    }
  }

  function toBuffer(value) {
    if (Buffer.isBuffer(value)) return value;
    if (value instanceof ArrayBuffer) return Buffer.from(value);
    if (ArrayBuffer.isView(value)) {
      return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    return Buffer.from(value);
  }

  function normalizeString(value) {
    return value == null ? "" : String(value);
  }

  function positiveNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0;
  }

  function unique(values) {
    return [...new Set(values)];
  }

  function errorMessage(error) {
    const messages = [];
    const seen = new Set();
    for (let current = error; current != null && !seen.has(current); current = current?.cause) {
      seen.add(current);
      messages.push(current?.message ?? String(current));
      if (current?.code) messages.push(String(current.code));
      if (seen.size >= 4) break;
    }
    let message = unique(messages).join(": ");
    // HTTP runtimes may include the complete request URL in an error. Keep
    // diagnostics useful without exposing query tokens or login credentials.
    message = message.replace(/([?&][^=&#\s]+)=([^&#\s]*)/g, "$1=[redacted]");
    for (const secret of sensitiveValues) {
      if (!secret) continue;
      message = message.split(secret).join("[redacted]");
      message = message.split(encodeURIComponent(secret)).join("[redacted]");
    }
    return message;
  }

  function requestOrigin(url) {
    return normalizeString(url).match(/^https?:\/\/([^/?#]+)/i)?.[0]
      .replace(/\/\/[^/@]+@/, "//[redacted]@") || "未知服务";
  }
}

export { operator };

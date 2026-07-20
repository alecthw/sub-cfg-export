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

  const raw = Array.isArray(context?.raw)
    ? context.raw.filter((item) => item != null).join("\n")
    : context?.raw == null
    ? ""
    : String(context.raw);
  const config = parseConfig(raw);
  const activeSubscriptionHeaders = config.headers;
  const configHash = getHash(stableStringify(config));
  const subscribeUrlCacheKey = `${SUBSCRIBE_URL_CACHE_PREFIX}${configHash}`;
  const settings = $substore.read("settings") || {};
  const timeout = positiveNumber($arguments?.timeout)
    ? Number($arguments.timeout)
    : settings.defaultTimeout || 8000;
  const proxy =
    $arguments?.proxy ||
    settings.defaultProxy ||
    globalThis.process?.env?.SUB_STORE_BACKEND_DEFAULT_PROXY;

  const fetchAndParse = async (subscribeUrl) => {
    let lastError;
    const requestUrl = normalizeString(subscribeUrl).split("#")[0].trim();
    try {
      const content = await fetchSubscriptionContent(requestUrl);
      const candidates = [content];
      if (config.decrypt) {
        try {
          candidates.push(decryptAesBase64(content, config.decrypt));
        } catch (error) {
          lastError = error;
        }
      }
      if (config.subscriptionDecrypt) {
        try {
          candidates.push(
            decryptSubscriptionContent(content, config.subscriptionDecrypt)
          );
        } catch (error) {
          lastError = error;
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
      const parsed = await fetchAndParse(refreshedCachedUrl);
      persistSubUserinfo(refreshedCachedUrl);
      return parsed;
    }

    const baseURLs = await fetchBaseURLs();
    const authHeaders = {};
    const configuredUserAgent = getHeader(config.headers, "user-agent");
    if (configuredUserAgent) {
      authHeaders["User-Agent"] = configuredUserAgent;
    }

    let lastError;
    for (const baseURL of baseURLs) {
      try {
        const authData = await login(baseURL, authHeaders);
        const { subscribeUrl, token } = await getSubscribe(
          baseURL,
          authData,
          authHeaders
        );
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
            persistSubUserinfo(candidate);
            return parsed;
          } catch (error) {
            lastError = error;
          }
        }
      } catch (error) {
        lastError = error;
      }
    }
    throw new Error(
      `provider API 订阅获取失败: ${errorMessage(
        lastError || "无可用订阅地址"
      )}`
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
          $substore.error(`provider cfgUrl 获取失败: ${errorMessage(error)}`);
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
        cfg = JSON.parse(decryptOssConfig(response.body, config.decrypt));
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
    if (!subscribeUrl && !token) {
      throw new Error("getSubscribe 响应缺少 subscribe_url 或 token");
    }
    return { subscribeUrl, token };
  }

  async function fetchSubscriptionContent(subscribeUrl) {
    const response = await request("get", subscribeUrl, {
      headers: config.headers,
      encoding: null,
    });
    const content = bodyToText(response.body);
    if (!content.trim()) throw new Error("provider API 订阅内容为空");
    return content;
  }

  function decryptOssConfig(body, decrypt) {
    return decryptAesBase64(body, decrypt);
  }

  function decryptSubscriptionContent(body, decrypt) {
    if (!$substore.env?.isNode || typeof require !== "function") {
      throw new Error("订阅 AES-GCM 解密仅支持运行在 Node.js 后端的 Sub-Store");
    }
    const crypto = require("crypto");
    const encrypted = Buffer.from(normalizeBase64(bodyToText(body)), "base64");
    if (encrypted.length <= 28) {
      throw new Error("AES-GCM 订阅密文长度无效");
    }
    const nonce = encrypted.subarray(0, 12);
    const tag = encrypted.subarray(encrypted.length - 16);
    const ciphertext = encrypted.subarray(12, encrypted.length - 16);
    const key = crypto
      .createHash("sha256")
      .update(Buffer.from(decrypt.password, "utf8"))
      .digest();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      "utf8"
    );
  }

  function decryptAesBase64(body, decrypt) {
    if (!$substore.env?.isNode || typeof require !== "function") {
      throw new Error("AES 解密仅支持运行在 Node.js 后端的 Sub-Store");
    }
    const crypto = require("crypto");
    const key = Buffer.from(decrypt.key);
    const iv = Buffer.from(decrypt.iv);
    if (key.length !== 16 || iv.length !== 16) {
      throw new Error("AES key 和 iv 必须均为 16 字节");
    }
    const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
    const plainText = Buffer.concat([
      decipher.update(Buffer.from(normalizeBase64(body), "base64")),
      decipher.final(),
    ]);
    return Buffer.from(plainText.toString("utf8").trim(), "base64").toString(
      "utf8"
    );
  }

  function decodeBase64Text(value) {
    return b64d(normalizeBase64(value));
  }

  function normalizeBase64(value) {
    return normalizeString(value)
      .trim()
      .replace(/^\uFEFF/, "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");
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
    return error?.message ?? String(error);
  }
}

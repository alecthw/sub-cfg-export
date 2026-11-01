var ProviderApiSubscription = (function(exports) {
	Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
	//#region scripts/apex-provider.js
	async function runApexProvider({ config, runtime, timeout, proxy, sensitiveValues, errorMessage, cacheKey }) {
		var _cfg$subscribe_domain;
		const process = globalThis.process;
		if (!(runtime === null || runtime === void 0 ? void 0 : runtime.loadModule) || !process) throw new Error("Apex 新版需要支持 Node.js 内置模块及 mTLS 的 Sub-Store 后端");
		const { crypto, Buffer: B } = runtime;
		const apex = config.apex;
		const bytes = (v) => B.from(v, "base64");
		const text = (v) => B.from(v).toString("utf8");
		const maxBytes = 16777321;
		const xor = (v) => {
			const key = B.from(apex.xorKey, "utf8");
			return B.from(bytes(v).map((byte, i) => byte ^ key[i % key.length]));
		};
		const publicKey = (v) => crypto.createPublicKey({
			key: B.concat([B.from("302a300506032b6570032100", "hex"), bytes(v)]),
			format: "der",
			type: "spki"
		});
		function verify(key, prefix, payload, signature, label) {
			if (signature.length !== 64 || !crypto.verify(null, B.concat([B.from(prefix), payload]), publicKey(key), signature)) throw new Error(`${label} Ed25519 签名校验失败`);
		}
		function unwrapURL(value) {
			return value.startsWith("apex-url-v2:") ? text(xor(value.slice(12))) : value;
		}
		function httpsURL(value) {
			const url = new URL(value);
			if (url.protocol !== "https:" || url.username || url.password) throw new Error("Apex 仅允许 HTTPS 服务地址");
			return url;
		}
		async function request(urlValue, purpose, { method = "GET", auth, body } = {}) {
			var _Object$entries$find, _process$env, _process$env2, _process$env3, _process$env4;
			const url = httpsURL(urlValue);
			const bundle = apex.mtls[purpose];
			const tls = {
				cert: bundle.client_cert_pem,
				key: bundle.client_key_pem,
				rejectUnauthorized: purpose !== "subscription"
			};
			const headers = {
				...config.headers,
				"User-Agent": ((_Object$entries$find = Object.entries(config.headers).find(([name]) => name.toLowerCase() === "user-agent")) === null || _Object$entries$find === void 0 ? void 0 : _Object$entries$find[1]) || "Apex-SDK",
				Accept: "*/*",
				"Cache-Control": "no-cache",
				...auth ? { Authorization: auth } : {},
				...body ? { "Content-Type": "application/json" } : {}
			};
			const encoded = body ? JSON.stringify(body) : void 0;
			let response;
			const envProxy = ((_process$env = process.env) === null || _process$env === void 0 ? void 0 : _process$env.https_proxy) || ((_process$env2 = process.env) === null || _process$env2 === void 0 ? void 0 : _process$env2.HTTPS_PROXY) || ((_process$env3 = process.env) === null || _process$env3 === void 0 ? void 0 : _process$env3.all_proxy) || ((_process$env4 = process.env) === null || _process$env4 === void 0 ? void 0 : _process$env4.ALL_PROXY);
			const selectedProxy = proxy || envProxy;
			if (selectedProxy) {
				const require = runtime.loadModule("module").createRequire(`${process.cwd()}/package.json`);
				let undici;
				try {
					undici = require("undici");
				} catch (_unused) {
					throw new Error("Apex 代理请求需要 Sub-Store 后端安装 undici");
				}
				const options = {
					connect: tls,
					requestTls: tls
				};
				let dispatcher;
				if (/^socks5h?:\/\//i.test(selectedProxy)) {
					const { socksDispatcher } = require("fetch-socks");
					const parsed = new URL(selectedProxy);
					dispatcher = socksDispatcher({
						type: 5,
						host: parsed.hostname,
						port: Number(parsed.port || 1080),
						userId: decodeURIComponent(parsed.username),
						password: decodeURIComponent(parsed.password)
					}, options);
				} else dispatcher = new undici.ProxyAgent({
					...options,
					uri: selectedProxy
				});
				const controller = new AbortController();
				const timer = setTimeout(() => controller.abort(), timeout);
				try {
					const result = await undici.request(url, {
						dispatcher,
						method,
						headers,
						body: encoded,
						signal: controller.signal,
						headersTimeout: timeout,
						bodyTimeout: timeout,
						maxRedirections: 0
					});
					const chunks = [];
					let length = 0;
					for await (const chunk of result.body) {
						length += chunk.length;
						if (length > maxBytes) {
							result.body.destroy();
							throw new Error("Apex 响应超过大小限制");
						}
						chunks.push(B.from(chunk));
					}
					response = {
						status: result.statusCode,
						headers: result.headers,
						body: B.concat(chunks)
					};
				} finally {
					clearTimeout(timer);
					await dispatcher.close();
				}
			} else {
				const https = runtime.loadModule("https");
				response = await new Promise((resolve, reject) => {
					const req = https.request(url, {
						...tls,
						method,
						headers,
						agent: false
					}, (res) => {
						const chunks = [];
						let length = 0;
						res.on("data", (chunk) => {
							length += chunk.length;
							if (length > maxBytes) {
								res.destroy(/* @__PURE__ */ new Error("Apex 响应超过大小限制"));
								return;
							}
							chunks.push(B.from(chunk));
						});
						res.on("end", () => resolve({
							status: res.statusCode,
							headers: res.headers,
							body: B.concat(chunks)
						}));
						res.on("error", reject);
					});
					const timer = setTimeout(() => req.destroy(/* @__PURE__ */ new Error("Apex 请求超时")), timeout);
					req.on("close", () => clearTimeout(timer));
					req.on("error", reject);
					req.end(encoded);
				});
			}
			if (response.status !== 200) {
				const cloudflare = /Cloudflare/i.test(text(response.body.subarray(0, 2048))) ? "（Cloudflare 拦截）" : "";
				throw new Error(`Apex ${purpose} HTTP ${response.status}${cloudflare}`);
			}
			return response;
		}
		function decodeConfig(body) {
			const envelope = JSON.parse(text(xor(text(body).trim())));
			if (envelope.format !== "apex-config-v1") throw new Error("Apex 配置封装格式无效");
			const payload = bytes(envelope.payload);
			verify(apex.configPublicKey, "apex-config-v1\0", payload, bytes(envelope.signature), "Apex 配置");
			const cfg = JSON.parse(text(payload));
			if (!Array.isArray(cfg.domains) || !cfg.domains.length) throw new Error("Apex 配置缺少 domains");
			cfg.domains.forEach(httpsURL);
			if (cfg.subscribe_domain != null && !Array.isArray(cfg.subscribe_domain)) throw new Error("Apex subscribe_domain 格式无效");
			(cfg.subscribe_domain || []).forEach(httpsURL);
			return cfg;
		}
		function decryptSubscription(body) {
			if (body.length < 105 || body.length > maxBytes || text(body.subarray(0, 4)) !== "APXS" || body[4] !== 2) throw new Error("Apex APXS v2 订阅封装无效");
			if (body.readUInt32BE(5) !== apex.profileId || body.readUInt32BE(9) !== apex.keyId) throw new Error("Apex APXS profile/key ID 不匹配");
			verify(apex.subscriptionPublicKey, "apex-sub-sign-v2\0", body.subarray(0, -64), body.subarray(-64), "Apex 订阅");
			const decipher = crypto.createDecipheriv("aes-256-gcm", bytes(apex.subscriptionKey), body.subarray(13, 25));
			decipher.setAAD(B.concat([B.from("apex-sub-v2\0"), body.subarray(0, 25)]));
			decipher.setAuthTag(body.subarray(-80, -64));
			try {
				return text(B.concat([decipher.update(body.subarray(25, -80)), decipher.final()]));
			} catch (_unused2) {
				throw new Error("Apex APXS AES-GCM 认证失败");
			}
		}
		const failures = [];
		let cfg;
		for (const url of config.cfgUrls) try {
			cfg = decodeConfig((await request(url, "oss")).body);
			break;
		} catch (error) {
			failures.push(`配置 ${httpsURL(url).origin}: ${errorMessage(error)}`);
		}
		if (!cfg) throw new Error(`Apex 配置获取失败: ${failures.join("；")}`);
		const path = (original) => {
			var _cfg$subscribe_path;
			if (cfg.enable_api_path_mapping !== true) return original;
			const mapped = (_cfg$subscribe_path = cfg.subscribe_path) === null || _cfg$subscribe_path === void 0 ? void 0 : _cfg$subscribe_path[original];
			if (typeof mapped !== "string" || !mapped.startsWith("/") || mapped.startsWith("//") || mapped.includes("#")) throw new Error(`Apex 配置缺少有效 API 路由: ${original}`);
			return mapped;
		};
		const apiURL = (domain, original) => new URL(path(original), httpsURL(domain)).href;
		const domains = [...new Set(cfg.domains)];
		const subscriptionDomains = ((_cfg$subscribe_domain = cfg.subscribe_domain) === null || _cfg$subscribe_domain === void 0 ? void 0 : _cfg$subscribe_domain.length) ? cfg.subscribe_domain : domains;
		const allowedOrigins = new Set([...domains, ...subscriptionDomains].map((v) => httpsURL(v).origin));
		function subscriptionURLs(value, token) {
			const urls = [];
			if (value) {
				const url = httpsURL(unwrapURL(value));
				const original = "/api/v1/client/subscribe?token=";
				if (`${url.pathname}?token=` === original && url.searchParams.has("token")) {
					const mapped = new URL(path(original) + encodeURIComponent(url.searchParams.get("token")), url.origin);
					for (const [name, val] of url.searchParams) if (name !== "token") mapped.searchParams.set(name, val);
					if (allowedOrigins.has(mapped.origin)) urls.push(mapped);
					else for (const domain of subscriptionDomains) urls.push(new URL(mapped.pathname + mapped.search, httpsURL(domain)));
				} else if (allowedOrigins.has(url.origin)) urls.push(url);
				else for (const domain of subscriptionDomains) urls.push(new URL(url.pathname + url.search, httpsURL(domain)));
			}
			if (token) for (const domain of subscriptionDomains) urls.push(new URL(path("/api/v1/client/subscribe?token=") + encodeURIComponent(token), httpsURL(domain)));
			return [...new Set(urls.map((url) => {
				if (!allowedOrigins.has(url.origin)) throw new Error("Apex 订阅地址不在已验签配置的服务域名中");
				url.searchParams.set("flag", apex.flag);
				url.hash = "";
				return url.href;
			}))];
		}
		const download = async (url) => {
			const response = await request(url, "subscription");
			const nodes = ProxyUtils.parse(decryptSubscription(response.body));
			if (!Array.isArray(nodes) || !nodes.length) throw new Error("Apex 订阅未解析到有效节点");
			$substore.write(url, cacheKey);
			return nodes;
		};
		const cached = $substore.read(cacheKey);
		if (cached) try {
			for (const url of subscriptionURLs(cached)) return await download(url);
		} catch (error) {
			$substore.write("", cacheKey);
			$substore.info(`Apex 缓存失效，重新登录: ${errorMessage(error)}`);
		}
		for (const domain of domains) {
			let stage = "登录";
			try {
				var _login$data, _JSON$parse;
				const login = JSON.parse(text((await request(apiURL(domain, "/api/v1/passport/auth/login"), "api", {
					method: "POST",
					body: {
						email: config.username,
						password: config.password
					}
				})).body));
				const auth = login === null || login === void 0 || (_login$data = login.data) === null || _login$data === void 0 ? void 0 : _login$data.auth_data;
				if (typeof auth !== "string" || !auth) throw new Error("Apex 登录响应缺少 auth_data");
				sensitiveValues.push(auth);
				stage = "获取订阅地址";
				const sub = (_JSON$parse = JSON.parse(text((await request(apiURL(domain, "/api/v1/user/getSubscribe"), "api", { auth })).body))) === null || _JSON$parse === void 0 ? void 0 : _JSON$parse.data;
				if (!sub || !sub.subscribe_url && !sub.token) throw new Error("Apex getSubscribe 缺少 subscribe_url/token");
				if (sub.token) sensitiveValues.push(sub.token);
				stage = "下载订阅";
				for (const url of subscriptionURLs(sub.subscribe_url, sub.token)) try {
					return await download(url);
				} catch (error) {
					failures.push(`下载订阅 ${httpsURL(url).origin}: ${errorMessage(error)}`);
				}
			} catch (error) {
				failures.push(`${stage} ${httpsURL(domain).origin}: ${errorMessage(error)}`);
			}
		}
		throw new Error(`Apex 订阅获取失败: ${[...new Set(failures)].join("；")}`);
	}
	function normalizeApex(value) {
		if (value == null) return null;
		if (typeof value !== "object" || Array.isArray(value)) throw new Error("provider 参数 apex 必须为对象");
		for (const name of [
			"configPublicKey",
			"subscriptionPublicKey",
			"subscriptionKey"
		]) if (typeof value[name] !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value[name])) throw new Error(`Apex ${name} 必须为 32 字节 Base64`);
		if (typeof value.xorKey !== "string" || !/^[A-Za-z0-9]{32}$/.test(value.xorKey)) throw new Error("Apex xorKey 无效");
		if (!/^[a-z][a-z0-9]*$/.test(value.flag) || !Number.isInteger(value.profileId) || !Number.isInteger(value.keyId) || value.profileId < 1 || value.keyId < 1) throw new Error("Apex flag/profileId/keyId 无效");
		const ids = /* @__PURE__ */ new Set();
		for (const purpose of [
			"oss",
			"api",
			"subscription"
		]) {
			var _value$mtls, _bundle$client_cert_p, _bundle$client_key_pe;
			const bundle = (_value$mtls = value.mtls) === null || _value$mtls === void 0 ? void 0 : _value$mtls[purpose];
			if ((bundle === null || bundle === void 0 ? void 0 : bundle.version) !== 1 || bundle.purpose !== purpose || !Number.isInteger(bundle.profile_id) || !((_bundle$client_cert_p = bundle.client_cert_pem) === null || _bundle$client_cert_p === void 0 ? void 0 : _bundle$client_cert_p.startsWith("-----BEGIN CERTIFICATE-----")) || !((_bundle$client_key_pe = bundle.client_key_pem) === null || _bundle$client_key_pe === void 0 ? void 0 : _bundle$client_key_pe.startsWith("-----BEGIN PRIVATE KEY-----"))) throw new Error(`Apex ${purpose} 客户端证书缺失或用途错误`);
			ids.add(bundle.profile_id);
		}
		if (ids.size !== 1) throw new Error("Apex 三组客户端证书品牌不一致");
		return value;
	}
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/aes/aes.asm.js
	/**
	* @file {@link http://asmjs.org Asm.js} implementation of the {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard Advanced Encryption Standard}.
	* @author Artem S Vybornov <vybornov@gmail.com>
	* @license MIT
	*/
	var AES_asm = function() {
		"use strict";
		/**
		* Galois Field stuff init flag
		*/
		var ginit_done = false;
		/**
		* Galois Field exponentiation and logarithm tables for 3 (the generator)
		*/
		var gexp3, glog3;
		/**
		* Init Galois Field tables
		*/
		function ginit() {
			gexp3 = [], glog3 = [];
			var a = 1, c, d;
			for (c = 0; c < 255; c++) {
				gexp3[c] = a;
				d = a & 128, a <<= 1, a &= 255;
				if (d === 128) a ^= 27;
				a ^= gexp3[c];
				glog3[gexp3[c]] = c;
			}
			gexp3[255] = gexp3[0];
			glog3[0] = 0;
			ginit_done = true;
		}
		/**
		* Galois Field multiplication
		* @param {number} a
		* @param {number} b
		* @return {number}
		*/
		function gmul(a, b) {
			var c = gexp3[(glog3[a] + glog3[b]) % 255];
			if (a === 0 || b === 0) c = 0;
			return c;
		}
		/**
		* Galois Field reciprocal
		* @param {number} a
		* @return {number}
		*/
		function ginv(a) {
			var i = gexp3[255 - glog3[a]];
			if (a === 0) i = 0;
			return i;
		}
		/**
		* AES stuff init flag
		*/
		var aes_init_done = false;
		/**
		* Encryption, Decryption, S-Box and KeyTransform tables
		*
		* @type {number[]}
		*/
		var aes_sbox;
		/**
		* @type {number[]}
		*/
		var aes_sinv;
		/**
		* @type {number[][]}
		*/
		var aes_enc;
		/**
		* @type {number[][]}
		*/
		var aes_dec;
		/**
		* Init AES tables
		*/
		function aes_init() {
			if (!ginit_done) ginit();
			function _s(a) {
				var c, s = x = ginv(a), x;
				for (c = 0; c < 4; c++) {
					s = (s << 1 | s >>> 7) & 255;
					x ^= s;
				}
				x ^= 99;
				return x;
			}
			aes_sbox = [], aes_sinv = [], aes_enc = [
				[],
				[],
				[],
				[]
			], aes_dec = [
				[],
				[],
				[],
				[]
			];
			for (var i = 0; i < 256; i++) {
				var s = _s(i);
				aes_sbox[i] = s;
				aes_sinv[s] = i;
				aes_enc[0][i] = gmul(2, s) << 24 | s << 16 | s << 8 | gmul(3, s);
				aes_dec[0][s] = gmul(14, i) << 24 | gmul(9, i) << 16 | gmul(13, i) << 8 | gmul(11, i);
				for (var t = 1; t < 4; t++) {
					aes_enc[t][i] = aes_enc[t - 1][i] >>> 8 | aes_enc[t - 1][i] << 24;
					aes_dec[t][s] = aes_dec[t - 1][s] >>> 8 | aes_dec[t - 1][s] << 24;
				}
			}
			aes_init_done = true;
		}
		/**
		* Asm.js module constructor.
		*
		* <p>
		* Heap buffer layout by offset:
		* <pre>
		* 0x0000   encryption key schedule
		* 0x0400   decryption key schedule
		* 0x0800   sbox
		* 0x0c00   inv sbox
		* 0x1000   encryption tables
		* 0x2000   decryption tables
		* 0x3000   reserved (future GCM multiplication lookup table)
		* 0x4000   data
		* </pre>
		* Don't touch anything before <code>0x400</code>.
		* </p>
		*
		* @alias AES_asm
		* @class
		* @param foreign - <i>ignored</i>
		* @param buffer - heap buffer to link with
		*/
		var wrapper = function(foreign, buffer) {
			if (!aes_init_done) aes_init();
			var heap = new Uint32Array(buffer);
			heap.set(aes_sbox, 512);
			heap.set(aes_sinv, 768);
			for (var i = 0; i < 4; i++) {
				heap.set(aes_enc[i], 4096 + 1024 * i >> 2);
				heap.set(aes_dec[i], 8192 + 1024 * i >> 2);
			}
			/**
			* Calculate AES key schedules.
			* @instance
			* @memberof AES_asm
			* @param {number} ks - key size, 4/6/8 (for 128/192/256-bit key correspondingly)
			* @param {number} k0 - key vector components
			* @param {number} k1 - key vector components
			* @param {number} k2 - key vector components
			* @param {number} k3 - key vector components
			* @param {number} k4 - key vector components
			* @param {number} k5 - key vector components
			* @param {number} k6 - key vector components
			* @param {number} k7 - key vector components
			*/
			function set_key(ks, k0, k1, k2, k3, k4, k5, k6, k7) {
				var ekeys = heap.subarray(0, 60), dkeys = heap.subarray(256, 316);
				ekeys.set([
					k0,
					k1,
					k2,
					k3,
					k4,
					k5,
					k6,
					k7
				]);
				for (var i = ks, rcon = 1; i < 4 * ks + 28; i++) {
					var k = ekeys[i - 1];
					if (i % ks === 0 || ks === 8 && i % ks === 4) k = aes_sbox[k >>> 24] << 24 ^ aes_sbox[k >>> 16 & 255] << 16 ^ aes_sbox[k >>> 8 & 255] << 8 ^ aes_sbox[k & 255];
					if (i % ks === 0) {
						k = k << 8 ^ k >>> 24 ^ rcon << 24;
						rcon = rcon << 1 ^ (rcon & 128 ? 27 : 0);
					}
					ekeys[i] = ekeys[i - ks] ^ k;
				}
				for (var j = 0; j < i; j += 4) for (var jj = 0; jj < 4; jj++) {
					var k = ekeys[i - (4 + j) + (4 - jj) % 4];
					if (j < 4 || j >= i - 4) dkeys[j + jj] = k;
					else dkeys[j + jj] = aes_dec[0][aes_sbox[k >>> 24]] ^ aes_dec[1][aes_sbox[k >>> 16 & 255]] ^ aes_dec[2][aes_sbox[k >>> 8 & 255]] ^ aes_dec[3][aes_sbox[k & 255]];
				}
				asm.set_rounds(ks + 5);
			}
			var asm = function(stdlib, foreign, buffer) {
				"use asm";
				var S0 = 0, S1 = 0, S2 = 0, S3 = 0, I0 = 0, I1 = 0, I2 = 0, I3 = 0, N0 = 0, N1 = 0, N2 = 0, N3 = 0, M0 = 0, M1 = 0, M2 = 0, M3 = 0, H0 = 0, H1 = 0, H2 = 0, H3 = 0, R = 0;
				var HEAP = new stdlib.Uint32Array(buffer), DATA = new stdlib.Uint8Array(buffer);
				/**
				* AES core
				* @param {number} k - precomputed key schedule offset
				* @param {number} s - precomputed sbox table offset
				* @param {number} t - precomputed round table offset
				* @param {number} r - number of inner rounds to perform
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _core(k, s, t, r, x0, x1, x2, x3) {
					k = k | 0;
					s = s | 0;
					t = t | 0;
					r = r | 0;
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					var t1 = 0, t2 = 0, t3 = 0, y0 = 0, y1 = 0, y2 = 0, y3 = 0, i = 0;
					t1 = t | 1024, t2 = t | 2048, t3 = t | 3072;
					x0 = x0 ^ HEAP[(k | 0) >> 2], x1 = x1 ^ HEAP[(k | 4) >> 2], x2 = x2 ^ HEAP[(k | 8) >> 2], x3 = x3 ^ HEAP[(k | 12) >> 2];
					for (i = 16; (i | 0) <= r << 4; i = i + 16 | 0) {
						y0 = HEAP[(t | x0 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x1 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x2 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x3 << 2 & 1020) >> 2] ^ HEAP[(k | i | 0) >> 2], y1 = HEAP[(t | x1 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x2 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x3 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x0 << 2 & 1020) >> 2] ^ HEAP[(k | i | 4) >> 2], y2 = HEAP[(t | x2 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x3 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x0 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x1 << 2 & 1020) >> 2] ^ HEAP[(k | i | 8) >> 2], y3 = HEAP[(t | x3 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x0 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x1 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x2 << 2 & 1020) >> 2] ^ HEAP[(k | i | 12) >> 2];
						x0 = y0, x1 = y1, x2 = y2, x3 = y3;
					}
					S0 = HEAP[(s | x0 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x1 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x2 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x3 << 2 & 1020) >> 2] ^ HEAP[(k | i | 0) >> 2], S1 = HEAP[(s | x1 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x2 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x3 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x0 << 2 & 1020) >> 2] ^ HEAP[(k | i | 4) >> 2], S2 = HEAP[(s | x2 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x3 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x0 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x1 << 2 & 1020) >> 2] ^ HEAP[(k | i | 8) >> 2], S3 = HEAP[(s | x3 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x0 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x1 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x2 << 2 & 1020) >> 2] ^ HEAP[(k | i | 12) >> 2];
				}
				/**
				* ECB mode encryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _ecb_enc(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, x0, x1, x2, x3);
				}
				/**
				* ECB mode decryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _ecb_dec(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					var t = 0;
					_core(1024, 3072, 8192, R, x0, x3, x2, x1);
					t = S1, S1 = S3, S3 = t;
				}
				/**
				* CBC mode encryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _cbc_enc(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, I0 ^ x0, I1 ^ x1, I2 ^ x2, I3 ^ x3);
					I0 = S0, I1 = S1, I2 = S2, I3 = S3;
				}
				/**
				* CBC mode decryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _cbc_dec(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					var t = 0;
					_core(1024, 3072, 8192, R, x0, x3, x2, x1);
					t = S1, S1 = S3, S3 = t;
					S0 = S0 ^ I0, S1 = S1 ^ I1, S2 = S2 ^ I2, S3 = S3 ^ I3;
					I0 = x0, I1 = x1, I2 = x2, I3 = x3;
				}
				/**
				* CFB mode encryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _cfb_enc(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, I0, I1, I2, I3);
					I0 = S0 = S0 ^ x0, I1 = S1 = S1 ^ x1, I2 = S2 = S2 ^ x2, I3 = S3 = S3 ^ x3;
				}
				/**
				* CFB mode decryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _cfb_dec(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, I0, I1, I2, I3);
					S0 = S0 ^ x0, S1 = S1 ^ x1, S2 = S2 ^ x2, S3 = S3 ^ x3;
					I0 = x0, I1 = x1, I2 = x2, I3 = x3;
				}
				/**
				* OFB mode encryption / decryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _ofb(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, I0, I1, I2, I3);
					I0 = S0, I1 = S1, I2 = S2, I3 = S3;
					S0 = S0 ^ x0, S1 = S1 ^ x1, S2 = S2 ^ x2, S3 = S3 ^ x3;
				}
				/**
				* CTR mode encryption / decryption
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _ctr(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					_core(0, 2048, 4096, R, N0, N1, N2, N3);
					N3 = ~M3 & N3 | M3 & N3 + 1;
					N2 = ~M2 & N2 | M2 & N2 + ((N3 | 0) == 0);
					N1 = ~M1 & N1 | M1 & N1 + ((N2 | 0) == 0);
					N0 = ~M0 & N0 | M0 & N0 + ((N1 | 0) == 0);
					S0 = S0 ^ x0;
					S1 = S1 ^ x1;
					S2 = S2 ^ x2;
					S3 = S3 ^ x3;
				}
				/**
				* GCM mode MAC calculation
				* @param {number} x0 - 128-bit input block vector
				* @param {number} x1 - 128-bit input block vector
				* @param {number} x2 - 128-bit input block vector
				* @param {number} x3 - 128-bit input block vector
				*/
				function _gcm_mac(x0, x1, x2, x3) {
					x0 = x0 | 0;
					x1 = x1 | 0;
					x2 = x2 | 0;
					x3 = x3 | 0;
					var y0 = 0, y1 = 0, y2 = 0, y3 = 0, z0 = 0, z1 = 0, z2 = 0, z3 = 0, i = 0, c = 0;
					x0 = x0 ^ I0, x1 = x1 ^ I1, x2 = x2 ^ I2, x3 = x3 ^ I3;
					y0 = H0 | 0, y1 = H1 | 0, y2 = H2 | 0, y3 = H3 | 0;
					for (; (i | 0) < 128; i = i + 1 | 0) {
						if (y0 >>> 31) z0 = z0 ^ x0, z1 = z1 ^ x1, z2 = z2 ^ x2, z3 = z3 ^ x3;
						y0 = y0 << 1 | y1 >>> 31, y1 = y1 << 1 | y2 >>> 31, y2 = y2 << 1 | y3 >>> 31, y3 = y3 << 1;
						c = x3 & 1;
						x3 = x3 >>> 1 | x2 << 31, x2 = x2 >>> 1 | x1 << 31, x1 = x1 >>> 1 | x0 << 31, x0 = x0 >>> 1;
						if (c) x0 = x0 ^ 3774873600;
					}
					I0 = z0, I1 = z1, I2 = z2, I3 = z3;
				}
				/**
				* Set the internal rounds number.
				* @instance
				* @memberof AES_asm
				* @param {number} r - number if inner AES rounds
				*/
				function set_rounds(r) {
					r = r | 0;
					R = r;
				}
				/**
				* Populate the internal state of the module.
				* @instance
				* @memberof AES_asm
				* @param {number} s0 - state vector
				* @param {number} s1 - state vector
				* @param {number} s2 - state vector
				* @param {number} s3 - state vector
				*/
				function set_state(s0, s1, s2, s3) {
					s0 = s0 | 0;
					s1 = s1 | 0;
					s2 = s2 | 0;
					s3 = s3 | 0;
					S0 = s0, S1 = s1, S2 = s2, S3 = s3;
				}
				/**
				* Populate the internal iv of the module.
				* @instance
				* @memberof AES_asm
				* @param {number} i0 - iv vector
				* @param {number} i1 - iv vector
				* @param {number} i2 - iv vector
				* @param {number} i3 - iv vector
				*/
				function set_iv(i0, i1, i2, i3) {
					i0 = i0 | 0;
					i1 = i1 | 0;
					i2 = i2 | 0;
					i3 = i3 | 0;
					I0 = i0, I1 = i1, I2 = i2, I3 = i3;
				}
				/**
				* Set nonce for CTR-family modes.
				* @instance
				* @memberof AES_asm
				* @param {number} n0 - nonce vector
				* @param {number} n1 - nonce vector
				* @param {number} n2 - nonce vector
				* @param {number} n3 - nonce vector
				*/
				function set_nonce(n0, n1, n2, n3) {
					n0 = n0 | 0;
					n1 = n1 | 0;
					n2 = n2 | 0;
					n3 = n3 | 0;
					N0 = n0, N1 = n1, N2 = n2, N3 = n3;
				}
				/**
				* Set counter mask for CTR-family modes.
				* @instance
				* @memberof AES_asm
				* @param {number} m0 - counter mask vector
				* @param {number} m1 - counter mask vector
				* @param {number} m2 - counter mask vector
				* @param {number} m3 - counter mask vector
				*/
				function set_mask(m0, m1, m2, m3) {
					m0 = m0 | 0;
					m1 = m1 | 0;
					m2 = m2 | 0;
					m3 = m3 | 0;
					M0 = m0, M1 = m1, M2 = m2, M3 = m3;
				}
				/**
				* Set counter for CTR-family modes.
				* @instance
				* @memberof AES_asm
				* @param {number} c0 - counter vector
				* @param {number} c1 - counter vector
				* @param {number} c2 - counter vector
				* @param {number} c3 - counter vector
				*/
				function set_counter(c0, c1, c2, c3) {
					c0 = c0 | 0;
					c1 = c1 | 0;
					c2 = c2 | 0;
					c3 = c3 | 0;
					N3 = ~M3 & N3 | M3 & c3, N2 = ~M2 & N2 | M2 & c2, N1 = ~M1 & N1 | M1 & c1, N0 = ~M0 & N0 | M0 & c0;
				}
				/**
				* Store the internal state vector into the heap.
				* @instance
				* @memberof AES_asm
				* @param {number} pos - offset where to put the data
				* @return {number} The number of bytes have been written into the heap, always 16.
				*/
				function get_state(pos) {
					pos = pos | 0;
					if (pos & 15) return -1;
					DATA[pos | 0] = S0 >>> 24, DATA[pos | 1] = S0 >>> 16 & 255, DATA[pos | 2] = S0 >>> 8 & 255, DATA[pos | 3] = S0 & 255, DATA[pos | 4] = S1 >>> 24, DATA[pos | 5] = S1 >>> 16 & 255, DATA[pos | 6] = S1 >>> 8 & 255, DATA[pos | 7] = S1 & 255, DATA[pos | 8] = S2 >>> 24, DATA[pos | 9] = S2 >>> 16 & 255, DATA[pos | 10] = S2 >>> 8 & 255, DATA[pos | 11] = S2 & 255, DATA[pos | 12] = S3 >>> 24, DATA[pos | 13] = S3 >>> 16 & 255, DATA[pos | 14] = S3 >>> 8 & 255, DATA[pos | 15] = S3 & 255;
					return 16;
				}
				/**
				* Store the internal iv vector into the heap.
				* @instance
				* @memberof AES_asm
				* @param {number} pos - offset where to put the data
				* @return {number} The number of bytes have been written into the heap, always 16.
				*/
				function get_iv(pos) {
					pos = pos | 0;
					if (pos & 15) return -1;
					DATA[pos | 0] = I0 >>> 24, DATA[pos | 1] = I0 >>> 16 & 255, DATA[pos | 2] = I0 >>> 8 & 255, DATA[pos | 3] = I0 & 255, DATA[pos | 4] = I1 >>> 24, DATA[pos | 5] = I1 >>> 16 & 255, DATA[pos | 6] = I1 >>> 8 & 255, DATA[pos | 7] = I1 & 255, DATA[pos | 8] = I2 >>> 24, DATA[pos | 9] = I2 >>> 16 & 255, DATA[pos | 10] = I2 >>> 8 & 255, DATA[pos | 11] = I2 & 255, DATA[pos | 12] = I3 >>> 24, DATA[pos | 13] = I3 >>> 16 & 255, DATA[pos | 14] = I3 >>> 8 & 255, DATA[pos | 15] = I3 & 255;
					return 16;
				}
				/**
				* GCM initialization.
				* @instance
				* @memberof AES_asm
				*/
				function gcm_init() {
					_ecb_enc(0, 0, 0, 0);
					H0 = S0, H1 = S1, H2 = S2, H3 = S3;
				}
				/**
				* Perform ciphering operation on the supplied data.
				* @instance
				* @memberof AES_asm
				* @param {number} mode - block cipher mode (see {@link AES_asm} mode constants)
				* @param {number} pos - offset of the data being processed
				* @param {number} len - length of the data being processed
				* @return {number} Actual amount of data have been processed.
				*/
				function cipher(mode, pos, len) {
					mode = mode | 0;
					pos = pos | 0;
					len = len | 0;
					var ret = 0;
					if (pos & 15) return -1;
					while ((len | 0) >= 16) {
						_cipher_modes[mode & 7](DATA[pos | 0] << 24 | DATA[pos | 1] << 16 | DATA[pos | 2] << 8 | DATA[pos | 3], DATA[pos | 4] << 24 | DATA[pos | 5] << 16 | DATA[pos | 6] << 8 | DATA[pos | 7], DATA[pos | 8] << 24 | DATA[pos | 9] << 16 | DATA[pos | 10] << 8 | DATA[pos | 11], DATA[pos | 12] << 24 | DATA[pos | 13] << 16 | DATA[pos | 14] << 8 | DATA[pos | 15]);
						DATA[pos | 0] = S0 >>> 24, DATA[pos | 1] = S0 >>> 16 & 255, DATA[pos | 2] = S0 >>> 8 & 255, DATA[pos | 3] = S0 & 255, DATA[pos | 4] = S1 >>> 24, DATA[pos | 5] = S1 >>> 16 & 255, DATA[pos | 6] = S1 >>> 8 & 255, DATA[pos | 7] = S1 & 255, DATA[pos | 8] = S2 >>> 24, DATA[pos | 9] = S2 >>> 16 & 255, DATA[pos | 10] = S2 >>> 8 & 255, DATA[pos | 11] = S2 & 255, DATA[pos | 12] = S3 >>> 24, DATA[pos | 13] = S3 >>> 16 & 255, DATA[pos | 14] = S3 >>> 8 & 255, DATA[pos | 15] = S3 & 255;
						ret = ret + 16 | 0, pos = pos + 16 | 0, len = len - 16 | 0;
					}
					return ret | 0;
				}
				/**
				* Calculates MAC of the supplied data.
				* @instance
				* @memberof AES_asm
				* @param {number} mode - block cipher mode (see {@link AES_asm} mode constants)
				* @param {number} pos - offset of the data being processed
				* @param {number} len - length of the data being processed
				* @return {number} Actual amount of data have been processed.
				*/
				function mac(mode, pos, len) {
					mode = mode | 0;
					pos = pos | 0;
					len = len | 0;
					var ret = 0;
					if (pos & 15) return -1;
					while ((len | 0) >= 16) {
						_mac_modes[mode & 1](DATA[pos | 0] << 24 | DATA[pos | 1] << 16 | DATA[pos | 2] << 8 | DATA[pos | 3], DATA[pos | 4] << 24 | DATA[pos | 5] << 16 | DATA[pos | 6] << 8 | DATA[pos | 7], DATA[pos | 8] << 24 | DATA[pos | 9] << 16 | DATA[pos | 10] << 8 | DATA[pos | 11], DATA[pos | 12] << 24 | DATA[pos | 13] << 16 | DATA[pos | 14] << 8 | DATA[pos | 15]);
						ret = ret + 16 | 0, pos = pos + 16 | 0, len = len - 16 | 0;
					}
					return ret | 0;
				}
				/**
				* AES cipher modes table (virual methods)
				*/
				var _cipher_modes = [
					_ecb_enc,
					_ecb_dec,
					_cbc_enc,
					_cbc_dec,
					_cfb_enc,
					_cfb_dec,
					_ofb,
					_ctr
				];
				/**
				* AES MAC modes table (virual methods)
				*/
				var _mac_modes = [_cbc_enc, _gcm_mac];
				/**
				* Asm.js module exports
				*/
				return {
					set_rounds,
					set_state,
					set_iv,
					set_nonce,
					set_mask,
					set_counter,
					get_state,
					get_iv,
					gcm_init,
					cipher,
					mac
				};
			}({
				Uint8Array,
				Uint32Array
			}, foreign, buffer);
			asm.set_key = set_key;
			return asm;
		};
		/**
		* AES enciphering mode constants
		* @enum {number}
		* @const
		*/
		wrapper.ENC = {
			ECB: 0,
			CBC: 2,
			CFB: 4,
			OFB: 6,
			CTR: 7
		}, wrapper.DEC = {
			ECB: 1,
			CBC: 3,
			CFB: 5,
			OFB: 6,
			CTR: 7
		}, wrapper.MAC = {
			CBC: 0,
			GCM: 1
		};
		/**
		* Heap data offset
		* @type {number}
		* @const
		*/
		wrapper.HEAP_DATA = 16384;
		return wrapper;
	}();
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/other/utils.js
	function is_bytes(a) {
		return a instanceof Uint8Array;
	}
	function _heap_init(heap, heapSize) {
		const size = heap ? heap.byteLength : heapSize || 65536;
		if (size & 4095 || size <= 0) throw new Error("heap size must be a positive integer and a multiple of 4096");
		heap = heap || new Uint8Array(new ArrayBuffer(size));
		return heap;
	}
	function _heap_write(heap, hpos, data, dpos, dlen) {
		const hlen = heap.length - hpos;
		const wlen = hlen < dlen ? hlen : dlen;
		heap.set(data.subarray(dpos, dpos + wlen), hpos);
		return wlen;
	}
	function joinBytes(...arg) {
		const totalLenght = arg.reduce((sum, curr) => sum + curr.length, 0);
		const ret = new Uint8Array(totalLenght);
		let cursor = 0;
		for (let i = 0; i < arg.length; i++) {
			ret.set(arg[i], cursor);
			cursor += arg[i].length;
		}
		return ret;
	}
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/other/errors.js
	var IllegalStateError = class extends Error {
		constructor(...args) {
			super(...args);
			Object.create(Error.prototype, { name: { value: "IllegalStateError" } });
		}
	};
	var IllegalArgumentError = class extends Error {
		constructor(...args) {
			super(...args);
			Object.create(Error.prototype, { name: { value: "IllegalArgumentError" } });
		}
	};
	var SecurityError = class extends Error {
		constructor(...args) {
			super(...args);
			Object.create(Error.prototype, { name: { value: "SecurityError" } });
		}
	};
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/aes/aes.js
	var AES = class {
		constructor(key, iv, padding = true, mode) {
			this.pos = 0;
			this.len = 0;
			this.mode = mode;
			this.heap = _heap_init().subarray(AES_asm.HEAP_DATA);
			this.asm = new AES_asm(null, this.heap.buffer);
			this.pos = 0;
			this.len = 0;
			const keylen = key.length;
			if (keylen !== 16 && keylen !== 24 && keylen !== 32) throw new IllegalArgumentError("illegal key size");
			const keyview = new DataView(key.buffer, key.byteOffset, key.byteLength);
			this.asm.set_key(keylen >> 2, keyview.getUint32(0), keyview.getUint32(4), keyview.getUint32(8), keyview.getUint32(12), keylen > 16 ? keyview.getUint32(16) : 0, keylen > 16 ? keyview.getUint32(20) : 0, keylen > 24 ? keyview.getUint32(24) : 0, keylen > 24 ? keyview.getUint32(28) : 0);
			if (iv !== void 0) {
				if (iv.length !== 16) throw new IllegalArgumentError("illegal iv size");
				let ivview = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
				this.asm.set_iv(ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12));
			} else this.asm.set_iv(0, 0, 0, 0);
			this.padding = padding;
		}
		AES_Encrypt_process(data) {
			if (!is_bytes(data)) throw new TypeError("data isn't of expected type");
			let asm = this.asm;
			let heap = this.heap;
			let amode = AES_asm.ENC[this.mode];
			let hpos = AES_asm.HEAP_DATA;
			let pos = this.pos;
			let len = this.len;
			let dpos = 0;
			let dlen = data.length || 0;
			let rpos = 0;
			let rlen = len + dlen & -16;
			let wlen = 0;
			let result = new Uint8Array(rlen);
			while (dlen > 0) {
				wlen = _heap_write(heap, pos + len, data, dpos, dlen);
				len += wlen;
				dpos += wlen;
				dlen -= wlen;
				wlen = asm.cipher(amode, hpos + pos, len);
				if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
				rpos += wlen;
				if (wlen < len) {
					pos += wlen;
					len -= wlen;
				} else {
					pos = 0;
					len = 0;
				}
			}
			this.pos = pos;
			this.len = len;
			return result;
		}
		AES_Encrypt_finish() {
			let asm = this.asm;
			let heap = this.heap;
			let amode = AES_asm.ENC[this.mode];
			let hpos = AES_asm.HEAP_DATA;
			let pos = this.pos;
			let len = this.len;
			let plen = 16 - len % 16;
			let rlen = len;
			if (this.hasOwnProperty("padding")) {
				if (this.padding) {
					for (let p = 0; p < plen; ++p) heap[pos + len + p] = plen;
					len += plen;
					rlen = len;
				} else if (len % 16) throw new IllegalArgumentError("data length must be a multiple of the block size");
			} else len += plen;
			const result = new Uint8Array(rlen);
			if (len) asm.cipher(amode, hpos + pos, len);
			if (rlen) result.set(heap.subarray(pos, pos + rlen));
			this.pos = 0;
			this.len = 0;
			return result;
		}
		AES_Decrypt_process(data) {
			if (!is_bytes(data)) throw new TypeError("data isn't of expected type");
			let asm = this.asm;
			let heap = this.heap;
			let amode = AES_asm.DEC[this.mode];
			let hpos = AES_asm.HEAP_DATA;
			let pos = this.pos;
			let len = this.len;
			let dpos = 0;
			let dlen = data.length || 0;
			let rpos = 0;
			let rlen = len + dlen & -16;
			let plen = 0;
			let wlen = 0;
			if (this.padding) {
				plen = len + dlen - rlen || 16;
				rlen -= plen;
			}
			const result = new Uint8Array(rlen);
			while (dlen > 0) {
				wlen = _heap_write(heap, pos + len, data, dpos, dlen);
				len += wlen;
				dpos += wlen;
				dlen -= wlen;
				wlen = asm.cipher(amode, hpos + pos, len - (!dlen ? plen : 0));
				if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
				rpos += wlen;
				if (wlen < len) {
					pos += wlen;
					len -= wlen;
				} else {
					pos = 0;
					len = 0;
				}
			}
			this.pos = pos;
			this.len = len;
			return result;
		}
		AES_Decrypt_finish() {
			let asm = this.asm;
			let heap = this.heap;
			let amode = AES_asm.DEC[this.mode];
			let hpos = AES_asm.HEAP_DATA;
			let pos = this.pos;
			let len = this.len;
			let rlen = len;
			if (len > 0) {
				if (len % 16) if (this.hasOwnProperty("padding")) throw new IllegalArgumentError("data length must be a multiple of the block size");
				else len += 16 - len % 16;
				asm.cipher(amode, hpos + pos, len);
				if (this.hasOwnProperty("padding") && this.padding) {
					let pad = heap[pos + rlen - 1];
					if (pad < 1 || pad > 16 || pad > rlen) throw new SecurityError("bad padding");
					let pcheck = 0;
					for (let i = pad; i > 1; i--) pcheck |= pad ^ heap[pos + rlen - i];
					if (pcheck) throw new SecurityError("bad padding");
					rlen -= pad;
				}
			}
			const result = new Uint8Array(rlen);
			if (rlen > 0) result.set(heap.subarray(pos, pos + rlen));
			this.pos = 0;
			this.len = 0;
			return result;
		}
	};
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/aes/cbc.js
	var AES_CBC = class AES_CBC extends AES {
		static encrypt(data, key, padding = true, iv) {
			return new AES_CBC(key, iv, padding).encrypt(data);
		}
		static decrypt(data, key, padding = true, iv) {
			return new AES_CBC(key, iv, padding).decrypt(data);
		}
		constructor(key, iv, padding = true) {
			super(key, iv, padding, "CBC");
		}
		encrypt(data) {
			return joinBytes(this.AES_Encrypt_process(data), this.AES_Encrypt_finish());
		}
		decrypt(data) {
			return joinBytes(this.AES_Decrypt_process(data), this.AES_Decrypt_finish());
		}
	};
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/aes/gcm.js
	var _AES_GCM_data_maxLength = 68719476704;
	var AES_GCM = class AES_GCM extends AES {
		constructor(key, nonce, adata, tagSize = 16) {
			super(key, void 0, false, "CTR");
			this.tagSize = tagSize;
			this.gamma0 = 0;
			this.counter = 1;
			this.asm.gcm_init();
			if (this.tagSize < 4 || this.tagSize > 16) throw new IllegalArgumentError("illegal tagSize value");
			const noncelen = nonce.length || 0;
			const noncebuf = /* @__PURE__ */ new Uint8Array(16);
			if (noncelen !== 12) {
				this._gcm_mac_process(nonce);
				this.heap[0] = 0;
				this.heap[1] = 0;
				this.heap[2] = 0;
				this.heap[3] = 0;
				this.heap[4] = 0;
				this.heap[5] = 0;
				this.heap[6] = 0;
				this.heap[7] = 0;
				this.heap[8] = 0;
				this.heap[9] = 0;
				this.heap[10] = 0;
				this.heap[11] = noncelen >>> 29;
				this.heap[12] = noncelen >>> 21 & 255;
				this.heap[13] = noncelen >>> 13 & 255;
				this.heap[14] = noncelen >>> 5 & 255;
				this.heap[15] = noncelen << 3 & 255;
				this.asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);
				this.asm.get_iv(AES_asm.HEAP_DATA);
				this.asm.set_iv(0, 0, 0, 0);
				noncebuf.set(this.heap.subarray(0, 16));
			} else {
				noncebuf.set(nonce);
				noncebuf[15] = 1;
			}
			const nonceview = new DataView(noncebuf.buffer);
			this.gamma0 = nonceview.getUint32(12);
			this.asm.set_nonce(nonceview.getUint32(0), nonceview.getUint32(4), nonceview.getUint32(8), 0);
			this.asm.set_mask(0, 0, 0, 4294967295);
			if (adata !== void 0) {
				if (adata.length > _AES_GCM_data_maxLength) throw new IllegalArgumentError("illegal adata length");
				if (adata.length) {
					this.adata = adata;
					this._gcm_mac_process(adata);
				} else this.adata = void 0;
			} else this.adata = void 0;
			if (this.counter < 1 || this.counter > 4294967295) throw new RangeError("counter must be a positive 32-bit integer");
			this.asm.set_counter(0, 0, 0, this.gamma0 + this.counter | 0);
		}
		static encrypt(cleartext, key, nonce, adata, tagsize) {
			return new AES_GCM(key, nonce, adata, tagsize).encrypt(cleartext);
		}
		static decrypt(ciphertext, key, nonce, adata, tagsize) {
			return new AES_GCM(key, nonce, adata, tagsize).decrypt(ciphertext);
		}
		encrypt(data) {
			return this.AES_GCM_encrypt(data);
		}
		decrypt(data) {
			return this.AES_GCM_decrypt(data);
		}
		AES_GCM_Encrypt_process(data) {
			let dpos = 0;
			let dlen = data.length || 0;
			let asm = this.asm;
			let heap = this.heap;
			let counter = this.counter;
			let pos = this.pos;
			let len = this.len;
			let rpos = 0;
			let rlen = len + dlen & -16;
			let wlen = 0;
			if ((counter - 1 << 4) + len + dlen > _AES_GCM_data_maxLength) throw new RangeError("counter overflow");
			const result = new Uint8Array(rlen);
			while (dlen > 0) {
				wlen = _heap_write(heap, pos + len, data, dpos, dlen);
				len += wlen;
				dpos += wlen;
				dlen -= wlen;
				wlen = asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, len);
				wlen = asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen);
				if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
				counter += wlen >>> 4;
				rpos += wlen;
				if (wlen < len) {
					pos += wlen;
					len -= wlen;
				} else {
					pos = 0;
					len = 0;
				}
			}
			this.counter = counter;
			this.pos = pos;
			this.len = len;
			return result;
		}
		AES_GCM_Encrypt_finish() {
			let asm = this.asm;
			let heap = this.heap;
			let counter = this.counter;
			let tagSize = this.tagSize;
			let adata = this.adata;
			let pos = this.pos;
			let len = this.len;
			const result = new Uint8Array(len + tagSize);
			asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, len + 15 & -16);
			if (len) result.set(heap.subarray(pos, pos + len));
			let i = len;
			for (; i & 15; i++) heap[pos + i] = 0;
			asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i);
			const alen = adata !== void 0 ? adata.length : 0;
			const clen = (counter - 1 << 4) + len;
			heap[0] = 0;
			heap[1] = 0;
			heap[2] = 0;
			heap[3] = alen >>> 29;
			heap[4] = alen >>> 21;
			heap[5] = alen >>> 13 & 255;
			heap[6] = alen >>> 5 & 255;
			heap[7] = alen << 3 & 255;
			heap[8] = heap[9] = heap[10] = 0;
			heap[11] = clen >>> 29;
			heap[12] = clen >>> 21 & 255;
			heap[13] = clen >>> 13 & 255;
			heap[14] = clen >>> 5 & 255;
			heap[15] = clen << 3 & 255;
			asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);
			asm.get_iv(AES_asm.HEAP_DATA);
			asm.set_counter(0, 0, 0, this.gamma0);
			asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);
			result.set(heap.subarray(0, tagSize), len);
			this.counter = 1;
			this.pos = 0;
			this.len = 0;
			return result;
		}
		AES_GCM_Decrypt_process(data) {
			let dpos = 0;
			let dlen = data.length || 0;
			let asm = this.asm;
			let heap = this.heap;
			let counter = this.counter;
			let tagSize = this.tagSize;
			let pos = this.pos;
			let len = this.len;
			let rpos = 0;
			let rlen = len + dlen > tagSize ? len + dlen - tagSize & -16 : 0;
			let tlen = len + dlen - rlen;
			let wlen = 0;
			if ((counter - 1 << 4) + len + dlen > _AES_GCM_data_maxLength) throw new RangeError("counter overflow");
			const result = new Uint8Array(rlen);
			while (dlen > tlen) {
				wlen = _heap_write(heap, pos + len, data, dpos, dlen - tlen);
				len += wlen;
				dpos += wlen;
				dlen -= wlen;
				wlen = asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen);
				wlen = asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen);
				if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
				counter += wlen >>> 4;
				rpos += wlen;
				pos = 0;
				len = 0;
			}
			if (dlen > 0) len += _heap_write(heap, 0, data, dpos, dlen);
			this.counter = counter;
			this.pos = pos;
			this.len = len;
			return result;
		}
		AES_GCM_Decrypt_finish() {
			let asm = this.asm;
			let heap = this.heap;
			let tagSize = this.tagSize;
			let adata = this.adata;
			let counter = this.counter;
			let pos = this.pos;
			let len = this.len;
			let rlen = len - tagSize;
			if (len < tagSize) throw new IllegalStateError("authentication tag not found");
			const result = new Uint8Array(rlen);
			const atag = new Uint8Array(heap.subarray(pos + rlen, pos + len));
			let i = rlen;
			for (; i & 15; i++) heap[pos + i] = 0;
			asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i);
			asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, i);
			if (rlen) result.set(heap.subarray(pos, pos + rlen));
			const alen = adata !== void 0 ? adata.length : 0;
			const clen = (counter - 1 << 4) + len - tagSize;
			heap[0] = 0;
			heap[1] = 0;
			heap[2] = 0;
			heap[3] = alen >>> 29;
			heap[4] = alen >>> 21;
			heap[5] = alen >>> 13 & 255;
			heap[6] = alen >>> 5 & 255;
			heap[7] = alen << 3 & 255;
			heap[8] = heap[9] = heap[10] = 0;
			heap[11] = clen >>> 29;
			heap[12] = clen >>> 21 & 255;
			heap[13] = clen >>> 13 & 255;
			heap[14] = clen >>> 5 & 255;
			heap[15] = clen << 3 & 255;
			asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);
			asm.get_iv(AES_asm.HEAP_DATA);
			asm.set_counter(0, 0, 0, this.gamma0);
			asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);
			let acheck = 0;
			for (let i = 0; i < tagSize; ++i) acheck |= atag[i] ^ heap[i];
			if (acheck) throw new SecurityError("data integrity check failed");
			this.counter = 1;
			this.pos = 0;
			this.len = 0;
			return result;
		}
		AES_GCM_decrypt(data) {
			const result1 = this.AES_GCM_Decrypt_process(data);
			const result2 = this.AES_GCM_Decrypt_finish();
			const result = new Uint8Array(result1.length + result2.length);
			if (result1.length) result.set(result1);
			if (result2.length) result.set(result2, result1.length);
			return result;
		}
		AES_GCM_encrypt(data) {
			const result1 = this.AES_GCM_Encrypt_process(data);
			const result2 = this.AES_GCM_Encrypt_finish();
			const result = new Uint8Array(result1.length + result2.length);
			if (result1.length) result.set(result1);
			if (result2.length) result.set(result2, result1.length);
			return result;
		}
		_gcm_mac_process(data) {
			const heap = this.heap;
			const asm = this.asm;
			let dpos = 0;
			let dlen = data.length || 0;
			let wlen = 0;
			while (dlen > 0) {
				wlen = _heap_write(heap, 0, data, dpos, dlen);
				dpos += wlen;
				dlen -= wlen;
				while (wlen & 15) heap[wlen++] = 0;
				asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, wlen);
			}
		}
	};
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/hash/sha256/sha256.asm.js
	var sha256_asm = function(stdlib, foreign, buffer) {
		"use asm";
		var H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0, TOTAL0 = 0, TOTAL1 = 0;
		var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0, I6 = 0, I7 = 0, O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0, O5 = 0, O6 = 0, O7 = 0;
		var HEAP = new stdlib.Uint8Array(buffer);
		function _core(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15) {
			w0 = w0 | 0;
			w1 = w1 | 0;
			w2 = w2 | 0;
			w3 = w3 | 0;
			w4 = w4 | 0;
			w5 = w5 | 0;
			w6 = w6 | 0;
			w7 = w7 | 0;
			w8 = w8 | 0;
			w9 = w9 | 0;
			w10 = w10 | 0;
			w11 = w11 | 0;
			w12 = w12 | 0;
			w13 = w13 | 0;
			w14 = w14 | 0;
			w15 = w15 | 0;
			var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;
			a = H0;
			b = H1;
			c = H2;
			d = H3;
			e = H4;
			f = H5;
			g = H6;
			h = H7;
			h = w0 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 1116352408 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			g = w1 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 1899447441 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			f = w2 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 3049323471 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			e = w3 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 3921009573 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			d = w4 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 961987163 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			c = w5 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 1508970993 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			b = w6 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 2453635748 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			a = w7 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 2870763221 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			h = w8 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 3624381080 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			g = w9 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 310598401 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			f = w10 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 607225278 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			e = w11 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 1426881987 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			d = w12 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 1925078388 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			c = w13 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 2162078206 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			b = w14 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 2614888103 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			a = w15 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 3248222580 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w0 = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
			h = w0 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 3835390401 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w1 = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
			g = w1 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 4022224774 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w2 = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
			f = w2 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 264347078 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w3 = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
			e = w3 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 604807628 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w4 = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
			d = w4 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 770255983 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w5 = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
			c = w5 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 1249150122 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w6 = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
			b = w6 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 1555081692 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w7 = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
			a = w7 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 1996064986 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w8 = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
			h = w8 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 2554220882 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w9 = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
			g = w9 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 2821834349 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w10 = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
			f = w10 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 2952996808 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w11 = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
			e = w11 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 3210313671 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w12 = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
			d = w12 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 3336571891 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w13 = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
			c = w13 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 3584528711 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w14 = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
			b = w14 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 113926993 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w15 = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
			a = w15 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 338241895 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w0 = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
			h = w0 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 666307205 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w1 = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
			g = w1 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 773529912 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w2 = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
			f = w2 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 1294757372 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w3 = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
			e = w3 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 1396182291 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w4 = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
			d = w4 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 1695183700 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w5 = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
			c = w5 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 1986661051 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w6 = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
			b = w6 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 2177026350 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w7 = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
			a = w7 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 2456956037 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w8 = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
			h = w8 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 2730485921 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w9 = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
			g = w9 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 2820302411 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w10 = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
			f = w10 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 3259730800 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w11 = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
			e = w11 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 3345764771 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w12 = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
			d = w12 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 3516065817 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w13 = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
			c = w13 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 3600352804 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w14 = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
			b = w14 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 4094571909 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w15 = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
			a = w15 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 275423344 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w0 = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
			h = w0 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 430227734 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w1 = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
			g = w1 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 506948616 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w2 = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
			f = w2 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 659060556 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w3 = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
			e = w3 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 883997877 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w4 = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
			d = w4 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 958139571 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w5 = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
			c = w5 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 1322822218 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w6 = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
			b = w6 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 1537002063 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w7 = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
			a = w7 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 1747873779 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			w8 = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
			h = w8 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 1955562222 | 0;
			d = d + h | 0;
			h = h + (a & b ^ c & (a ^ b)) + (a >>> 2 ^ a >>> 13 ^ a >>> 22 ^ a << 30 ^ a << 19 ^ a << 10) | 0;
			w9 = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
			g = w9 + g + (d >>> 6 ^ d >>> 11 ^ d >>> 25 ^ d << 26 ^ d << 21 ^ d << 7) + (f ^ d & (e ^ f)) + 2024104815 | 0;
			c = c + g | 0;
			g = g + (h & a ^ b & (h ^ a)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
			w10 = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
			f = w10 + f + (c >>> 6 ^ c >>> 11 ^ c >>> 25 ^ c << 26 ^ c << 21 ^ c << 7) + (e ^ c & (d ^ e)) + 2227730452 | 0;
			b = b + f | 0;
			f = f + (g & h ^ a & (g ^ h)) + (g >>> 2 ^ g >>> 13 ^ g >>> 22 ^ g << 30 ^ g << 19 ^ g << 10) | 0;
			w11 = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
			e = w11 + e + (b >>> 6 ^ b >>> 11 ^ b >>> 25 ^ b << 26 ^ b << 21 ^ b << 7) + (d ^ b & (c ^ d)) + 2361852424 | 0;
			a = a + e | 0;
			e = e + (f & g ^ h & (f ^ g)) + (f >>> 2 ^ f >>> 13 ^ f >>> 22 ^ f << 30 ^ f << 19 ^ f << 10) | 0;
			w12 = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
			d = w12 + d + (a >>> 6 ^ a >>> 11 ^ a >>> 25 ^ a << 26 ^ a << 21 ^ a << 7) + (c ^ a & (b ^ c)) + 2428436474 | 0;
			h = h + d | 0;
			d = d + (e & f ^ g & (e ^ f)) + (e >>> 2 ^ e >>> 13 ^ e >>> 22 ^ e << 30 ^ e << 19 ^ e << 10) | 0;
			w13 = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
			c = w13 + c + (h >>> 6 ^ h >>> 11 ^ h >>> 25 ^ h << 26 ^ h << 21 ^ h << 7) + (b ^ h & (a ^ b)) + 2756734187 | 0;
			g = g + c | 0;
			c = c + (d & e ^ f & (d ^ e)) + (d >>> 2 ^ d >>> 13 ^ d >>> 22 ^ d << 30 ^ d << 19 ^ d << 10) | 0;
			w14 = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
			b = w14 + b + (g >>> 6 ^ g >>> 11 ^ g >>> 25 ^ g << 26 ^ g << 21 ^ g << 7) + (a ^ g & (h ^ a)) + 3204031479 | 0;
			f = f + b | 0;
			b = b + (c & d ^ e & (c ^ d)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
			w15 = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
			a = w15 + a + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (h ^ f & (g ^ h)) + 3329325298 | 0;
			e = e + a | 0;
			a = a + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
			H0 = H0 + a | 0;
			H1 = H1 + b | 0;
			H2 = H2 + c | 0;
			H3 = H3 + d | 0;
			H4 = H4 + e | 0;
			H5 = H5 + f | 0;
			H6 = H6 + g | 0;
			H7 = H7 + h | 0;
		}
		function _core_heap(offset) {
			offset = offset | 0;
			_core(HEAP[offset | 0] << 24 | HEAP[offset | 1] << 16 | HEAP[offset | 2] << 8 | HEAP[offset | 3], HEAP[offset | 4] << 24 | HEAP[offset | 5] << 16 | HEAP[offset | 6] << 8 | HEAP[offset | 7], HEAP[offset | 8] << 24 | HEAP[offset | 9] << 16 | HEAP[offset | 10] << 8 | HEAP[offset | 11], HEAP[offset | 12] << 24 | HEAP[offset | 13] << 16 | HEAP[offset | 14] << 8 | HEAP[offset | 15], HEAP[offset | 16] << 24 | HEAP[offset | 17] << 16 | HEAP[offset | 18] << 8 | HEAP[offset | 19], HEAP[offset | 20] << 24 | HEAP[offset | 21] << 16 | HEAP[offset | 22] << 8 | HEAP[offset | 23], HEAP[offset | 24] << 24 | HEAP[offset | 25] << 16 | HEAP[offset | 26] << 8 | HEAP[offset | 27], HEAP[offset | 28] << 24 | HEAP[offset | 29] << 16 | HEAP[offset | 30] << 8 | HEAP[offset | 31], HEAP[offset | 32] << 24 | HEAP[offset | 33] << 16 | HEAP[offset | 34] << 8 | HEAP[offset | 35], HEAP[offset | 36] << 24 | HEAP[offset | 37] << 16 | HEAP[offset | 38] << 8 | HEAP[offset | 39], HEAP[offset | 40] << 24 | HEAP[offset | 41] << 16 | HEAP[offset | 42] << 8 | HEAP[offset | 43], HEAP[offset | 44] << 24 | HEAP[offset | 45] << 16 | HEAP[offset | 46] << 8 | HEAP[offset | 47], HEAP[offset | 48] << 24 | HEAP[offset | 49] << 16 | HEAP[offset | 50] << 8 | HEAP[offset | 51], HEAP[offset | 52] << 24 | HEAP[offset | 53] << 16 | HEAP[offset | 54] << 8 | HEAP[offset | 55], HEAP[offset | 56] << 24 | HEAP[offset | 57] << 16 | HEAP[offset | 58] << 8 | HEAP[offset | 59], HEAP[offset | 60] << 24 | HEAP[offset | 61] << 16 | HEAP[offset | 62] << 8 | HEAP[offset | 63]);
		}
		function _state_to_heap(output) {
			output = output | 0;
			HEAP[output | 0] = H0 >>> 24;
			HEAP[output | 1] = H0 >>> 16 & 255;
			HEAP[output | 2] = H0 >>> 8 & 255;
			HEAP[output | 3] = H0 & 255;
			HEAP[output | 4] = H1 >>> 24;
			HEAP[output | 5] = H1 >>> 16 & 255;
			HEAP[output | 6] = H1 >>> 8 & 255;
			HEAP[output | 7] = H1 & 255;
			HEAP[output | 8] = H2 >>> 24;
			HEAP[output | 9] = H2 >>> 16 & 255;
			HEAP[output | 10] = H2 >>> 8 & 255;
			HEAP[output | 11] = H2 & 255;
			HEAP[output | 12] = H3 >>> 24;
			HEAP[output | 13] = H3 >>> 16 & 255;
			HEAP[output | 14] = H3 >>> 8 & 255;
			HEAP[output | 15] = H3 & 255;
			HEAP[output | 16] = H4 >>> 24;
			HEAP[output | 17] = H4 >>> 16 & 255;
			HEAP[output | 18] = H4 >>> 8 & 255;
			HEAP[output | 19] = H4 & 255;
			HEAP[output | 20] = H5 >>> 24;
			HEAP[output | 21] = H5 >>> 16 & 255;
			HEAP[output | 22] = H5 >>> 8 & 255;
			HEAP[output | 23] = H5 & 255;
			HEAP[output | 24] = H6 >>> 24;
			HEAP[output | 25] = H6 >>> 16 & 255;
			HEAP[output | 26] = H6 >>> 8 & 255;
			HEAP[output | 27] = H6 & 255;
			HEAP[output | 28] = H7 >>> 24;
			HEAP[output | 29] = H7 >>> 16 & 255;
			HEAP[output | 30] = H7 >>> 8 & 255;
			HEAP[output | 31] = H7 & 255;
		}
		function reset() {
			H0 = 1779033703;
			H1 = 3144134277;
			H2 = 1013904242;
			H3 = 2773480762;
			H4 = 1359893119;
			H5 = 2600822924;
			H6 = 528734635;
			H7 = 1541459225;
			TOTAL0 = TOTAL1 = 0;
		}
		function init(h0, h1, h2, h3, h4, h5, h6, h7, total0, total1) {
			h0 = h0 | 0;
			h1 = h1 | 0;
			h2 = h2 | 0;
			h3 = h3 | 0;
			h4 = h4 | 0;
			h5 = h5 | 0;
			h6 = h6 | 0;
			h7 = h7 | 0;
			total0 = total0 | 0;
			total1 = total1 | 0;
			H0 = h0;
			H1 = h1;
			H2 = h2;
			H3 = h3;
			H4 = h4;
			H5 = h5;
			H6 = h6;
			H7 = h7;
			TOTAL0 = total0;
			TOTAL1 = total1;
		}
		function process(offset, length) {
			offset = offset | 0;
			length = length | 0;
			var hashed = 0;
			if (offset & 63) return -1;
			while ((length | 0) >= 64) {
				_core_heap(offset);
				offset = offset + 64 | 0;
				length = length - 64 | 0;
				hashed = hashed + 64 | 0;
			}
			TOTAL0 = TOTAL0 + hashed | 0;
			if (TOTAL0 >>> 0 < hashed >>> 0) TOTAL1 = TOTAL1 + 1 | 0;
			return hashed | 0;
		}
		function finish(offset, length, output) {
			offset = offset | 0;
			length = length | 0;
			output = output | 0;
			var hashed = 0, i = 0;
			if (offset & 63) return -1;
			if (~output) {
				if (output & 31) return -1;
			}
			if ((length | 0) >= 64) {
				hashed = process(offset, length) | 0;
				if ((hashed | 0) == -1) return -1;
				offset = offset + hashed | 0;
				length = length - hashed | 0;
			}
			hashed = hashed + length | 0;
			TOTAL0 = TOTAL0 + length | 0;
			if (TOTAL0 >>> 0 < length >>> 0) TOTAL1 = TOTAL1 + 1 | 0;
			HEAP[offset | length] = 128;
			if ((length | 0) >= 56) {
				for (i = length + 1 | 0; (i | 0) < 64; i = i + 1 | 0) HEAP[offset | i] = 0;
				_core_heap(offset);
				length = 0;
				HEAP[offset | 0] = 0;
			}
			for (i = length + 1 | 0; (i | 0) < 59; i = i + 1 | 0) HEAP[offset | i] = 0;
			HEAP[offset | 56] = TOTAL1 >>> 21 & 255;
			HEAP[offset | 57] = TOTAL1 >>> 13 & 255;
			HEAP[offset | 58] = TOTAL1 >>> 5 & 255;
			HEAP[offset | 59] = TOTAL1 << 3 & 255 | TOTAL0 >>> 29;
			HEAP[offset | 60] = TOTAL0 >>> 21 & 255;
			HEAP[offset | 61] = TOTAL0 >>> 13 & 255;
			HEAP[offset | 62] = TOTAL0 >>> 5 & 255;
			HEAP[offset | 63] = TOTAL0 << 3 & 255;
			_core_heap(offset);
			if (~output) _state_to_heap(output);
			return hashed | 0;
		}
		function hmac_reset() {
			H0 = I0;
			H1 = I1;
			H2 = I2;
			H3 = I3;
			H4 = I4;
			H5 = I5;
			H6 = I6;
			H7 = I7;
			TOTAL0 = 64;
			TOTAL1 = 0;
		}
		function _hmac_opad() {
			H0 = O0;
			H1 = O1;
			H2 = O2;
			H3 = O3;
			H4 = O4;
			H5 = O5;
			H6 = O6;
			H7 = O7;
			TOTAL0 = 64;
			TOTAL1 = 0;
		}
		function hmac_init(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15) {
			p0 = p0 | 0;
			p1 = p1 | 0;
			p2 = p2 | 0;
			p3 = p3 | 0;
			p4 = p4 | 0;
			p5 = p5 | 0;
			p6 = p6 | 0;
			p7 = p7 | 0;
			p8 = p8 | 0;
			p9 = p9 | 0;
			p10 = p10 | 0;
			p11 = p11 | 0;
			p12 = p12 | 0;
			p13 = p13 | 0;
			p14 = p14 | 0;
			p15 = p15 | 0;
			reset();
			_core(p0 ^ 1549556828, p1 ^ 1549556828, p2 ^ 1549556828, p3 ^ 1549556828, p4 ^ 1549556828, p5 ^ 1549556828, p6 ^ 1549556828, p7 ^ 1549556828, p8 ^ 1549556828, p9 ^ 1549556828, p10 ^ 1549556828, p11 ^ 1549556828, p12 ^ 1549556828, p13 ^ 1549556828, p14 ^ 1549556828, p15 ^ 1549556828);
			O0 = H0;
			O1 = H1;
			O2 = H2;
			O3 = H3;
			O4 = H4;
			O5 = H5;
			O6 = H6;
			O7 = H7;
			reset();
			_core(p0 ^ 909522486, p1 ^ 909522486, p2 ^ 909522486, p3 ^ 909522486, p4 ^ 909522486, p5 ^ 909522486, p6 ^ 909522486, p7 ^ 909522486, p8 ^ 909522486, p9 ^ 909522486, p10 ^ 909522486, p11 ^ 909522486, p12 ^ 909522486, p13 ^ 909522486, p14 ^ 909522486, p15 ^ 909522486);
			I0 = H0;
			I1 = H1;
			I2 = H2;
			I3 = H3;
			I4 = H4;
			I5 = H5;
			I6 = H6;
			I7 = H7;
			TOTAL0 = 64;
			TOTAL1 = 0;
		}
		function hmac_finish(offset, length, output) {
			offset = offset | 0;
			length = length | 0;
			output = output | 0;
			var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, hashed = 0;
			if (offset & 63) return -1;
			if (~output) {
				if (output & 31) return -1;
			}
			hashed = finish(offset, length, -1) | 0;
			t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
			_hmac_opad();
			_core(t0, t1, t2, t3, t4, t5, t6, t7, 2147483648, 0, 0, 0, 0, 0, 0, 768);
			if (~output) _state_to_heap(output);
			return hashed | 0;
		}
		function pbkdf2_generate_block(offset, length, block, count, output) {
			offset = offset | 0;
			length = length | 0;
			block = block | 0;
			count = count | 0;
			output = output | 0;
			var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0;
			if (offset & 63) return -1;
			if (~output) {
				if (output & 31) return -1;
			}
			HEAP[offset + length | 0] = block >>> 24;
			HEAP[offset + length + 1 | 0] = block >>> 16 & 255;
			HEAP[offset + length + 2 | 0] = block >>> 8 & 255;
			HEAP[offset + length + 3 | 0] = block & 255;
			hmac_finish(offset, length + 4 | 0, -1) | 0;
			h0 = t0 = H0, h1 = t1 = H1, h2 = t2 = H2, h3 = t3 = H3, h4 = t4 = H4, h5 = t5 = H5, h6 = t6 = H6, h7 = t7 = H7;
			count = count - 1 | 0;
			while ((count | 0) > 0) {
				hmac_reset();
				_core(t0, t1, t2, t3, t4, t5, t6, t7, 2147483648, 0, 0, 0, 0, 0, 0, 768);
				t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
				_hmac_opad();
				_core(t0, t1, t2, t3, t4, t5, t6, t7, 2147483648, 0, 0, 0, 0, 0, 0, 768);
				t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
				h0 = h0 ^ H0;
				h1 = h1 ^ H1;
				h2 = h2 ^ H2;
				h3 = h3 ^ H3;
				h4 = h4 ^ H4;
				h5 = h5 ^ H5;
				h6 = h6 ^ H6;
				h7 = h7 ^ H7;
				count = count - 1 | 0;
			}
			H0 = h0;
			H1 = h1;
			H2 = h2;
			H3 = h3;
			H4 = h4;
			H5 = h5;
			H6 = h6;
			H7 = h7;
			if (~output) _state_to_heap(output);
			return 0;
		}
		return {
			reset,
			init,
			process,
			finish,
			hmac_reset,
			hmac_init,
			hmac_finish,
			pbkdf2_generate_block
		};
	};
	//#endregion
	//#region node_modules/asmcrypto.js/dist_es8/hash/hash.js
	var Hash = class {
		constructor() {
			this.pos = 0;
			this.len = 0;
		}
		reset() {
			this.result = null;
			this.pos = 0;
			this.len = 0;
			this.asm.reset();
			return this;
		}
		process(data) {
			if (this.result !== null) throw new IllegalStateError("state must be reset before processing new data");
			let asm = this.asm;
			let heap = this.heap;
			let hpos = this.pos;
			let hlen = this.len;
			let dpos = 0;
			let dlen = data.length;
			let wlen = 0;
			while (dlen > 0) {
				wlen = _heap_write(heap, hpos + hlen, data, dpos, dlen);
				hlen += wlen;
				dpos += wlen;
				dlen -= wlen;
				wlen = asm.process(hpos, hlen);
				hpos += wlen;
				hlen -= wlen;
				if (!hlen) hpos = 0;
			}
			this.pos = hpos;
			this.len = hlen;
			return this;
		}
		finish() {
			if (this.result !== null) throw new IllegalStateError("state must be reset before processing new data");
			this.asm.finish(this.pos, this.len, 0);
			this.result = new Uint8Array(this.HASH_SIZE);
			this.result.set(this.heap.subarray(0, this.HASH_SIZE));
			this.pos = 0;
			this.len = 0;
			return this;
		}
	};
	var Sha256 = class extends Hash {
		constructor() {
			super();
			this.NAME = "sha256";
			this.BLOCK_SIZE = 64;
			this.HASH_SIZE = 32;
			this.heap = _heap_init();
			this.asm = sha256_asm({ Uint8Array }, null, this.heap.buffer);
			this.reset();
		}
	};
	Sha256.NAME = "sha256";
	//#endregion
	//#region scripts/provider-api-subscription.js
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
		var _$arguments, _$arguments2, _globalThis$process;
		const CFG_USER_AGENT = "Mozilla/5.0 (dart:io) SuperAccelerator";
		const DEFAULT_SUBSCRIPTION_DECRYPT = Object.freeze({
			type: "aes-256-gcm",
			password: "86f2e72ead6e985e"
		});
		const CACHE_PREFIX = "provider-api-subscription:";
		const SUBSCRIBE_URL_CACHE_PREFIX = "#sub-store-cached-provider-script-subscribe-url-";
		const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		let nodeRuntime;
		let nodeRuntimeResolved = false;
		const raw = Array.isArray(context === null || context === void 0 ? void 0 : context.raw) ? context.raw.filter((item) => item != null).join("\n") : (context === null || context === void 0 ? void 0 : context.raw) == null ? "" : String(context.raw);
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
		const timeout = positiveNumber((_$arguments = $arguments) === null || _$arguments === void 0 ? void 0 : _$arguments.timeout) ? Number($arguments.timeout) : settings.defaultTimeout || 8e3;
		const proxy = ((_$arguments2 = $arguments) === null || _$arguments2 === void 0 ? void 0 : _$arguments2.proxy) || settings.defaultProxy || ((_globalThis$process = globalThis.process) === null || _globalThis$process === void 0 || (_globalThis$process = _globalThis$process.env) === null || _globalThis$process === void 0 ? void 0 : _globalThis$process.SUB_STORE_BACKEND_DEFAULT_PROXY);
		if (config.apex) {
			clearAutoSubUserinfo();
			const key = Symbol.for("sub-store.provider-api-subscription.refresh-tasks");
			const tasks = globalThis[key] instanceof Map ? globalThis[key] : globalThis[key] = /* @__PURE__ */ new Map();
			const refreshKey = `${CACHE_PREFIX}apex-refresh:${configHash}`;
			if (tasks.has(refreshKey)) return tasks.get(refreshKey);
			const task = runApexProvider({
				config,
				runtime: getNodeRuntime(),
				timeout,
				proxy,
				sensitiveValues,
				errorMessage,
				cacheKey: `${CACHE_PREFIX}apex-url:${configHash}`
			});
			tasks.set(refreshKey, task);
			try {
				return await task;
			} finally {
				tasks.delete(refreshKey);
			}
		}
		const fetchAndParse = async (subscribeUrl) => {
			let lastError;
			const requestUrl = normalizeString(subscribeUrl).split("#")[0].trim();
			try {
				const content = await fetchSubscriptionContent(requestUrl);
				const candidates = [content];
				const isSn2 = content.trim().startsWith("SN2.");
				if (isSn2) candidates.splice(0, 1, await decryptSn2Subscription(content));
				if (!isSn2 && config.decrypt) try {
					candidates.push(await decryptAesBase64(content, config.decrypt));
				} catch (error) {
					lastError = error;
				}
				if (!isSn2 && config.subscriptionDecrypt) try {
					candidates.push(await decryptSubscriptionContent(content, config.subscriptionDecrypt));
				} catch (error) {
					lastError = error;
				}
				if (!isSn2) try {
					const mirrored = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210/+";
					const normalized = content.trim().replace(/[A-Za-z0-9+/]/g, (char) => BASE64_ALPHABET[mirrored.indexOf(char)]);
					candidates.push(bytesToUtf8(base64ToBytes(normalized)));
				} catch (_unused) {}
				for (const candidate of candidates) try {
					const parsed = ProxyUtils.parse(candidate);
					if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("provider API 订阅未解析到有效节点");
					return parsed;
				} catch (error) {
					lastError = error;
				}
			} catch (error) {
				lastError = error;
			}
			throw lastError || /* @__PURE__ */ new Error("provider API 订阅未解析到有效节点");
		};
		const cachedSubscribeUrl = normalizeString($substore.read(subscribeUrlCacheKey)).trim();
		if (cachedSubscribeUrl) try {
			const parsed = await fetchAndParse(cachedSubscribeUrl);
			persistSubUserinfo(cachedSubscribeUrl);
			return parsed;
		} catch (error) {
			$substore.info(`provider API 缓存的订阅地址已失效，将重新获取: ${errorMessage(error)}`);
			$substore.write("", subscribeUrlCacheKey);
			$substore.write("", subscribeUuidCacheKey);
			subscriptionUuid = "";
			clearAutoSubUserinfo();
		}
		const refreshTasksKey = Symbol.for("sub-store.provider-api-subscription.refresh-tasks");
		const refreshTasks = globalThis[refreshTasksKey] instanceof Map ? globalThis[refreshTasksKey] : globalThis[refreshTasksKey] = /* @__PURE__ */ new Map();
		const refreshKey = `${CACHE_PREFIX}refresh:${configHash}`;
		if (refreshTasks.has(refreshKey)) return refreshTasks.get(refreshKey);
		const task = (async () => {
			const refreshedCachedUrl = normalizeString($substore.read(subscribeUrlCacheKey)).trim();
			if (refreshedCachedUrl) {
				subscriptionUuid = normalizeString($substore.read(subscribeUuidCacheKey)).trim();
				if (subscriptionUuid) sensitiveValues.push(subscriptionUuid);
				const parsed = await fetchAndParse(refreshedCachedUrl);
				persistSubUserinfo(refreshedCachedUrl);
				return parsed;
			}
			const baseURLs = await fetchBaseURLs();
			const authHeaders = {
				"User-Agent": CFG_USER_AGENT,
				Accept: "application/json"
			};
			const failures = [];
			for (const baseURL of baseURLs) {
				let stage = "登录";
				try {
					const authData = await login(baseURL, authHeaders);
					sensitiveValues.push(authData);
					stage = "获取订阅地址";
					const { subscribeUrl, token, uuid } = await getSubscribe(baseURL, authData, authHeaders);
					if (token) sensitiveValues.push(token);
					subscriptionUuid = uuid;
					if (uuid) sensitiveValues.push(uuid);
					const candidates = [subscribeUrl];
					if (token) for (const fallbackBaseURL of baseURLs) candidates.push(fallbackSubscribeURL(fallbackBaseURL, token));
					for (const candidate of unique(candidates.filter(Boolean))) try {
						const parsed = await fetchAndParse(candidate);
						$substore.write(candidate, subscribeUrlCacheKey);
						$substore.write(subscriptionUuid, subscribeUuidCacheKey);
						persistSubUserinfo(candidate);
						return parsed;
					} catch (error) {
						failures.push(`下载订阅 ${requestOrigin(candidate)}: ${errorMessage(error)}`);
					}
				} catch (error) {
					failures.push(`${stage} ${requestOrigin(baseURL)}: ${errorMessage(error)}`);
				}
			}
			throw new Error(`provider API 订阅获取失败: ${unique(failures).join("；") || "无可用订阅地址"}`);
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
				value = (yaml.parse || yaml.safeLoad || yaml.load).call(yaml, normalizeString(content));
			} catch (error) {
				throw new Error(`provider 参数 YAML 解析失败: ${errorMessage(error)}`);
			}
			if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("provider 参数 YAML 必须为对象");
			const cfgUrls = (Array.isArray(value.cfgUrls) ? value.cfgUrls : value.cfgUrls == null ? [] : [value.cfgUrls]).map((url) => normalizeString(url).trim()).filter(Boolean);
			if (cfgUrls.length === 0) throw new Error("provider 参数 cfgUrls 不能为空");
			return {
				cfgUrls,
				apex: normalizeApex(value.apex),
				username: normalizeString(value.username),
				password: normalizeString(value.password),
				headers: normalizeHeaders(value.headers),
				decrypt: normalizeDecrypt(value.decrypt),
				subscriptionDecrypt: normalizeSubscriptionDecrypt(value.subscriptionDecrypt) || DEFAULT_SUBSCRIPTION_DECRYPT
			};
		}
		function normalizeDecrypt(decrypt) {
			if (decrypt == null) return null;
			if (typeof decrypt !== "object" || Array.isArray(decrypt)) throw new Error("provider 参数 decrypt 必须为 null 或对象");
			return {
				key: normalizeString(decrypt.key),
				iv: normalizeString(decrypt.iv)
			};
		}
		function normalizeSubscriptionDecrypt(decrypt) {
			if (decrypt == null) return null;
			if (typeof decrypt !== "object" || Array.isArray(decrypt)) throw new Error("provider 参数 subscriptionDecrypt 必须为 null 或对象");
			const type = normalizeString(decrypt.type).trim().toLowerCase();
			const password = normalizeString(decrypt.password).trim();
			if (type !== "aes-256-gcm") throw new Error("provider 参数 subscriptionDecrypt.type 仅支持 aes-256-gcm");
			if (!password) throw new Error("provider 参数 subscriptionDecrypt.password 不能为空");
			return {
				type,
				password
			};
		}
		async function fetchBaseURLs() {
			const baseURLs = unique((await Promise.all(config.cfgUrls.map(async (cfgUrl) => {
				try {
					return await fetchConfigHosts(cfgUrl);
				} catch (error) {
					$substore.error(`provider cfgUrl ${requestOrigin(cfgUrl)} 获取失败: ${errorMessage(error)}`);
					return [];
				}
			}))).flat().flatMap((host) => baseURLCandidates(host)));
			if (baseURLs.length === 0) throw new Error("provider cfgUrl 未返回可用的服务地址");
			return baseURLs;
		}
		async function fetchConfigHosts(cfgUrl) {
			const response = await request("get", cfgUrl, { headers: { "User-Agent": CFG_USER_AGENT } });
			let cfg;
			try {
				cfg = JSON.parse(decodeBase64Text(response.body));
			} catch (plainError) {
				if (!config.decrypt) throw new Error(`cfgUrl 内容解析失败: ${errorMessage(plainError)}`);
				try {
					cfg = JSON.parse(await decryptOssConfig(response.body, config.decrypt));
				} catch (decryptError) {
					throw new Error(`cfgUrl 内容解密失败: ${errorMessage(decryptError)}`);
				}
			}
			const hosts = [...Array.isArray(cfg === null || cfg === void 0 ? void 0 : cfg.hosts) ? cfg.hosts : [], cfg === null || cfg === void 0 ? void 0 : cfg.host_source].map((host) => normalizeString(host).trim()).filter(Boolean);
			if (hosts.length === 0) throw new Error("cfgUrl 未返回可用 hosts");
			return hosts;
		}
		async function login(baseURL, headers) {
			var _data$data;
			const data = parseJSON((await request("post", `${baseURL}/passport/auth/login`, {
				headers: {
					...headers,
					"Content-Type": "application/json"
				},
				body: JSON.stringify({
					email: config.username,
					password: config.password
				})
			})).body, "登录响应");
			const authData = normalizeString(data === null || data === void 0 || (_data$data = data.data) === null || _data$data === void 0 ? void 0 : _data$data.auth_data).trim();
			if (!authData) throw new Error("登录响应缺少 auth_data");
			return authData;
		}
		async function getSubscribe(baseURL, authData, headers) {
			var _parseJSON;
			const data = ((_parseJSON = parseJSON((await request("get", `${baseURL}/user/getSubscribe`, { headers: {
				...headers,
				Authorization: authData
			} })).body, "getSubscribe 响应")) === null || _parseJSON === void 0 ? void 0 : _parseJSON.data) || {};
			const subscribeUrl = normalizeString(data.subscribe_url).trim();
			const token = normalizeString(data.token).trim();
			const uuid = normalizeString(data.uuid).trim();
			if (!subscribeUrl && !token) throw new Error("getSubscribe 响应缺少 subscribe_url 或 token");
			return {
				subscribeUrl,
				token,
				uuid
			};
		}
		async function fetchSubscriptionContent(subscribeUrl) {
			var _$substore$env;
			const content = bodyToText((await request("get", subscribeUrl, {
				headers: config.headers,
				encoding: null,
				...((_$substore$env = $substore.env) === null || _$substore$env === void 0 ? void 0 : _$substore$env.isNode) ? { strictSSL: false } : { insecure: true }
			})).body);
			if (!content.trim()) throw new Error("provider API 订阅内容为空");
			if (/^\s*(?:<!doctype\s+html\b|<html\b)/i.test(content)) throw new Error("订阅地址返回 HTML 验证页或错误页，未收到节点配置");
			return content;
		}
		async function decryptOssConfig(body, decrypt) {
			return decryptAesBase64(body, decrypt);
		}
		async function decryptSubscriptionContent(body, decrypt) {
			const encrypted = base64ToBytes(bodyToText(body));
			if (encrypted.length <= 28) throw new Error("AES-GCM 订阅密文长度无效");
			const nonce = encrypted.subarray(0, 12);
			const tag = encrypted.subarray(encrypted.length - 16);
			const ciphertext = encrypted.subarray(12, encrypted.length - 16);
			const sealed = encrypted.subarray(12);
			const password = utf8ToBytes(decrypt.password);
			const runtime = getNodeRuntime();
			if (runtime) try {
				const key = runtime.crypto.createHash("sha256").update(runtime.Buffer.from(password)).digest();
				const decipher = runtime.crypto.createDecipheriv("aes-256-gcm", key, runtime.Buffer.from(nonce));
				decipher.setAuthTag(runtime.Buffer.from(tag));
				return runtime.Buffer.concat([decipher.update(runtime.Buffer.from(ciphertext)), decipher.final()]).toString("utf8");
			} catch (_unused2) {}
			const webCryptoPlainText = await tryWebCryptoGcm(password, nonce, sealed);
			if (webCryptoPlainText) return bytesToUtf8(webCryptoPlainText);
			const key = new Sha256().process(password).finish().result;
			if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("AES-GCM SHA-256 密钥派生失败");
			return bytesToUtf8(AES_GCM.decrypt(sealed, key, nonce, void 0, 16));
		}
		async function decryptSn2Subscription(body) {
			var _config$subscriptionD;
			const parts = body.trim().split(".");
			const expiresAt = Number(parts[1]);
			if (parts.length !== 3 || !/^\d+$/.test(parts[1]) || !Number.isSafeInteger(expiresAt)) throw new Error("SN2 订阅封装格式无效");
			if (Math.floor(Date.now() / 1e3) > expiresAt) throw new Error("SN2 订阅已过期，请重新获取");
			if (!subscriptionUuid) throw new Error("SN2 订阅解密缺少账号 UUID，getSubscribe 未返回 uuid");
			const seed = /^[0-9a-f]{32}$/.test((_config$subscriptionD = config.subscriptionDecrypt) === null || _config$subscriptionD === void 0 ? void 0 : _config$subscriptionD.password) ? config.subscriptionDecrypt.password : "66d570165fad0012ba46077644ac1ba6";
			return decryptSubscriptionContent(parts[2], { password: `${seed}${subscriptionUuid}` });
		}
		async function decryptAesBase64(body, decrypt) {
			const key = utf8ToBytes(decrypt.key);
			const iv = utf8ToBytes(decrypt.iv);
			if (key.length !== 16 || iv.length !== 16) throw new Error("AES key 和 iv 必须均为 16 字节");
			const encrypted = base64ToBytes(bodyToText(body));
			const runtime = getNodeRuntime();
			if (runtime) try {
				const decipher = runtime.crypto.createDecipheriv("aes-128-cbc", runtime.Buffer.from(key), runtime.Buffer.from(iv));
				const plainText = runtime.Buffer.concat([decipher.update(runtime.Buffer.from(encrypted)), decipher.final()]);
				return decodeNestedBase64(new Uint8Array(plainText.buffer, plainText.byteOffset, plainText.byteLength));
			} catch (_unused3) {}
			const webCryptoPlainText = await tryWebCryptoCbc(key, iv, encrypted);
			if (webCryptoPlainText) try {
				return decodeNestedBase64(webCryptoPlainText);
			} catch (_unused4) {}
			return decodeNestedBase64(AES_CBC.decrypt(encrypted, key, true, iv));
		}
		function decodeNestedBase64(value) {
			return bytesToUtf8(base64ToBytes(bytesToUtf8(value).trim()));
		}
		function getNodeRuntime() {
			var _$substore$env2;
			if (nodeRuntimeResolved) return nodeRuntime;
			nodeRuntimeResolved = true;
			nodeRuntime = null;
			if (!((_$substore$env2 = $substore.env) === null || _$substore$env2 === void 0 ? void 0 : _$substore$env2.isNode)) return nodeRuntime;
			try {
				var _globalThis$process2;
				const loadModule = ((_globalThis$process2 = globalThis.process) === null || _globalThis$process2 === void 0 ? void 0 : _globalThis$process2.getBuiltinModule) ? (name) => globalThis.process.getBuiltinModule(name) : typeof require === "function" ? (name) => require(name) : null;
				const crypto = loadModule === null || loadModule === void 0 ? void 0 : loadModule("crypto");
				const NodeBuffer = globalThis.Buffer;
				if (typeof (crypto === null || crypto === void 0 ? void 0 : crypto.createDecipheriv) === "function" && typeof (crypto === null || crypto === void 0 ? void 0 : crypto.createHash) === "function" && typeof (NodeBuffer === null || NodeBuffer === void 0 ? void 0 : NodeBuffer.from) === "function") nodeRuntime = {
					crypto,
					Buffer: NodeBuffer,
					loadModule
				};
			} catch (_unused5) {
				nodeRuntime = null;
			}
			return nodeRuntime;
		}
		function getWebCryptoSubtle(requiredMethods) {
			var _globalThis$crypto;
			const subtle = (_globalThis$crypto = globalThis.crypto) === null || _globalThis$crypto === void 0 ? void 0 : _globalThis$crypto.subtle;
			if (!subtle) return null;
			return requiredMethods.every((method) => typeof subtle[method] === "function") ? subtle : null;
		}
		async function tryWebCryptoCbc(key, iv, encrypted) {
			const subtle = getWebCryptoSubtle(["importKey", "decrypt"]);
			if (!subtle) return null;
			try {
				const cryptoKey = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"]);
				const plainText = await subtle.decrypt({
					name: "AES-CBC",
					iv
				}, cryptoKey, encrypted);
				return new Uint8Array(plainText);
			} catch (_unused6) {
				return null;
			}
		}
		async function tryWebCryptoGcm(password, nonce, sealed) {
			const subtle = getWebCryptoSubtle([
				"digest",
				"importKey",
				"decrypt"
			]);
			if (!subtle) return null;
			try {
				const keyBytes = new Uint8Array(await subtle.digest("SHA-256", password));
				const cryptoKey = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
				const plainText = await subtle.decrypt({
					name: "AES-GCM",
					iv: nonce,
					tagLength: 128
				}, cryptoKey, sealed);
				return new Uint8Array(plainText);
			} catch (_unused7) {
				return null;
			}
		}
		function decodeBase64Text(value) {
			return bytesToUtf8(base64ToBytes(value));
		}
		function normalizeBase64(value) {
			return normalizeString(value).trim().replace(/^\uFEFF/, "").replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
		}
		function base64ToBytes(value) {
			const normalized = normalizeBase64(value);
			if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error("Base64 内容包含无效字符");
			const input = normalized.replace(/=+$/, "");
			if (input.length % 4 === 1) throw new Error("Base64 内容长度无效");
			const output = new Uint8Array(Math.floor(input.length * 6 / 8));
			let accumulator = 0;
			let bits = 0;
			let outputPos = 0;
			for (let index = 0; index < input.length; index++) {
				const digit = BASE64_ALPHABET.indexOf(input[index]);
				if (digit < 0) throw new Error("Base64 内容包含无效字符");
				accumulator = accumulator << 6 | digit;
				bits += 6;
				if (bits >= 8) {
					bits -= 8;
					output[outputPos++] = accumulator >>> bits & 255;
					accumulator &= (1 << bits) - 1;
				}
			}
			return output;
		}
		function utf8ToBytes(value) {
			const text = normalizeString(value);
			if (typeof TextEncoder !== "undefined") try {
				return new TextEncoder().encode(text);
			} catch (_unused8) {}
			const bytes = [];
			for (let index = 0; index < text.length; index++) {
				let codePoint = text.charCodeAt(index);
				if (codePoint >= 55296 && codePoint <= 56319 && index + 1 < text.length) {
					const next = text.charCodeAt(index + 1);
					if (next >= 56320 && next <= 57343) {
						codePoint = 65536 + (codePoint - 55296 << 10) + (next - 56320);
						index++;
					}
				}
				if (codePoint <= 127) bytes.push(codePoint);
				else if (codePoint <= 2047) bytes.push(192 | codePoint >>> 6, 128 | codePoint & 63);
				else if (codePoint <= 65535) bytes.push(224 | codePoint >>> 12, 128 | codePoint >>> 6 & 63, 128 | codePoint & 63);
				else bytes.push(240 | codePoint >>> 18, 128 | codePoint >>> 12 & 63, 128 | codePoint >>> 6 & 63, 128 | codePoint & 63);
			}
			return Uint8Array.from(bytes);
		}
		function bytesToUtf8(value) {
			const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
			if (typeof TextDecoder !== "undefined") try {
				return new TextDecoder("utf-8").decode(bytes);
			} catch (_unused9) {}
			let output = "";
			for (let index = 0; index < bytes.length;) {
				const first = bytes[index++];
				let codePoint;
				let continuationCount;
				if (first <= 127) {
					codePoint = first;
					continuationCount = 0;
				} else if ((first & 224) === 192) {
					codePoint = first & 31;
					continuationCount = 1;
				} else if ((first & 240) === 224) {
					codePoint = first & 15;
					continuationCount = 2;
				} else if ((first & 248) === 240) {
					codePoint = first & 7;
					continuationCount = 3;
				} else throw new Error("UTF-8 内容无效");
				for (let offset = 0; offset < continuationCount; offset++) {
					const next = bytes[index++];
					if (next === void 0 || (next & 192) !== 128) throw new Error("UTF-8 内容无效");
					codePoint = codePoint << 6 | next & 63;
				}
				if (codePoint <= 65535) output += String.fromCharCode(codePoint);
				else {
					codePoint -= 65536;
					output += String.fromCharCode(55296 | codePoint >>> 10, 56320 | codePoint & 1023);
				}
			}
			return output;
		}
		function bodyToText(value) {
			var _$substore$env3;
			if (((_$substore$env3 = $substore.env) === null || _$substore$env3 === void 0 ? void 0 : _$substore$env3.isNode) && typeof Buffer !== "undefined") {
				if (Buffer.isBuffer(value) || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return toBuffer(value).toString("utf8");
			}
			return normalizeString(value);
		}
		async function request(method, url, options = {}) {
			const requestOptions = {
				url,
				timeout,
				...options,
				...proxy ? getProxyOptions(proxy) : {}
			};
			const response = await $substore.http[method](requestOptions);
			if (!response || response.statusCode !== 200 || response.body == null) {
				var _response$statusCode;
				throw new Error(`provider API 请求返回状态码 ${(_response$statusCode = response === null || response === void 0 ? void 0 : response.statusCode) !== null && _response$statusCode !== void 0 ? _response$statusCode : "unknown"}`);
			}
			return response;
		}
		function getProxyOptions(selectedProxy) {
			var _$substore$env4, _$substore$env5;
			const options = { proxy: selectedProxy };
			if ((_$substore$env4 = $substore.env) === null || _$substore$env4 === void 0 ? void 0 : _$substore$env4.isLoon) options.node = selectedProxy;
			if ((_$substore$env5 = $substore.env) === null || _$substore$env5 === void 0 ? void 0 : _$substore$env5.isQX) options.opts = { policy: selectedProxy };
			return options;
		}
		function buildSubUserinfoUrl(url, headers) {
			return buildUrlArguments(url, headers, {
				providerScriptAutoSubUserinfo: true,
				insecure: true
			});
		}
		function buildUrlArguments(url, headers, extraArguments = {}) {
			const baseUrl = normalizeString(url).split("#")[0];
			const argumentsObject = { ...extraArguments };
			if (Object.keys(headers).length > 0) argumentsObject.headers = JSON.stringify(headers);
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
			const source = context === null || context === void 0 ? void 0 : context.source;
			if (!source || typeof source !== "object" || Array.isArray(source)) return;
			const sourceEntries = Object.entries(source).filter(([name, sub]) => !name.startsWith("_") && sub && typeof sub === "object" && sub.source === "local");
			if (sourceEntries.length === 0) return;
			const allSubs = $substore.read("subs");
			if (!Array.isArray(allSubs)) return;
			let changed = false;
			for (const [name, sourceSub] of sourceEntries) {
				const sub = allSubs.find((item) => (item === null || item === void 0 ? void 0 : item.name) === name);
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
				return (argumentsObject === null || argumentsObject === void 0 ? void 0 : argumentsObject.providerScriptAutoSubUserinfo) === true;
			} catch (error) {
				return false;
			}
		}
		function baseURLCandidates(baseURL) {
			const normalized = normalizeBaseURL(baseURL);
			if (!normalized) return [];
			if (normalized.endsWith("/api/v1")) return [normalized];
			if (normalized.endsWith("/api")) return [normalized, `${normalized}/v1`];
			return [`${normalized}/api/v1`];
		}
		function fallbackSubscribeURL(baseURL, token) {
			return `${normalizeBaseURL(baseURL)}/client/subscribe?token=${encodeURIComponent(token)}`;
		}
		function normalizeBaseURL(value) {
			return normalizeString(value).trim().replace(/\/+$/, "");
		}
		function normalizeHeaders(headers) {
			if (!headers || typeof headers !== "object" || Array.isArray(headers)) return {};
			return Object.fromEntries(Object.entries(headers).filter(([key, value]) => key && value != null).map(([key, value]) => [String(key), String(value)]));
		}
		function stableStringify(value) {
			if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
			if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
			return JSON.stringify(value);
		}
		function getHash(value) {
			if (typeof ProxyUtils.hex_md5 === "function") return ProxyUtils.hex_md5(value);
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
			if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
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
			const seen = /* @__PURE__ */ new Set();
			for (let current = error; current != null && !seen.has(current); current = current === null || current === void 0 ? void 0 : current.cause) {
				var _current$message;
				seen.add(current);
				messages.push((_current$message = current === null || current === void 0 ? void 0 : current.message) !== null && _current$message !== void 0 ? _current$message : String(current));
				if (current === null || current === void 0 ? void 0 : current.code) messages.push(String(current.code));
				if (seen.size >= 4) break;
			}
			let message = unique(messages).join(": ");
			message = message.replace(/([?&][^=&#\s]+)=([^&#\s]*)/g, "$1=[redacted]");
			for (const secret of sensitiveValues) {
				if (!secret) continue;
				message = message.split(secret).join("[redacted]");
				message = message.split(encodeURIComponent(secret)).join("[redacted]");
			}
			return message;
		}
		function requestOrigin(url) {
			var _normalizeString$matc;
			return ((_normalizeString$matc = normalizeString(url).match(/^https?:\/\/([^/?#]+)/i)) === null || _normalizeString$matc === void 0 ? void 0 : _normalizeString$matc[0].replace(/\/\/[^/@]+@/, "//[redacted]@")) || "未知服务";
		}
	}
	//#endregion
	exports.operator = operator;
	return exports;
})({});
var operator = ProviderApiSubscription.operator;

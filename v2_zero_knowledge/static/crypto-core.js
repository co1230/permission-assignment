/**
 * V2 核心密码学逻辑（纯 Web Crypto，浏览器与服务端都不依赖第三方库）
 *
 * 加密流程（信封加密 / hybrid encryption）：
 *   1) 每个文件随机生成一把一次性 AES-256 数据密钥（只在浏览器内存里）
 *   2) 用这把数据密钥加密文件内容（AES-256-GCM，带认证标签）
 *   3) 用"小张的 RSA 公钥"把数据密钥封装起来（RSA-OAEP-SHA256）
 *   4) 上传给服务端的只有：密文 + nonce + 被公钥封装的数据密钥
 *
 * 解密流程只在有私钥的人（小张）的浏览器里发生：
 *   私钥包（口令加密的 PKCS#8）→ 口令解开 → 私钥解封数据密钥 → 解出明文
 *
 * 服务端既没有私钥，也没有明文数据密钥，因此无法解密。
 */

const RSA_PARAMS = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

const WRAP_KDF = { name: "PBKDF2", hash: "SHA-256", iterations: 250000 };
const AAD_FILE = "v2-file-envelope";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toB64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function fromB64(text) {
  const binary = atob(String(text).trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function sha256B64(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 小张首次使用时：在浏览器本地生成 RSA 密钥对（私钥不离开本机） */
export async function generateAdminKeyPair() {
  const pair = await crypto.subtle.generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  return {
    publicKeySpkiB64: toB64(spki),
    privateKeyPkcs8B64: toB64(pkcs8),
    fingerprint: await sha256B64(spki),
  };
}

export async function importPublicKey(spkiB64) {
  return crypto.subtle.importKey("spki", fromB64(spkiB64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

/** 用口令把私钥加密成一个可以下载保存的密钥包（PBKDF2 + AES-GCM） */
export async function wrapPrivateKey(privateKeyPkcs8B64, passphrase, meta = {}) {
  if (!passphrase || passphrase.length < 6) throw new Error("口令至少 6 位");
  const pkcs8 = fromB64(privateKeyPkcs8B64);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const wrapKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: WRAP_KDF.iterations, hash: WRAP_KDF.hash },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("v2-private-key-wrap") },
    wrapKey,
    pkcs8
  );
  return {
    v: 1,
    type: "v2-private-key",
    owner: meta.owner || "小张",
    created_at: new Date().toISOString(),
    public_key_fingerprint: meta.fingerprint || "",
    kdf: { ...WRAP_KDF, salt_b64: toB64(salt) },
    cipher: { name: "AES-GCM", iv_b64: toB64(iv) },
    ciphertext_b64: toB64(ciphertext),
    hint: "这是小张的私钥包，已用口令加密。请离线保存，不要上传给任何人 / 任何服务器。",
  };
}

/** 小张在本机用口令打开私钥包 */
export async function unwrapPrivateKey(wrapped, passphrase) {
  if (!wrapped || wrapped.type !== "v2-private-key") throw new Error("不是有效的私钥包文件");
  const salt = fromB64(wrapped.kdf.salt_b64);
  const iv = fromB64(wrapped.cipher.iv_b64);
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const unwrapKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: wrapped.kdf.iterations, hash: wrapped.kdf.hash },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode("v2-private-key-wrap") },
      unwrapKey,
      fromB64(wrapped.ciphertext_b64)
    );
  } catch (_) {
    throw new Error("口令错误，或私钥包已损坏");
  }
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

/** 加密：返回可以上传的密文与信封信息（不含任何明文密钥） */
export async function encryptFile(buffer, publicKeyB64, filename, onProgress) {
  const publicKey = await importPublicKey(publicKeyB64);
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await crypto.subtle.importKey("raw", dataKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  onProgress && onProgress("正在加密（AES-256-GCM）…");
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(`${AAD_FILE}|${filename}`) },
    aesKey,
    buffer
  );

  onProgress && onProgress("正在用公钥封装密钥（RSA-OAEP）…");
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dataKey);
  dataKey.fill(0);

  return {
    ciphertext: new Uint8Array(ciphertext),
    nonceB64: toB64(nonce),
    wrappedKeyB64: toB64(wrappedKey),
    sha256Cipher: await sha256B64(ciphertext),
  };
}

/** 解密：只在持有私钥的浏览器里执行 */
export async function decryptFile(cipherBuffer, envelope, privateKey) {
  const nonce = fromB64(envelope.nonce_b64);
  let dataKey;
  try {
    dataKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, fromB64(envelope.wrapped_key_b64));
  } catch (_) {
    throw new Error("私钥与这个文件不匹配（可能不是同一对密钥）");
  }
  const aesKey = await crypto.subtle.importKey("raw", dataKey, { name: "AES-GCM" }, false, ["decrypt"]);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(`${AAD_FILE}|${envelope.filename}`) },
      aesKey,
      cipherBuffer
    );
  } catch (_) {
    throw new Error("解密失败：密文被改动，或文件名被修改（文件名参与认证）");
  }
  return new Uint8Array(plain);
}

export function describeBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = next;
  }
  return `${value.toFixed(1)} ${unit}`;
}

export { decoder, encoder, AAD_FILE };

/**
 * demo_code.js — 测试用 JavaScript 源码文件
 *
 * 用途：验证 JS 源码（模板字符串、注释、中文）在加解密往返后一致。
 * 这段代码演示浏览器端 AES-GCM + RSA-OAEP 的"信封加密"。
 */

const encoder = new TextEncoder();

/** 生成一次性 AES-256 数据密钥 */
export async function newDataKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** 用 AES-GCM 加密文件内容，返回密文与 nonce */
export async function encryptBytes(bytes, key) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode("demo") },
    key,
    bytes
  );
  return { ciphertext, nonce };
}

/** 用 RSA 公钥封装数据密钥：服务端即使拿到它，没有私钥也解不开 */
export async function wrapKey(dataKey, publicKey) {
  const raw = await crypto.subtle.exportKey("raw", dataKey);
  return crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, raw);
}

export const NOTE = `零知识的关键不是"不给权限"，
而是"不给密钥材料"——权限可以被绕过，密钥学不能。`;

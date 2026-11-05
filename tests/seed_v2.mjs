/**
 * 给 V2 灌入演示数据（开发/演示前用，不属于服务本身）
 *  - 生成一对临时密钥（口令 demo123456），把私钥包写到系统临时目录，仅用于本地演示
 *  - 用小孔账号把所有测试素材逐个本地加密后上传
 *
 * 运行：node tests/seed_v2.mjs
 */
import { readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const BASE = process.env.V2_BASE || "http://127.0.0.1:8002";
const PASSPHRASE = "demo123456";

const source = await readFile(path.join(ROOT, "v2_zero_knowledge/static/crypto-core.js"), "utf8");
const cc = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

async function login(username, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error(`登录失败 ${username}`);
  return (await res.json()).token;
}

const admin = await login("xiaozhang", "xiaozhang123");
const user = await login("xiaokong", "xiaokong123");

const pair = await cc.generateAdminKeyPair();
await fetch(`${BASE}/api/keys/public`, {
  method: "POST",
  headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
  body: JSON.stringify({ public_key_b64: pair.publicKeySpkiB64 }),
});
const wrapped = await cc.wrapPrivateKey(pair.privateKeyPkcs8B64, PASSPHRASE, { fingerprint: pair.fingerprint });
const keyPath = path.join(tmpdir(), "xiaozhang-demo.key.json");
await writeFile(keyPath, JSON.stringify(wrapped, null, 2), "utf8");

const dir = path.join(ROOT, "test_files");
const files = (await readdir(dir)).filter((name) => !name.endsWith(".json")).sort();

for (const name of files) {
  const buffer = await readFile(path.join(dir, name));
  const bytes = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  const result = await cc.encryptFile(bytes, pair.publicKeySpkiB64, name);
  const form = new FormData();
  form.append("ciphertext", new Blob([result.ciphertext]), "blob.enc");
  form.append("filename", name);
  form.append("category", "auto");
  form.append("orig_size", String(bytes.byteLength));
  form.append("nonce_b64", result.nonceB64);
  form.append("wrapped_key_b64", result.wrappedKeyB64);
  form.append("sha256_cipher", result.sha256Cipher);
  const res = await fetch(`${BASE}/api/files`, { method: "POST", headers: { Authorization: `Bearer ${user}` }, body: form });
  if (!res.ok) throw new Error(`上传失败 ${name}: ${await res.text()}`);
  const data = await res.json();
  console.log(`  ${name.padEnd(18)} → ${data.category}  ${data.cipher_size_text}`);
}

console.log(`\n密钥包（口令 ${PASSPHRASE}）：${keyPath}`);
console.log(`公钥指纹：${pair.fingerprint.slice(0, 32)}…`);

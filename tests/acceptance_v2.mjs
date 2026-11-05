/**
 * V2 全格式验收：test_files/ 里每个文件都走一遍
 *   本地加密 → 上传（小孔）→ 小张下载 → 本地解密 → SHA-256 比对
 * 再检查：小孔取密文 403、服务端解密 501、数据库无机密字段。
 *
 * 前置：V2 服务已启动（默认 http://127.0.0.1:8002）
 * 运行：node tests/acceptance_v2.mjs
 */
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const BASE = process.env.V2_BASE || "http://127.0.0.1:8002";
const PASSPHRASE = "acceptance-pass";

const source = await readFile(path.join(ROOT, "v2_zero_knowledge/static/crypto-core.js"), "utf8");
const cc = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const sizeText = (n) => (n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(2)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

async function login(username, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error(`登录 ${username} 失败`);
  return (await res.json()).token;
}

const auth = (t) => ({ Authorization: `Bearer ${t}` });
let failures = 0;
function check(name, ok, detail = "") {
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  → ${detail}` : ""}`);
}

const admin = await login("xiaozhang", "xiaozhang123");
const user = await login("xiaokong", "xiaokong123");

console.log(`\n=== V2 全格式验收 ===\n服务：${BASE}\n`);

// 1. 生成密钥对并发布公钥（模拟小张第一次使用）
const pair = await cc.generateAdminKeyPair();
await fetch(`${BASE}/api/keys/public`, {
  method: "POST",
  headers: { ...auth(admin), "Content-Type": "application/json" },
  body: JSON.stringify({ public_key_b64: pair.publicKeySpkiB64 }),
});
const wrapped = await cc.wrapPrivateKey(pair.privateKeyPkcs8B64, PASSPHRASE, { fingerprint: pair.fingerprint });
const privateKey = await cc.unwrapPrivateKey(wrapped, PASSPHRASE);
console.log("密钥对已生成（私钥仅在本进程内存，未上传）\n");

const dir = path.join(ROOT, "test_files");
const names = (await readdir(dir)).filter((n) => !n.endsWith(".json")).sort();
console.log(`${"文件".padEnd(20)}${"类型".padStart(6)}${"原始".padStart(11)}${"密文".padStart(11)}   还原`);
console.log("-".repeat(68));

let firstId = null;
for (const name of names) {
  const buffer = await readFile(path.join(dir, name));
  const bytes = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);

  const enc = await cc.encryptFile(bytes, pair.publicKeySpkiB64, name);
  const form = new FormData();
  form.append("ciphertext", new Blob([enc.ciphertext]), "blob.enc");
  form.append("filename", name);
  form.append("category", "auto");
  form.append("orig_size", String(bytes.byteLength));
  form.append("nonce_b64", enc.nonceB64);
  form.append("wrapped_key_b64", enc.wrappedKeyB64);
  form.append("sha256_cipher", enc.sha256Cipher);

  const up = await fetch(`${BASE}/api/files`, { method: "POST", headers: auth(user), body: form });
  const meta = await up.json();
  if (!up.ok) throw new Error(`上传失败 ${name}: ${JSON.stringify(meta)}`);
  if (!firstId) firstId = meta.id;

  const cipherRes = await fetch(`${BASE}/api/files/${meta.id}/ciphertext`, { headers: auth(admin) });
  const envRes = await fetch(`${BASE}/api/files/${meta.id}/envelope`, { headers: auth(admin) });
  if (!cipherRes.ok || !envRes.ok) {
    const detail = await envRes.text().catch(() => "");
    throw new Error(`下载失败 ${name}: cipher=${cipherRes.status} envelope=${envRes.status} ${detail.slice(0, 200)}`);
  }
  const cipher = new Uint8Array(await cipherRes.arrayBuffer());
  const envelope = await envRes.json();
  const plain = await cc.decryptFile(cipher, envelope, privateKey);

  const same = Buffer.from(plain).equals(buffer) && (await cc.sha256B64(plain)) === (await cc.sha256B64(bytes));
  console.log(`${name.padEnd(20)}${String(meta.category).padStart(6)}${sizeText(bytes.byteLength).padStart(11)}${sizeText(meta.cipher_size).padStart(11)}   ${same ? "一致" : "不一致"}`);
  if (!same) failures += 1;
}

console.log("\n权限与自证");
const deny = await fetch(`${BASE}/api/files/${firstId}/ciphertext`, { headers: auth(user) });
check("小孔取密文被拒（403）", deny.status === 403, `HTTP ${deny.status}`);

const proof = await fetch(`${BASE}/api/proof/server-decrypt/${firstId}`, { method: "POST", headers: auth(admin) });
const proofData = await proof.json();
check("服务端尝试解密返回 501", proof.status === 501 && proofData.reason === "NO_PRIVATE_KEY", proofData.reason);

const schemaRes = await fetch(`${BASE}/api/proof/schema`, { headers: auth(user) });
const schema = await schemaRes.json();
check("数据库无任何机密字段", Array.isArray(schema.secret_columns) && schema.secret_columns.length === 0,
  `secret_columns=${JSON.stringify(schema.secret_columns)}`);

let wrongPassRejected = false;
try {
  await cc.unwrapPrivateKey(wrapped, "wrong-pass");
} catch {
  wrongPassRejected = true;
}
check("错误口令无法解开密钥包", wrongPassRejected);

console.log(failures === 0
  ? `\n${names.length} 种格式 + 权限 + 自证，全部通过。\n`
  : `\n有 ${failures} 项未通过。\n`);
process.exit(failures === 0 ? 0 : 1);

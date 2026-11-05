/**
 * V2 端到端测试（Node ≥ 18，内置 Web Crypto / fetch）
 *
 * 直接加载前端真实的 static/crypto-core.js，验证：
 *   1. 公钥发布 / 小孔加密上传 / 小张本地解密 的完整链路
 *   2. 小孔下载密文被拒（403）
 *   3. 服务端尝试解密必定失败（501）
 *   4. 数据库表里没有任何机密字段
 *   5. 错误口令打不开私钥包；换私钥解不开别人的文件
 *
 * 运行：node tests/e2e_v2.mjs
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const BASE = process.env.V2_BASE || "http://127.0.0.1:8002";

// 以 ESM data URL 方式加载前端密码学模块，确保测的是同一份代码
const source = await readFile(path.join(ROOT, "v2_zero_knowledge/static/crypto-core.js"), "utf8");
const cryptoCore = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const results = [];
function step(name, fn) {
  return (async () => {
    const started = Date.now();
    try {
      const detail = await fn();
      results.push({ name, ok: true, detail, ms: Date.now() - started });
    } catch (err) {
      results.push({ name, ok: false, detail: err.message, ms: Date.now() - started });
      throw err;
    }
  })();
}

async function login(username, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  assert.equal(res.status, 200, `登录 ${username} 失败`);
  return (await res.json()).token;
}

const auth = (token) => ({ Authorization: `Bearer ${token}` });

async function main() {
  console.log(`\n=== V2 端到端测试 (${BASE}) ===\n`);

  const adminToken = await login("xiaozhang", "xiaozhang123");
  const userToken = await login("xiaokong", "xiaokong123");
  let pair;
  let wrapped;
  let uploaded;

  await step("小张在本地生成 RSA 密钥对，并只把公钥发布到服务器", async () => {
    pair = await cryptoCore.generateAdminKeyPair();
    const res = await fetch(`${BASE}/api/keys/public`, {
      method: "POST",
      headers: { ...auth(adminToken), "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_b64: pair.publicKeySpkiB64 }),
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.fingerprint, pair.fingerprint);
    return `公钥指纹 ${pair.fingerprint.slice(0, 16)}…`;
  });

  await step("私钥被口令加密成密钥包（服务端收不到私钥）", async () => {
    wrapped = await cryptoCore.wrapPrivateKey(pair.privateKeyPkcs8B64, "zhang-2024", { fingerprint: pair.fingerprint });
    assert.equal(wrapped.type, "v2-private-key");
    assert.ok(!JSON.stringify(wrapped).includes("PRIVATE"), "密钥包里不应出现明文私钥结构");
    assert.ok(JSON.stringify(wrapped).length < 6000, "密钥包体积应很小");
    return `密钥包 ${(JSON.stringify(wrapped).length / 1024).toFixed(1)} KB，已用 PBKDF2(${wrapped.kdf.iterations}) 加密`;
  });

  const sample = await readFile(path.join(ROOT, "test_files/demo_code.py"));
  const sampleBuf = sample.buffer.slice(sample.byteOffset, sample.byteOffset + sample.byteLength);

  await step("小孔用公钥加密文件并上传（服务端只收密文）", async () => {
    const result = await cryptoCore.encryptFile(sampleBuf, pair.publicKeySpkiB64, "demo_code.py");
    const form = new FormData();
    form.append("ciphertext", new Blob([result.ciphertext]), "blob.enc");
    form.append("filename", "demo_code.py");
    form.append("category", "auto");
    form.append("orig_size", String(sampleBuf.byteLength));
    form.append("nonce_b64", result.nonceB64);
    form.append("wrapped_key_b64", result.wrappedKeyB64);
    form.append("sha256_cipher", result.sha256Cipher);
    const res = await fetch(`${BASE}/api/files`, { method: "POST", headers: auth(userToken), body: form });
    const data = await res.json();
    assert.equal(res.status, 200, JSON.stringify(data));
    uploaded = { id: data.id, cipherSize: data.cipher_size, sha: result.sha256Cipher };
    assert.equal(data.server_can_decrypt, false);
    assert.ok(data.cipher_size > sampleBuf.byteLength);
    return `文件 ID ${uploaded.id} · 原文 ${sampleBuf.byteLength}B → 密文 ${data.cipher_size}B`;
  });

  await step("小孔尝试下载密文被拒绝（403）", async () => {
    const res = await fetch(`${BASE}/api/files/${uploaded.id}/ciphertext`, { headers: auth(userToken) });
    assert.equal(res.status, 403);
    return "403 " + (await res.json()).detail;
  });

  await step("小张下载密文与封装信息，并在本地解出原文", async () => {
    const [cipherRes, envelopeRes] = await Promise.all([
      fetch(`${BASE}/api/files/${uploaded.id}/ciphertext`, { headers: auth(adminToken) }),
      fetch(`${BASE}/api/files/${uploaded.id}/envelope`, { headers: auth(adminToken) }),
    ]);
    assert.equal(cipherRes.status, 200);
    assert.equal(envelopeRes.status, 200);
    const cipher = new Uint8Array(await cipherRes.arrayBuffer());
    const envelope = await envelopeRes.json();
    const privateKey = await cryptoCore.unwrapPrivateKey(wrapped, "zhang-2024");
    const plain = await cryptoCore.decryptFile(cipher, envelope, privateKey);
    assert.equal(Buffer.from(plain).toString("utf8"), sample.toString("utf8"), "解密结果与原文件不一致");
    assert.equal(await cryptoCore.sha256B64(plain), await cryptoCore.sha256B64(sampleBuf));
    return `还原 ${plain.length}B，SHA-256 与原文件一致`;
  });

  await step("服务端尝试解密 → 501 NO_PRIVATE_KEY", async () => {
    const res = await fetch(`${BASE}/api/proof/server-decrypt/${uploaded.id}`, {
      method: "POST",
      headers: auth(adminToken),
    });
    const data = await res.json();
    assert.equal(res.status, 501);
    assert.equal(data.reason, "NO_PRIVATE_KEY");
    return data.message;
  });

  await step("数据库表结构里没有任何机密字段", async () => {
    const res = await fetch(`${BASE}/api/proof/schema`, { headers: auth(userToken) });
    const data = await res.json();
    assert.deepEqual(data.secret_columns, []);
    const keyCol = data.columns.find((c) => c.name === "wrapped_key_b64");
    assert.ok(keyCol, "应存在 wrapped_key_b64 字段");
    return `字段数 ${data.columns.length}，secret_columns=[]，DB ${data.db_size}`;
  });

  await step("错误口令打不开私钥包", async () => {
    await assert.rejects(() => cryptoCore.unwrapPrivateKey(wrapped, "wrong-pass"), /口令错误/);
    return "口令错误被正确拒绝";
  });

  await step("别人的私钥解不开这个文件", async () => {
    const other = await cryptoCore.generateAdminKeyPair();
    const otherWrapped = await cryptoCore.wrapPrivateKey(other.privateKeyPkcs8B64, "another-pass");
    const otherKey = await cryptoCore.unwrapPrivateKey(otherWrapped, "another-pass");
    const [cipherRes, envelopeRes] = await Promise.all([
      fetch(`${BASE}/api/files/${uploaded.id}/ciphertext`, { headers: auth(adminToken) }),
      fetch(`${BASE}/api/files/${uploaded.id}/envelope`, { headers: auth(adminToken) }),
    ]);
    const cipher = new Uint8Array(await cipherRes.arrayBuffer());
    const envelope = await envelopeRes.json();
    await assert.rejects(() => cryptoCore.decryptFile(cipher, envelope, otherKey), /私钥与这个文件不匹配/);
    return "RSA 私钥不匹配，解封失败";
  });

  await step("篡改密文后解密失败（GCM 认证）", async () => {
    const [cipherRes, envelopeRes] = await Promise.all([
      fetch(`${BASE}/api/files/${uploaded.id}/ciphertext`, { headers: auth(adminToken) }),
      fetch(`${BASE}/api/files/${uploaded.id}/envelope`, { headers: auth(adminToken) }),
    ]);
    const cipher = new Uint8Array(await cipherRes.arrayBuffer());
    cipher[10] ^= 0xff;
    const envelope = await envelopeRes.json();
    const privateKey = await cryptoCore.unwrapPrivateKey(wrapped, "zhang-2024");
    await assert.rejects(() => cryptoCore.decryptFile(cipher, envelope, privateKey), /解密失败/);
    return "被改动的密文无法通过认证";
  });

  console.log("\n结果：");
  for (const item of results) {
    console.log(`  ${item.ok ? "PASS" : "FAIL"}  ${item.name}  (${item.ms}ms)`);
    if (item.detail) console.log(`        → ${item.detail}`);
  }
  console.log(`\n全部 ${results.length} 项通过\n`);
}

main().catch((err) => {
  console.error("\n测试失败：", err.message);
  for (const item of results) console.log(`  ${item.ok ? "PASS" : "FAIL"}  ${item.name}`);
  process.exit(1);
});

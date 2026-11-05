/* V2 前端：所有加解密都在浏览器本地完成，服务端只收密文 */
import {
  generateAdminKeyPair,
  wrapPrivateKey,
  unwrapPrivateKey,
  encryptFile,
  decryptFile,
  sha256B64,
  describeBytes,
} from "./crypto-core.js";

const TOKEN_KEY = "v2_demo_token";
const state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  user: null,
  files: [],
  publicKey: null,
  privateKey: null, // 仅内存，刷新即失效
  privateKeyFingerprint: "",
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

function toast(message, isError = false) {
  const box = $("#toast");
  box.textContent = message;
  box.className = "toast show" + (isError ? " err" : "");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => (box.className = "toast"), 2800);
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, Object.assign({}, options, { headers }));
  if (res.status === 401 && !path.endsWith("/api/login")) {
    signOut();
    throw new Error("登录已过期，请重新登录");
  }
  if (!res.ok) {
    let detail = `请求失败（${res.status}）`;
    try {
      const data = await res.json();
      if (data.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch (_) {}
    throw new Error(detail);
  }
  return res;
}

/* ---------------- 登录 ---------------- */
document.querySelectorAll(".role-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".role-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    $("#login-user").value = btn.dataset.user;
    $("#login-pass").value = btn.dataset.pass;
  });
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const res = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#login-user").value.trim(),
        password: $("#login-pass").value,
      }),
    });
    const data = await res.json();
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem(TOKEN_KEY, data.token);
    await enterApp();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (_) {}
  signOut();
});

function signOut() {
  state.token = "";
  state.user = null;
  state.files = [];
  state.privateKey = null;
  state.publicKey = null;
  localStorage.removeItem(TOKEN_KEY);
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
}

async function enterApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#user-name").textContent = state.user.display_name;
  $("#user-title").textContent = state.user.title;
  const avatar = $("#user-avatar");
  avatar.textContent = state.user.display_name.slice(-1);
  avatar.className = "role-avatar " + (state.user.role === "admin" ? "avatar-z" : "avatar-k");

  const isAdmin = state.user.role === "admin";
  $("#owner-panel").classList.toggle("hidden", !isAdmin);
  $("#admin-zone").classList.toggle("hidden", !isAdmin);
  $("#offline-zone").classList.toggle("hidden", !isAdmin);
  $("#audit-zone").classList.toggle("hidden", !isAdmin);

  await loadPublicKey();
  await loadFiles();
  if (isAdmin) await loadAudit();
}

/* ---------------- 公钥 ---------------- */
async function loadPublicKey() {
  try {
    const res = await api("/api/keys/public");
    const data = await res.json();
    state.publicKey = data.public_key_b64 ? data : null;

    const tag = $("#pubkey-state");
    if (state.publicKey) {
      tag.textContent = "公钥已就绪";
      tag.className = "card-tag ok";
      $("#fingerprint").textContent = data.fingerprint.slice(0, 32) + "…";
      $("#key-owner").textContent = data.owner === "xiaozhang" ? "小张" : data.owner;
      $("#key-missing").classList.add("hidden");
    } else {
      tag.textContent = "尚未生成公钥";
      tag.className = "card-tag danger";
      $("#fingerprint").textContent = "—";
      $("#key-owner").textContent = "—";
      $("#key-missing").classList.toggle("hidden", state.user.role === "admin");
    }
  } catch (err) {
    toast(err.message, true);
  }
}

$("#gen-keypair-btn").addEventListener("click", () => createKeyPair(false));
$("#rotate-keypair-btn").addEventListener("click", () => {
  if (!confirm("重新生成后，旧文件将无法再解密（旧私钥对不上新公钥）。确定继续？")) return;
  createKeyPair(true);
});

async function createKeyPair(force) {
  const passphrase = prompt("给私钥包设置一个口令（至少 6 位）。这个口令不会上传，请记住它：");
  if (passphrase === null) return;
  if (passphrase.length < 6) {
    toast("口令至少 6 位", true);
    return;
  }
  const again = prompt("再输入一次口令确认：");
  if (again !== passphrase) {
    toast("两次输入的口令不一致", true);
    return;
  }

  const btn = $("#gen-keypair-btn");
  btn.disabled = true;
  btn.textContent = "生成中…";
  try {
    const pair = await generateAdminKeyPair();
    const wrapped = await wrapPrivateKey(pair.privateKeyPkcs8B64, passphrase, {
      owner: "小张",
      fingerprint: pair.fingerprint,
    });
    const day = new Date().toISOString().slice(0, 10);
    downloadText(JSON.stringify(wrapped, null, 2), `小张-私钥包-${day}.key.json`);

    await api("/api/keys/public", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_b64: pair.publicKeySpkiB64 }),
    });

    state.privateKey = await unwrapPrivateKey(wrapped, passphrase);
    state.privateKeyFingerprint = pair.fingerprint;
    setKeyState(true, pair.fingerprint);
    await loadPublicKey();
    toast("密钥对已生成：私钥包已下载到本机，公钥已发布");
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成密钥对并下载密钥包";
  }
}

function setKeyState(unlocked, fingerprint) {
  const tag = $("#key-state");
  if (unlocked) {
    tag.textContent = "私钥已解锁";
    tag.className = "card-tag ok";
    $("#unlock-msg").textContent = `私钥仅在页面内存中 · 指纹 ${String(fingerprint).slice(0, 16)}…`;
  } else {
    tag.textContent = "未解锁";
    tag.className = "card-tag";
    $("#unlock-msg").textContent = "";
  }
}

/* ---------------- 解锁私钥 ---------------- */
$("#unlock-btn").addEventListener("click", async () => {
  const file = $("#privkey-file").files[0];
  const passphrase = $("#privkey-pass").value;
  if (!file) return toast("请选择密钥包文件", true);
  if (!passphrase) return toast("请输入口令", true);
  try {
    const wrapped = JSON.parse(await file.text());
    const key = await unwrapPrivateKey(wrapped, passphrase);
    state.privateKey = key;
    state.privateKeyFingerprint = wrapped.public_key_fingerprint || "";
    setKeyState(true, wrapped.public_key_fingerprint || "");
    $("#privkey-pass").value = "";

    if (wrapped.public_key_fingerprint && state.publicKey &&
        wrapped.public_key_fingerprint !== state.publicKey.fingerprint) {
      toast("这个私钥包与服务器上的公钥不匹配，可能无法解密新文件", true);
    } else {
      toast("私钥已在本地解锁");
    }
  } catch (err) {
    toast(err.message, true);
  }
});

/* ---------------- 上传 ---------------- */
const dropzone = $("#dropzone");
const fileInput = $("#file-input");

dropzone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  uploadFiles(Array.from(fileInput.files));
  fileInput.value = "";
});
["dragenter", "dragover"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("drag"); })
);
["dragleave", "drop"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); })
);
dropzone.addEventListener("drop", (e) => {
  const files = Array.from(e.dataTransfer.files || []);
  if (files.length) uploadFiles(files);
});

async function uploadFiles(files) {
  if (!state.publicKey) {
    toast("还没有公钥：请让小张先生成密钥对", true);
    return;
  }
  const category = $("#category-select").value;

  for (const file of files) {
    const item = el("div", "queue-item");
    item.appendChild(el("span", "name", file.name));
    item.appendChild(el("span", "state", describeBytes(file.size)));
    const status = el("span", "state", "读取…");
    item.appendChild(status);
    $("#upload-queue").appendChild(item);

    try {
      status.textContent = "本地加密中…";
      const buffer = await file.arrayBuffer();
      const started = performance.now();
      const result = await encryptFile(buffer, state.publicKey.public_key_b64, file.name, (msg) => {
        status.textContent = msg;
      });

      const form = new FormData();
      form.append("ciphertext", new Blob([result.ciphertext], { type: "application/octet-stream" }), "blob.enc");
      form.append("filename", file.name);
      form.append("category", category);
      form.append("orig_size", String(file.size));
      form.append("nonce_b64", result.nonceB64);
      form.append("wrapped_key_b64", result.wrappedKeyB64);
      form.append("sha256_cipher", result.sha256Cipher);
      form.append("alg", "AES-256-GCM + RSA-OAEP-256");

      status.textContent = "上传密文中…";
      const res = await api("/api/files", { method: "POST", body: form });
      const data = await res.json();
      const ms = Math.round(performance.now() - started);
      status.textContent = `已加密 · ${data.category}`;
      status.className = "state ok";
      $("#upload-msg").textContent =
        `密文 ${data.cipher_size_text}（原文 ${describeBytes(file.size)}），耗时 ${ms} ms。` +
        `服务端从头到尾没有拿到明文，也没有拿到数据密钥。`;
    } catch (err) {
      status.textContent = "失败：" + err.message;
      status.className = "state err";
      toast(err.message, true);
    }
  }
  await loadFiles();
  if (state.user.role === "admin") await loadAudit();
}

/* ---------------- 列表 ---------------- */
$("#refresh-btn").addEventListener("click", async () => {
  await loadFiles();
  if (state.user.role === "admin") await loadAudit();
  toast("已刷新");
});

async function loadFiles() {
  try {
    const res = await api("/api/files");
    const data = await res.json();
    state.files = data.files;
    renderFiles();
  } catch (err) {
    toast(err.message, true);
  }
}

function renderFiles() {
  const tbody = $("#file-rows");
  tbody.innerHTML = "";
  $("#file-count").textContent = `${state.files.length} 个文件`;
  $("#empty-tip").classList.toggle("hidden", state.files.length > 0);
  const isAdmin = state.user && state.user.role === "admin";

  for (const file of state.files) {
    const tr = el("tr");

    const nameCell = el("td");
    const nameBox = el("div", "fname");
    nameBox.appendChild(el("span", "dot"));
    nameBox.appendChild(el("span", "txt", file.filename));
    nameCell.appendChild(nameBox);
    tr.appendChild(nameCell);

    const catCell = el("td");
    catCell.appendChild(el("span", "badge", file.category));
    tr.appendChild(catCell);

    tr.appendChild(el("td", "", file.orig_size_text));
    tr.appendChild(el("td", "", file.cipher_size_text));

    const wrapCell = el("td");
    wrapCell.appendChild(el("span", "mono", file.wrapped_key_preview));
    tr.appendChild(wrapCell);

    tr.appendChild(el("td", "", file.owner === "xiaozhang" ? "小张" : "小孔"));
    tr.appendChild(el("td", "", file.created_at));

    const actionCell = el("td");
    const actions = el("div", "actions");

    if (isAdmin) {
      const decBtn = el("button", "btn btn-sm btn-primary", "本地解密");
      decBtn.addEventListener("click", () => decryptFromServer(file, decBtn));
      actions.appendChild(decBtn);

      const envBtn = el("button", "btn btn-sm", "封装信息");
      envBtn.addEventListener("click", () => downloadEnvelope(file));
      actions.appendChild(envBtn);

      const cipherBtn = el("button", "btn btn-sm", "下载密文");
      cipherBtn.addEventListener("click", () => downloadCipher(file));
      actions.appendChild(cipherBtn);

      const delBtn = el("button", "btn btn-sm btn-danger", "删除");
      delBtn.addEventListener("click", () => deleteFile(file));
      actions.appendChild(delBtn);
    } else {
      const locked = el("button", "btn btn-sm btn-lock", "解密（无权限）");
      locked.disabled = true;
      locked.title = "小孔没有私钥，服务端也不会给他密文";
      actions.appendChild(locked);
    }

    actionCell.appendChild(actions);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  }
}

/* ---------------- 下载与解密 ---------------- */
function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function downloadText(text, filename, type = "application/json") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

async function fetchCipher(file) {
  const res = await api(`/api/files/${file.id}/ciphertext`);
  return new Uint8Array(await res.arrayBuffer());
}

async function fetchEnvelope(file) {
  const res = await api(`/api/files/${file.id}/envelope`);
  return res.json();
}

async function downloadCipher(file) {
  try {
    const bytes = await fetchCipher(file);
    downloadBytes(bytes, file.filename + ".enc");
    toast("密文已下载：没有私钥，它只是一堆字节");
  } catch (err) {
    toast(err.message, true);
  }
}

async function downloadEnvelope(file) {
  try {
    const data = await fetchEnvelope(file);
    const check = await sha256B64(new TextEncoder().encode(data.wrapped_key_b64));
    downloadText(JSON.stringify({ ...data, envelope_sha256: check }, null, 2), file.filename + ".envelope.json");
    toast("封装信息已下载（不含私钥，无法单独解密）");
  } catch (err) {
    toast(err.message, true);
  }
}

async function decryptFromServer(file, button) {
  if (!state.privateKey) {
    toast("请先在下方「我的私钥」里解锁密钥包", true);
    document.getElementById("privkey-file").focus();
    return;
  }
  button.disabled = true;
  button.textContent = "解密中…";
  try {
    const [cipher, envelope] = await Promise.all([fetchCipher(file), fetchEnvelope(file)]);
    const plain = await decryptFile(cipher, envelope, state.privateKey);
    downloadBytes(plain, envelope.filename);
    toast(`本地解密完成：${describeBytes(plain.length)}`);
  } catch (err) {
    toast(err.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "本地解密";
    await loadFiles();
    await loadAudit();
  }
}

async function deleteFile(file) {
  if (!confirm(`确定删除「${file.filename}」？`)) return;
  try {
    await api(`/api/files/${file.id}`, { method: "DELETE" });
    toast("已删除");
    await loadFiles();
    await loadAudit();
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------------- 服务器自证 ---------------- */
$("#proof-btn").addEventListener("click", async () => {
  const out = $("#proof-output");
  if (!state.files.length) {
    out.textContent = "还没有文件，先上传一个再验证。";
    return;
  }
  const target = state.files[0];
  out.textContent = `正在让服务端尝试解密「${target.filename}」…`;
  const res = await fetch(`/api/proof/server-decrypt/${target.id}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${state.token}` },
  });
  const data = await res.json();
  out.textContent =
    `HTTP ${res.status} · 服务端解密结果\n\n` +
    JSON.stringify(data, null, 2) +
    `\n\n也就是说：不是"没给权限"，而是"根本没有解密的材料"。`;
  await loadAudit();
});

$("#schema-btn").addEventListener("click", async () => {
  const out = $("#proof-output");
  try {
    const res = await api("/api/proof/schema");
    const data = await res.json();
    const lines = data.columns.map(
      (c) => `  ${c.name.padEnd(18)} ${c.type.padEnd(9)} ${c.holds_secret ? "← 含机密" : ""}`
    );
    out.textContent =
      `数据库表 files 的字段：\n${lines.join("\n")}\n\n` +
      `含机密信息的字段：${data.secret_columns.length ? data.secret_columns.join(", ") : "无"}\n` +
      `服务端持有的密钥材料：${data.stored_key_material}\n` +
      `公钥指纹：${data.public_key_fingerprint}\n` +
      `数据库文件：${data.db_file}（${data.db_size}，${data.file_count} 条记录）\n\n` +
      data.conclusion;
  } catch (err) {
    out.textContent = "读取失败：" + err.message;
  }
});

/* ---------------- 离线解密 ---------------- */
$("#offline-btn").addEventListener("click", async () => {
  const cipherFile = $("#off-cipher").files[0];
  const envFile = $("#off-envelope").files[0];
  const keyFile = $("#off-privkey").files[0];
  const passphrase = $("#off-pass").value;
  const msg = $("#offline-msg");
  if (!cipherFile || !envFile || !keyFile) {
    msg.textContent = "请选择密文、封装信息、密钥包三个文件";
    return;
  }
  try {
    msg.textContent = "本地解密中…";
    const envelope = JSON.parse(await envFile.text());
    const wrapped = JSON.parse(await keyFile.text());
    const privateKey = await unwrapPrivateKey(wrapped, passphrase);
    const cipher = new Uint8Array(await cipherFile.arrayBuffer());

    const expected = envelope.sha256_cipher;
    const actual = await sha256B64(cipher);
    if (expected && expected !== actual) throw new Error("密文完整性校验失败（文件被改动）");

    const plain = await decryptFile(cipher, envelope, privateKey);
    downloadBytes(plain, envelope.filename);
    msg.textContent = `解密成功：${envelope.filename}（${describeBytes(plain.length)}）`;
    toast("离线解密完成");
  } catch (err) {
    msg.textContent = "失败：" + err.message;
    toast(err.message, true);
  }
});

/* ---------------- 审计 ---------------- */
async function loadAudit() {
  try {
    const res = await api("/api/audit?limit=30");
    const data = await res.json();
    const box = $("#audit-list");
    box.innerHTML = "";
    for (const log of data.logs) {
      const row = el("div", "audit-row" + (log.result === "deny" ? " deny" : ""));
      row.appendChild(el("span", "t", log.ts));
      row.appendChild(el("span", "u", log.username));
      row.appendChild(el("span", "a", `${log.action} · ${log.detail}`));
      box.appendChild(row);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------------- 启动 ---------------- */
(async function boot() {
  if (!state.token) return;
  try {
    const res = await api("/api/me");
    const data = await res.json();
    state.user = data.user;
    await enterApp();
  } catch (_) {
    signOut();
  }
})();

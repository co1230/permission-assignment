/* V1 对照版前端逻辑：登录、上传、列表、服务端解密、密钥库、审计 */
const TOKEN_KEY = "v1_demo_token";
const state = { token: localStorage.getItem(TOKEN_KEY) || "", user: null, files: [] };

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
  toast._timer = setTimeout(() => (box.className = "toast"), 2600);
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
    enterApp();
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
  $("#admin-zone").classList.toggle("hidden", state.user.role !== "admin");
  await loadFiles();
  if (state.user.role === "admin") {
    await Promise.all([loadVault(), loadAudit()]);
  }
}

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
  const category = $("#category-select").value;
  for (const file of files) {
    const item = el("div", "queue-item");
    item.appendChild(el("span", "name", file.name));
    const size = el("span", "state", formatSize(file.size));
    item.appendChild(size);
    const stateText = el("span", "state", "加密中…");
    item.appendChild(stateText);
    $("#upload-queue").appendChild(item);

    const form = new FormData();
    form.append("file", file, file.name);
    form.append("category", category);

    try {
      const res = await api("/api/files", { method: "POST", body: form });
      const data = await res.json();
      stateText.textContent = `已加密 · ${data.category}`;
      stateText.className = "state ok";
      $("#upload-msg").textContent =
        `服务端生成 AES-256 密钥并已入库；密文 ${data.cipher_size_text}。小孔无法解密，小张可解密。`;
    } catch (err) {
      stateText.textContent = "失败：" + err.message;
      stateText.className = "state err";
      toast(err.message, true);
    }
  }
  await loadFiles();
  if (state.user.role === "admin") await Promise.all([loadVault(), loadAudit()]);
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  const units = ["KB", "MB", "GB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = next;
  }
  return value.toFixed(1) + " " + unit;
}

/* ---------------- 列表 ---------------- */
$("#refresh-btn").addEventListener("click", async () => {
  await loadFiles();
  if (state.user && state.user.role === "admin") await Promise.all([loadVault(), loadAudit()]);
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
    tr.appendChild(el("td", "", file.owner === "xiaozhang" ? "小张" : "小孔"));
    tr.appendChild(el("td", "", file.created_at));

    const actionCell = el("td");
    const actions = el("div", "actions");

    const cipherBtn = el("button", "btn btn-sm", "下载密文");
    cipherBtn.addEventListener("click", () => downloadCipher(file));
    actions.appendChild(cipherBtn);

    if (state.user.role === "admin") {
      const decBtn = el("button", "btn btn-sm btn-primary", "解密下载");
      decBtn.addEventListener("click", () => decryptFile(file, decBtn));
      actions.appendChild(decBtn);

      const delBtn = el("button", "btn btn-sm btn-danger", "删除");
      delBtn.addEventListener("click", () => deleteFile(file));
      actions.appendChild(delBtn);
    } else {
      const locked = el("button", "btn btn-sm btn-lock", "解密（无权限）");
      locked.disabled = true;
      locked.title = "小孔没有解密权限，只有小张可以解密";
      actions.appendChild(locked);
    }

    actionCell.appendChild(actions);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  }
}

async function downloadBlob(res, fallbackName) {
  const blob = await res.blob();
  let filename = fallbackName;
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
  if (match) filename = decodeURIComponent(match[1]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

async function downloadCipher(file) {
  try {
    const res = await api(`/api/files/${file.id}/ciphertext`);
    await downloadBlob(res, file.filename + ".enc");
    toast("密文已下载（没有密钥无法还原）");
  } catch (err) {
    toast(err.message, true);
  }
}

async function decryptFile(file, button) {
  button.disabled = true;
  button.textContent = "解密中…";
  try {
    const res = await api(`/api/files/${file.id}/decrypt`);
    await downloadBlob(res, file.filename);
    toast("服务端用库内密钥解密完成");
  } catch (err) {
    toast(err.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "解密下载";
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
    await Promise.all([loadVault(), loadAudit()]);
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------------- 管理端 ---------------- */
async function loadVault() {
  try {
    const res = await api("/api/admin/vault");
    const data = await res.json();
    const box = $("#vault-list");
    box.innerHTML = "";
    if (!data.keys.length) {
      box.appendChild(el("p", "tiny", "库里还没有密文，上传文件后这里会出现对应的密钥。"));
      return;
    }
    for (const key of data.keys) {
      const item = el("div", "vault-item");
      item.appendChild(el("div", "vname", key.filename));
      item.appendChild(el("div", "vkey", "key = " + key.key_b64));
      box.appendChild(item);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

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

/* ========================================================
   Vulnerability Agent – Admin Panel JavaScript
   ======================================================== */

// ── 状態管理 ────────────────────────────────────────
const state = {
  tab: "sbom",
  sbomPage: 1,
  sbomPerPage: 50,
  sbomQuery: "",
  sbomTotal: 0,
  ownerQuery: "",
  ownerTotal: 0,
  editTarget: null,  // 編集中のエントリ
};

let sbomDebounceTimer = null;
let ownerDebounceTimer = null;

// ── DOM参照 ─────────────────────────────────────────
const userBadge       = document.getElementById("admin-user-badge");
const sbomPane        = document.getElementById("pane-sbom");
const ownerPane       = document.getElementById("pane-owners");
const sbomTableBody   = document.getElementById("sbom-tbody");
const ownerTableBody  = document.getElementById("owner-tbody");
const sbomCountEl     = document.getElementById("sbom-count");
const ownerCountEl    = document.getElementById("owner-count");
const sbomSearchInput = document.getElementById("sbom-search");
const ownerSearchInput= document.getElementById("owner-search");
const sbomPageInfo    = document.getElementById("sbom-page-info");
const sbomPrevBtn     = document.getElementById("sbom-prev");
const sbomNextBtn     = document.getElementById("sbom-next");
const toastContainer  = document.getElementById("toast-container");
const modal           = document.getElementById("modal-overlay");
const modalTitle      = document.getElementById("modal-title");
const modalBody       = document.getElementById("modal-body");
const modalSaveBtn    = document.getElementById("modal-save");

// ── トースト通知 ─────────────────────────────────────
function showToast(message, type = "info") {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = message;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── API ヘルパー ──────────────────────────────────────
async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.status === "error") {
    throw new Error(data.detail || data.message || `HTTP ${res.status}`);
  }
  return data;
}

// ── ユーザー情報 ──────────────────────────────────────
async function loadUser() {
  try {
    const data = await apiFetch("/auth/me");
    const name = data.user?.name || data.user?.email || data.user?.sub || "anonymous";
    userBadge.querySelector(".user-name").textContent = name;
  } catch {
    // 認証情報取得失敗は無視
  }
}

// ── タブ切り替え ──────────────────────────────────────
function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll(".admin-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });
  sbomPane.classList.toggle("active", tab === "sbom");
  ownerPane.classList.toggle("active", tab === "owners");
  if (tab === "sbom") loadSbom();
  else loadOwners();
}

// ════════════════════════════════════════════════════
// SBOM セクション
// ════════════════════════════════════════════════════

async function loadSbom() {
  sbomTableBody.innerHTML = `
    <tr><td colspan="10" class="table-loading">
      <div class="spinner"></div> 読み込み中...
    </td></tr>`;
  const params = new URLSearchParams({
    q: state.sbomQuery,
    page: state.sbomPage,
    per_page: state.sbomPerPage,
  });
  try {
    const data = await apiFetch(`/api/admin/sbom?${params}`);
    state.sbomTotal = data.total || 0;
    renderSbomTable(data.entries || []);
    updateSbomPagination();
    sbomCountEl.textContent = `全 ${state.sbomTotal} 件`;
  } catch (e) {
    sbomTableBody.innerHTML = `<tr><td colspan="10" class="table-empty">読み込み失敗: ${e.message}</td></tr>`;
    showToast(`SBOM読み込み失敗: ${e.message}`, "error");
  }
}

function renderSbomTable(entries) {
  if (!entries.length) {
    sbomTableBody.innerHTML = `<tr><td colspan="10" class="table-empty">データがありません</td></tr>`;
    updateBulkDeleteBtn();
    return;
  }
  sbomTableBody.innerHTML = entries.map((e, idx) => `
    <tr>
      <td class="cell-check"><input type="checkbox" class="sbom-row-check" data-idx="${idx}"></td>
      <td><span class="badge ${typeBadgeClass(e.type)}">${esc(e.type)}</span></td>
      <td>${esc(e.name)}</td>
      <td>${esc(e.version)}</td>
      <td>${esc(e.release)}</td>
      <td class="cell-purl" title="${esc(e.purl)}">${esc(e.purl)}</td>
      <td>${esc(e.os_name)}</td>
      <td>${esc(e.os_version)}</td>
      <td>${esc(e.arch)}</td>
      <td>
        <div class="action-btns">
          <button class="btn-action" title="編集" onclick="openSbomEdit(${idx})">
            <i data-lucide="pencil"></i>
          </button>
          <button class="btn-action btn-delete" title="削除" onclick="confirmDeleteSbom(${idx})">
            <i data-lucide="trash-2"></i>
          </button>
        </div>
      </td>
    </tr>`).join("");
  // テーブル描画後にLucideアイコンを再初期化
  lucide.createIcons();
  // エントリをDOMにキャッシュ（インデックス→データ参照用）
  window._sbomEntries = entries;
  // チェックボックスイベント
  document.querySelectorAll(".sbom-row-check").forEach((cb) => {
    cb.addEventListener("change", updateBulkDeleteBtn);
  });
  const selectAll = document.getElementById("sbom-select-all");
  if (selectAll) selectAll.checked = false;
  updateBulkDeleteBtn();
}

function typeBadgeClass(type) {
  const map = {
    rpm: "badge-blue", deb: "badge-green", npm: "badge-teal",
    maven: "badge-amber", pypi: "badge-purple",
  };
  return map[type?.toLowerCase()] || "badge-gray";
}

function updateSbomPagination() {
  const totalPages = Math.max(1, Math.ceil(state.sbomTotal / state.sbomPerPage));
  sbomPageInfo.textContent = `${state.sbomPage} / ${totalPages} ページ`;
  sbomPrevBtn.disabled = state.sbomPage <= 1;
  sbomNextBtn.disabled = state.sbomPage >= totalPages;
}

function openSbomAdd() {
  state.editTarget = null;
  modalTitle.textContent = "SBOMエントリを追加";
  modalBody.innerHTML = sbomFormHtml({});
  modalSaveBtn.onclick = saveSbom;
  openModal();
}

function openSbomEdit(idx) {
  const entry = window._sbomEntries?.[idx];
  if (!entry) return;
  state.editTarget = entry;
  modalTitle.textContent = "SBOMエントリを編集";
  modalBody.innerHTML = sbomFormHtml(entry);
  modalSaveBtn.onclick = saveSbom;
  openModal();
}

async function saveSbom() {
  const body = readSbomForm();
  try {
    if (state.editTarget) {
      // 旧エントリ特定用フィールド（PURLなしの場合のフォールバック）
      const updateBody = {
        old_purl: state.editTarget.purl || "",
        _old_name: state.editTarget.name || "",
        _old_type: state.editTarget.type || "",
        _old_version: state.editTarget.version || "",
        _old_release: state.editTarget.release || "",
        ...body,
      };
      await apiFetch("/api/admin/sbom", {
        method: "PUT",
        body: JSON.stringify(updateBody),
      });
      showToast("SBOMエントリを更新しました", "success");
    } else {
      await apiFetch("/api/admin/sbom", {
        method: "POST",
        body: JSON.stringify(body),
      });
      showToast("SBOMエントリを追加しました", "success");
    }
    closeModal();
    loadSbom();
  } catch (e) {
    showToast(`保存失敗: ${e.message}`, "error");
  }
}

async function confirmDeleteSbom(idx) {
  const entry = window._sbomEntries?.[idx];
  if (!entry) return;
  const label = entry.purl || `${entry.name} ${entry.version}`.trim() || "(不明)";
  if (!confirm(`以下のSBOMエントリを削除しますか?\n\n${label}`)) return;
  try {
    // PURLが空の場合はフォールバックフィールドも送信して削除
    const params = new URLSearchParams({
      purl:       entry.purl       || "",
      name:       entry.name       || "",
      type:       entry.type       || "",
      version:    entry.version    || "",
      release:    entry.release    || "",
      os_name:    entry.os_name    || "",
      os_version: entry.os_version || "",
      arch:       entry.arch       || "",
    });
    await apiFetch(`/api/admin/sbom?${params}`, { method: "DELETE" });
    showToast("削除しました", "success");
    loadSbom();
  } catch (e) {
    showToast(`削除失敗: ${e.message}`, "error");
  }
}

function getSelectedSbomIndices() {
  return Array.from(document.querySelectorAll(".sbom-row-check:checked"))
    .map((cb) => parseInt(cb.dataset.idx, 10));
}

function updateBulkDeleteBtn() {
  const btn = document.getElementById("btn-bulk-delete-sbom");
  if (!btn) return;
  const count = document.querySelectorAll(".sbom-row-check:checked").length;
  btn.style.display = count > 0 ? "inline-flex" : "none";
  btn.querySelector(".bulk-count").textContent = count;
}

function toggleSelectAllSbom(checked) {
  document.querySelectorAll(".sbom-row-check").forEach((cb) => {
    cb.checked = checked;
  });
  updateBulkDeleteBtn();
}

async function confirmBulkDeleteSbom() {
  const indices = getSelectedSbomIndices();
  if (!indices.length) return;
  if (!confirm(`選択した ${indices.length} 件のSBOMエントリを削除しますか?`)) return;
  const entries = indices.map((idx) => window._sbomEntries[idx]).filter(Boolean);
  try {
    await apiFetch("/api/admin/sbom/bulk-delete", {
      method: "POST",
      body: JSON.stringify({ entries }),
    });
    showToast(`${entries.length} 件を削除しました`, "success");
    loadSbom();
  } catch (e) {
    showToast(`一括削除失敗: ${e.message}`, "error");
  }
}

function readSbomForm() {
  return {
    type:       document.getElementById("f-type")?.value.trim() || "",
    name:       document.getElementById("f-name")?.value.trim() || "",
    version:    document.getElementById("f-version")?.value.trim() || "",
    release:    document.getElementById("f-release")?.value.trim() || "",
    purl:       document.getElementById("f-purl")?.value.trim() || "",
    os_name:    document.getElementById("f-os_name")?.value.trim() || "",
    os_version: document.getElementById("f-os_version")?.value.trim() || "",
    arch:       document.getElementById("f-arch")?.value.trim() || "",
  };
}

function sbomFormHtml(e) {
  return `
    <div class="form-grid">
      <div class="form-group">
        <label class="form-label">Type</label>
        <input id="f-type" class="form-input" placeholder="rpm / deb / npm …" value="${esc(e.type || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Name</label>
        <input id="f-name" class="form-input" placeholder="パッケージ名" value="${esc(e.name || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Version</label>
        <input id="f-version" class="form-input" placeholder="1.2.3" value="${esc(e.version || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Release</label>
        <input id="f-release" class="form-input" placeholder="1.el8" value="${esc(e.release || "")}">
      </div>
      <div class="form-group full-width">
        <label class="form-label">PURL</label>
        <input id="f-purl" class="form-input" placeholder="pkg:rpm/redhat/openssl@1.1.1g-15.el8" value="${esc(e.purl || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">OS Name</label>
        <input id="f-os_name" class="form-input" placeholder="AlmaLinux" value="${esc(e.os_name || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">OS Version</label>
        <input id="f-os_version" class="form-input" placeholder="8.9" value="${esc(e.os_version || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Arch</label>
        <input id="f-arch" class="form-input" placeholder="x86_64" value="${esc(e.arch || "")}">
      </div>
    </div>`;
}

// ════════════════════════════════════════════════════
// 担当者マッピング セクション
// ════════════════════════════════════════════════════

async function loadOwners() {
  ownerTableBody.innerHTML = `
    <tr><td colspan="7" class="table-loading">
      <div class="spinner"></div> 読み込み中...
    </td></tr>`;
  const params = new URLSearchParams({ q: state.ownerQuery });
  try {
    const data = await apiFetch(`/api/admin/owners?${params}`);
    state.ownerTotal = data.total || 0;
    renderOwnerTable(data.mappings || []);
    ownerCountEl.textContent = `全 ${state.ownerTotal} 件`;
  } catch (e) {
    ownerTableBody.innerHTML = `<tr><td colspan="7" class="table-empty">読み込み失敗: ${e.message}</td></tr>`;
    showToast(`担当者マッピング読み込み失敗: ${e.message}`, "error");
  }
}

function renderOwnerTable(mappings) {
  if (!mappings.length) {
    ownerTableBody.innerHTML = `<tr><td colspan="7" class="table-empty">データがありません</td></tr>`;
    return;
  }
  ownerTableBody.innerHTML = mappings.map((m, idx) => `
    <tr>
      <td class="cell-pattern" title="${esc(m.pattern)}">${esc(m.pattern)}</td>
      <td>${esc(m.system_name)}</td>
      <td class="cell-email" title="${esc(m.owner_email)}">${esc(m.owner_email)}</td>
      <td>${esc(m.owner_name)}</td>
      <td>${esc(m.notes)}</td>
      <td>${m.priority ?? ""}</td>
      <td>
        <div class="action-btns">
          <button class="btn-action" title="編集" onclick="openOwnerEdit(${idx})">
            <i data-lucide="pencil"></i>
          </button>
          <button class="btn-action btn-delete" title="削除" onclick="confirmDeleteOwner(${idx})">
            <i data-lucide="trash-2"></i>
          </button>
        </div>
      </td>
    </tr>`).join("");
  lucide.createIcons();
  window._ownerMappings = mappings;
}

function openOwnerAdd() {
  state.editTarget = null;
  modalTitle.textContent = "担当者マッピングを追加";
  modalBody.innerHTML = ownerFormHtml({});
  modalSaveBtn.onclick = saveOwner;
  openModal();
}

function openOwnerEdit(idx) {
  const mapping = window._ownerMappings?.[idx];
  if (!mapping) return;
  state.editTarget = mapping;
  modalTitle.textContent = "担当者マッピングを編集";
  modalBody.innerHTML = ownerFormHtml(mapping);
  modalSaveBtn.onclick = saveOwner;
  openModal();
}

async function saveOwner() {
  const body = readOwnerForm();
  if (!body.pattern.trim()) {
    document.getElementById("f-pattern")?.classList.add("error");
    showToast("Patternは必須です", "error");
    return;
  }
  try {
    if (state.editTarget) {
      await apiFetch("/api/admin/owners", {
        method: "PUT",
        body: JSON.stringify({
          old_pattern: state.editTarget.pattern,
          old_system_name: state.editTarget.system_name,
          ...body,
        }),
      });
      showToast("担当者マッピングを更新しました", "success");
    } else {
      await apiFetch("/api/admin/owners", {
        method: "POST",
        body: JSON.stringify(body),
      });
      showToast("担当者マッピングを追加しました", "success");
    }
    closeModal();
    loadOwners();
  } catch (e) {
    showToast(`保存失敗: ${e.message}`, "error");
  }
}

async function confirmDeleteOwner(idx) {
  const mapping = window._ownerMappings?.[idx];
  if (!mapping) return;
  if (!confirm(`以下のマッピングを削除しますか?\n\nPattern: ${mapping.pattern}\nSystem: ${mapping.system_name}`)) return;
  try {
    const params = new URLSearchParams({
      pattern: mapping.pattern,
      system_name: mapping.system_name,
    });
    await apiFetch(`/api/admin/owners?${params}`, { method: "DELETE" });
    showToast("削除しました", "success");
    loadOwners();
  } catch (e) {
    showToast(`削除失敗: ${e.message}`, "error");
  }
}

function readOwnerForm() {
  return {
    pattern:     document.getElementById("f-pattern")?.value.trim() || "",
    system_name: document.getElementById("f-system_name")?.value.trim() || "",
    owner_email: document.getElementById("f-owner_email")?.value.trim() || "",
    owner_name:  document.getElementById("f-owner_name")?.value.trim() || "",
    notes:       document.getElementById("f-notes")?.value.trim() || "",
    priority:    parseInt(document.getElementById("f-priority")?.value || "9999", 10) || 9999,
  };
}

function ownerFormHtml(m) {
  return `
    <div class="form-grid">
      <div class="form-group full-width">
        <label class="form-label">Pattern <span class="required">*</span></label>
        <input id="f-pattern" class="form-input" placeholder="pkg:rpm/redhat/* または *" value="${esc(m.pattern || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">System Name</label>
        <input id="f-system_name" class="form-input" placeholder="認証基盤" value="${esc(m.system_name || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Owner Email</label>
        <input id="f-owner_email" class="form-input" type="email" placeholder="owner@example.com" value="${esc(m.owner_email || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Owner Name</label>
        <input id="f-owner_name" class="form-input" placeholder="山田 太郎" value="${esc(m.owner_name || "")}">
      </div>
      <div class="form-group">
        <label class="form-label">Priority</label>
        <input id="f-priority" class="form-input" type="number" min="1" placeholder="1 (小さいほど優先)" value="${m.priority ?? ""}">
      </div>
      <div class="form-group full-width">
        <label class="form-label">Notes</label>
        <input id="f-notes" class="form-input" placeholder="備考・用途など" value="${esc(m.notes || "")}">
      </div>
    </div>`;
}

// ── モーダル共通 ──────────────────────────────────────
function openModal() {
  modal.classList.remove("hidden");
  lucide.createIcons();
}

function closeModal() {
  modal.classList.add("hidden");
  state.editTarget = null;
}

// ── ユーティリティ ─────────────────────────────────────
function esc(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── イベントバインド ──────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // タブ
  document.querySelectorAll(".admin-tab").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // SBOM検索（debounce）
  sbomSearchInput.addEventListener("input", () => {
    clearTimeout(sbomDebounceTimer);
    sbomDebounceTimer = setTimeout(() => {
      state.sbomQuery = sbomSearchInput.value;
      state.sbomPage = 1;
      loadSbom();
    }, 300);
  });

  // SBOM ページネーション
  sbomPrevBtn.addEventListener("click", () => {
    if (state.sbomPage > 1) { state.sbomPage--; loadSbom(); }
  });
  sbomNextBtn.addEventListener("click", () => {
    const totalPages = Math.ceil(state.sbomTotal / state.sbomPerPage);
    if (state.sbomPage < totalPages) { state.sbomPage++; loadSbom(); }
  });

  // 担当者検索（debounce）
  ownerSearchInput.addEventListener("input", () => {
    clearTimeout(ownerDebounceTimer);
    ownerDebounceTimer = setTimeout(() => {
      state.ownerQuery = ownerSearchInput.value;
      loadOwners();
    }, 300);
  });

  // モーダル: キャンセル / オーバーレイクリック
  document.getElementById("modal-cancel").addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  // 追加ボタン
  document.getElementById("btn-add-sbom").addEventListener("click", openSbomAdd);
  document.getElementById("btn-add-owner").addEventListener("click", openOwnerAdd);

  // Lucide 初期化
  lucide.createIcons();

  // 初期データロード
  loadUser();
  loadSbom();
});

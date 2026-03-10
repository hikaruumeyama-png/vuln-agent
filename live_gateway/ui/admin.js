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
  vulnsPage: 1,
  vulnsPerPage: 50,
  vulnsQuery: "",
  vulnsSource: "",
  vulnsSbomMatched: "",
  vulnsProcessed: "",
  vulnsTotal: 0,
  vulnsSelectedSource: "",  // カード選択状態
};

let sbomDebounceTimer = null;
let ownerDebounceTimer = null;
let vulnDebounceTimer = null;

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
const vulnPane          = document.getElementById("pane-vulns");
const vulnSourcesGrid   = document.getElementById("vuln-sources-grid");
const vulnSourcesCount  = document.getElementById("vuln-sources-count");
const vulnTableBody     = document.getElementById("vuln-tbody");
const vulnCountEl       = document.getElementById("vuln-count");
const vulnSearchInput   = document.getElementById("vuln-search");
const vulnSourceFilter  = document.getElementById("vuln-source-filter");
const vulnFilterSbom    = document.getElementById("vuln-filter-sbom");
const vulnFilterProcessed = document.getElementById("vuln-filter-processed");
const vulnPageInfo      = document.getElementById("vuln-page-info");
const vulnPrevBtn       = document.getElementById("vuln-prev");
const vulnNextBtn       = document.getElementById("vuln-next");
const vulnDetailOverlay = document.getElementById("vuln-detail-overlay");
const vulnDetailTitle   = document.getElementById("vuln-detail-title");
const vulnDetailBody    = document.getElementById("vuln-detail-body");
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
  vulnPane.classList.toggle("active", tab === "vulns");
  if (tab === "sbom") loadSbom();
  else if (tab === "owners") loadOwners();
  else if (tab === "vulns") { loadVulnSources(); loadVulns(); }
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

// ════════════════════════════════════════════════════
// 脆弱性フィード セクション
// ════════════════════════════════════════════════════

// ソース定義マップ（アイコン・ラベル・カテゴリ）
const VULN_SOURCE_META = {
  cisa_kev:   { icon: "shield-alert",  label: "CISA KEV",   category: "public_db" },
  nvd:        { icon: "database",      label: "NVD",         category: "public_db" },
  jvn:        { icon: "globe",         label: "JVN",         category: "public_db" },
  osv:        { icon: "package-open",  label: "OSV",         category: "public_db" },
  cisco_csaf: { icon: "router",        label: "Cisco",       category: "vendor_api" },
  msrc:       { icon: "monitor",       label: "MSRC",        category: "vendor_api" },
  fortinet:   { icon: "shield",        label: "Fortinet",    category: "vendor_api" },
  almalinux:  { icon: "server",        label: "AlmaLinux",   category: "vendor_api" },
  zabbix:     { icon: "activity",      label: "Zabbix",      category: "web_scraping" },
  motex:      { icon: "scan",          label: "MOTEX",       category: "web_scraping" },
  skysea:     { icon: "cloud",         label: "SKYSEA",      category: "web_scraping" },
};

const CATEGORY_LABELS = {
  public_db:     "Public DB",
  vendor_api:    "Vendor API",
  web_scraping:  "Web Scraping",
};

const CATEGORY_BADGE = {
  public_db:     "badge-blue",
  vendor_api:    "badge-teal",
  web_scraping:  "badge-purple",
};

// ── 相対時間ヘルパー ──────────────────────────────────
function timeAgo(isoString) {
  if (!isoString) return "---";
  const now = Date.now();
  const then = new Date(isoString).getTime();
  if (isNaN(then)) return "---";
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 0) return "たった今";
  if (diffSec < 60) return `${diffSec}秒前`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}分前`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}時間前`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 30) return `${diffDay}日前`;
  const diffMonth = Math.floor(diffDay / 30);
  if (diffMonth < 12) return `${diffMonth}ヶ月前`;
  return `${Math.floor(diffMonth / 12)}年前`;
}

// ── ソースカード読み込み ──────────────────────────────
async function loadVulnSources() {
  vulnSourcesGrid.innerHTML = `<div class="vuln-sources-loading"><div class="spinner"></div> ソース情報を読み込み中...</div>`;
  try {
    const data = await apiFetch("/api/admin/vulns/sources");
    const sources = data.sources || [];
    vulnSourcesCount.textContent = `${sources.length} ソース`;
    renderSourceCards(sources);
    // ソースフィルタードロップダウンを更新
    populateSourceFilter(sources);
  } catch (e) {
    vulnSourcesGrid.innerHTML = `<div class="vuln-sources-loading">読み込み失敗: ${esc(e.message)}</div>`;
    showToast(`ソース情報読み込み失敗: ${e.message}`, "error");
  }
}

function renderSourceCards(sources) {
  if (!sources.length) {
    vulnSourcesGrid.innerHTML = `<div class="vuln-sources-loading">ソースが登録されていません</div>`;
    return;
  }
  vulnSourcesGrid.innerHTML = sources.map((s) => {
    const meta = VULN_SOURCE_META[s.source_id] || { icon: "help-circle", label: s.source_id, category: "public_db" };
    const catBadge = CATEGORY_BADGE[meta.category] || "badge-gray";
    const catLabel = CATEGORY_LABELS[meta.category] || meta.category;
    const hasError = !!s.error_message;
    const neverPolled = !s.last_poll_at;
    const statusClass = hasError ? "error" : (neverPolled ? "never" : "ok");
    const statusDotClass = hasError ? "status-dot-red" : (neverPolled ? "status-dot-gray" : "status-dot-green");
    const isActive = state.vulnsSelectedSource === s.source_id;
    return `
      <div class="vuln-source-card ${isActive ? "active" : ""} ${hasError ? "error" : ""}"
           data-source-id="${esc(s.source_id)}"
           onclick="selectSource('${esc(s.source_id)}')"
           title="${hasError ? esc(s.error_message) : ""}">
        <div class="vuln-source-header">
          <div class="vuln-source-icon">
            <i data-lucide="${esc(meta.icon)}"></i>
          </div>
          <div class="vuln-source-label-wrap">
            <span class="vuln-source-label">${esc(meta.label)} <a href="${getSourceUrl(s.source_id)}" target="_blank" rel="noopener" class="vuln-source-ext-link" onclick="event.stopPropagation()" title="ソースサイトを開く"><i data-lucide="external-link"></i></a></span>
            <span class="badge ${catBadge}">${esc(catLabel)}</span>
          </div>
        </div>
        <div class="vuln-source-stats">
          <div class="vuln-stat">
            <span class="vuln-stat-value">${s.total_vulns ?? 0}</span>
            <span class="vuln-stat-label">脆弱性</span>
          </div>
          <div class="vuln-stat">
            <span class="vuln-stat-value">${s.sbom_matched_count ?? 0}</span>
            <span class="vuln-stat-label">SBOM突合</span>
          </div>
          <div class="vuln-stat">
            <span class="vuln-stat-value">${s.items_new ?? 0}</span>
            <span class="vuln-stat-label">新規</span>
          </div>
        </div>
        <div class="vuln-source-footer">
          <span class="vuln-source-poll-time">
            <span class="status-dot ${statusDotClass}"></span>
            ${neverPolled ? "未取得" : timeAgo(s.last_poll_at)}
          </span>
          ${hasError ? `<span class="vuln-source-error-hint" title="${esc(s.error_message)}"><i data-lucide="alert-triangle"></i></span>` : ""}
        </div>
      </div>`;
  }).join("");
  lucide.createIcons();
}

function populateSourceFilter(sources) {
  // 既存オプションをクリアして再構築
  vulnSourceFilter.innerHTML = `<option value="">すべてのソース</option>`;
  sources.forEach((s) => {
    const meta = VULN_SOURCE_META[s.source_id] || { label: s.source_id };
    const opt = document.createElement("option");
    opt.value = s.source_id;
    opt.textContent = meta.label;
    if (state.vulnsSource === s.source_id) opt.selected = true;
    vulnSourceFilter.appendChild(opt);
  });
}

function selectSource(sourceId) {
  // トグル動作: 同じカードを再クリックで解除
  if (state.vulnsSelectedSource === sourceId) {
    state.vulnsSelectedSource = "";
    state.vulnsSource = "";
  } else {
    state.vulnsSelectedSource = sourceId;
    state.vulnsSource = sourceId;
  }
  // カードのactive状態を更新
  document.querySelectorAll(".vuln-source-card").forEach((card) => {
    card.classList.toggle("active", card.dataset.sourceId === state.vulnsSelectedSource);
  });
  // ドロップダウンも同期
  vulnSourceFilter.value = state.vulnsSource;
  state.vulnsPage = 1;
  loadVulns();
}

// ── 脆弱性リスト読み込み ────────────────────────────────
async function loadVulns() {
  vulnTableBody.innerHTML = `
    <tr><td colspan="7" class="table-loading">
      <div class="spinner"></div> 読み込み中...
    </td></tr>`;
  const params = new URLSearchParams({
    q: state.vulnsQuery,
    source: state.vulnsSource,
    sbom_matched: state.vulnsSbomMatched,
    processed: state.vulnsProcessed,
    page: state.vulnsPage,
    per_page: state.vulnsPerPage,
  });
  try {
    const data = await apiFetch(`/api/admin/vulns?${params}`);
    state.vulnsTotal = data.total || 0;
    renderVulnTable(data.entries || []);
    updateVulnPagination();
    vulnCountEl.textContent = `全 ${state.vulnsTotal} 件`;
  } catch (e) {
    vulnTableBody.innerHTML = `<tr><td colspan="7" class="table-empty">読み込み失敗: ${esc(e.message)}</td></tr>`;
    showToast(`脆弱性一覧読み込み失敗: ${e.message}`, "error");
  }
}

function renderVulnTable(entries) {
  if (!entries.length) {
    vulnTableBody.innerHTML = `<tr><td colspan="7" class="table-empty">データがありません</td></tr>`;
    return;
  }
  vulnTableBody.innerHTML = entries.map((e) => {
    const aliases = (e.aliases || []).slice(0, 3).map((a) => esc(a)).join(", ");
    const aliasMore = (e.aliases || []).length > 3 ? ` +${(e.aliases || []).length - 3}` : "";
    const firstMeta = VULN_SOURCE_META[e.first_source] || { label: e.first_source };
    const firstBadge = CATEGORY_BADGE[(firstMeta).category] || "badge-gray";
    const sourcesSeen = (e.sources_seen || []).map((sid) => {
      const m = VULN_SOURCE_META[sid] || { label: sid };
      const b = CATEGORY_BADGE[(m).category] || "badge-gray";
      return `<span class="badge ${b} vuln-badge-sm">${esc(m.label)}</span>`;
    }).join(" ");
    const sbomIcon = e.sbom_matched
      ? `<span class="vuln-icon-yes" title="突合あり"><i data-lucide="check-circle"></i></span>`
      : `<span class="vuln-icon-no" title="突合なし"><i data-lucide="minus-circle"></i></span>`;
    const processedIcon = e.processed
      ? `<span class="vuln-icon-yes" title="処理済み"><i data-lucide="check-circle"></i></span>`
      : `<span class="vuln-icon-no" title="未処理"><i data-lucide="circle-dashed"></i></span>`;
    return `
      <tr class="vuln-row" onclick="showVulnDetail('${esc(e.vuln_id)}')">
        <td><a href="${getVulnUrl(e.vuln_id, e.first_source)}" target="_blank" rel="noopener" class="vuln-id-link" onclick="event.stopPropagation()" title="取得元ページを開く">${esc(e.vuln_id)} <i data-lucide="external-link"></i></a></td>
        <td class="cell-aliases" title="${esc((e.aliases || []).join(', '))}">${aliases}${aliasMore ? `<span class="vuln-alias-more">${aliasMore}</span>` : ""}</td>
        <td><span class="badge ${firstBadge}">${esc(firstMeta.label)}</span></td>
        <td class="cell-sources-seen">${sourcesSeen}</td>
        <td class="cell-date">${e.first_seen_at ? timeAgo(e.first_seen_at) : "---"}</td>
        <td class="cell-icon">${sbomIcon}</td>
        <td class="cell-icon">${processedIcon}</td>
      </tr>`;
  }).join("");
  lucide.createIcons();
  window._vulnEntries = entries;
}

function updateVulnPagination() {
  const totalPages = Math.max(1, Math.ceil(state.vulnsTotal / state.vulnsPerPage));
  vulnPageInfo.textContent = `${state.vulnsPage} / ${totalPages} ページ`;
  vulnPrevBtn.disabled = state.vulnsPage <= 1;
  vulnNextBtn.disabled = state.vulnsPage >= totalPages;
}

// ── 脆弱性詳細モーダル ──────────────────────────────────
async function showVulnDetail(vulnId) {
  vulnDetailTitle.textContent = vulnId;
  vulnDetailBody.innerHTML = `<div class="table-loading"><div class="spinner"></div> 読み込み中...</div>`;
  vulnDetailOverlay.classList.remove("hidden");
  lucide.createIcons();
  try {
    const data = await apiFetch(`/api/admin/vulns/${encodeURIComponent(vulnId)}`);
    const e = data.vuln || data.entry || {};
    const sourcesSeen = (e.sources_seen || []).map((sid) => {
      const m = VULN_SOURCE_META[sid] || { label: sid };
      const b = CATEGORY_BADGE[(m).category] || "badge-gray";
      return `<span class="badge ${b}">${esc(m.label)}</span>`;
    }).join(" ");
    vulnDetailBody.innerHTML = `
      <div class="vuln-detail-grid">
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">Vuln ID</span>
          <span class="vuln-detail-value vuln-detail-id">${esc(e.vuln_id)}</span>
        </div>
        <div class="vuln-detail-field full-width">
          <span class="vuln-detail-label">Source URL</span>
          <span class="vuln-detail-value"><a href="${getVulnUrl(e.vuln_id, e.first_source)}" target="_blank" rel="noopener" class="vuln-detail-link">${getVulnUrl(e.vuln_id, e.first_source)} <i data-lucide="external-link"></i></a></span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">Aliases</span>
          <span class="vuln-detail-value">${(e.aliases || []).map((a) => esc(a)).join(", ") || "---"}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">First Source</span>
          <span class="vuln-detail-value">${esc((VULN_SOURCE_META[e.first_source] || {}).label || e.first_source || "---")}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">Sources Seen</span>
          <span class="vuln-detail-value">${sourcesSeen || "---"}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">First Seen</span>
          <span class="vuln-detail-value">${e.first_seen_at || "---"}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">Last Updated</span>
          <span class="vuln-detail-value">${e.last_updated_at || "---"}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">SBOM Matched</span>
          <span class="vuln-detail-value">${e.sbom_matched ? '<span class="vuln-icon-yes"><i data-lucide="check-circle"></i> はい</span>' : '<span class="vuln-icon-no"><i data-lucide="minus-circle"></i> いいえ</span>'}</span>
        </div>
        <div class="vuln-detail-field">
          <span class="vuln-detail-label">Processed</span>
          <span class="vuln-detail-value">${e.processed ? '<span class="vuln-icon-yes"><i data-lucide="check-circle"></i> 処理済み</span>' : '<span class="vuln-icon-no"><i data-lucide="circle-dashed"></i> 未処理</span>'}</span>
        </div>
        ${e.skip_reason ? `
        <div class="vuln-detail-field full-width">
          <span class="vuln-detail-label">Skip Reason</span>
          <span class="vuln-detail-value vuln-detail-skip">${esc(e.skip_reason)}</span>
        </div>` : ""}
      </div>`;
    lucide.createIcons();
  } catch (e) {
    vulnDetailBody.innerHTML = `<div class="table-empty">読み込み失敗: ${esc(e.message)}</div>`;
    showToast(`詳細読み込み失敗: ${e.message}`, "error");
  }
}

function closeVulnDetail() {
  vulnDetailOverlay.classList.add("hidden");
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

// ── 外部リンクURL生成 ─────────────────────────────────
function getVulnUrl(vulnId, firstSource) {
  const id = (vulnId || "").trim();
  const src = (firstSource || "").trim();

  // First Source ベースで URL を生成（ソース固有の詳細ページ優先）
  const sourceUrlGenerators = {
    nvd:        (vid) => `https://nvd.nist.gov/vuln/detail/${vid}`,
    jvn:        (vid) => /^JVNDB-/i.test(vid)
                  ? `https://jvndb.jvn.jp/ja/contents/${vid.replace(/^JVNDB-(\d{4})-(\d+)$/i, '$1/JVNDB-$1-$2')}.html`
                  : `https://jvndb.jvn.jp/search/index.php?mode=_vulnerability_search_IA_VulnSearch&keyword=${encodeURIComponent(vid)}`,
    cisa_kev:   (vid) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    osv:        (vid) => `https://osv.dev/vulnerability/${vid}`,
    cisco_csaf: (vid) => /^CVE-/i.test(vid)
                  ? `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory?search=${encodeURIComponent(vid)}`
                  : `https://sec.cloudapps.cisco.com/security/center/publicationListing.x`,
    msrc:       (vid) => `https://msrc.microsoft.com/update-guide/vulnerability/${vid}`,
    fortinet:   (vid) => /^FG-IR-/i.test(vid)
                  ? `https://www.fortiguard.com/psirt/${vid}`
                  : `https://www.fortiguard.com/psirt?q=${encodeURIComponent(vid)}`,
    almalinux:  (vid) => /^ALSA-/i.test(vid)
                  ? `https://errata.almalinux.org/${vid.replace(/^ALSA-(\d{4}):(\d+)$/i, '$1/ALSA-$1-$2')}.html`
                  : `https://errata.almalinux.org/`,
    zabbix:     (vid) => `https://www.zabbix.com/security_advisories`,
    motex:      (vid) => `https://www.motex.co.jp/news/security/`,
    skysea:     (vid) => `https://www.skyseaclientview.net/news/`,
  };

  // First Source に対応する URL 生成器があればそれを使う
  if (src && sourceUrlGenerators[src]) {
    return sourceUrlGenerators[src](id);
  }

  // First Source が不明な場合は ID パターンでフォールバック
  if (/^CVE-/i.test(id))    return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^JVNDB-/i.test(id))  return `https://jvndb.jvn.jp/ja/contents/${id.replace(/^JVNDB-(\d{4})-(\d+)$/i, '$1/JVNDB-$1-$2')}.html`;
  if (/^GHSA-/i.test(id))   return `https://github.com/advisories/${id}`;
  if (/^FG-IR-/i.test(id))  return `https://www.fortiguard.com/psirt/${id}`;
  if (/^ALSA-/i.test(id))   return `https://errata.almalinux.org/`;

  return `https://www.google.com/search?q=${encodeURIComponent(id)}`;
}

function getSourceUrl(sourceId) {
  const urls = {
    cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    nvd: "https://nvd.nist.gov/vuln/search",
    jvn: "https://jvndb.jvn.jp/",
    osv: "https://osv.dev/",
    cisco_csaf: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    msrc: "https://msrc.microsoft.com/update-guide",
    fortinet: "https://www.fortiguard.com/psirt",
    almalinux: "https://errata.almalinux.org/",
    zabbix: "https://www.zabbix.com/security_advisories",
    motex: "https://www.motex.co.jp/news/security/",
    skysea: "https://www.skyseaclientview.net/news/",
  };
  return urls[sourceId] || "#";
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

  // 脆弱性検索（debounce）
  vulnSearchInput.addEventListener("input", () => {
    clearTimeout(vulnDebounceTimer);
    vulnDebounceTimer = setTimeout(() => {
      state.vulnsQuery = vulnSearchInput.value;
      state.vulnsPage = 1;
      loadVulns();
    }, 300);
  });

  // 脆弱性ソースフィルター
  vulnSourceFilter.addEventListener("change", () => {
    state.vulnsSource = vulnSourceFilter.value;
    state.vulnsSelectedSource = vulnSourceFilter.value;
    // カードのactive状態を同期
    document.querySelectorAll(".vuln-source-card").forEach((card) => {
      card.classList.toggle("active", card.dataset.sourceId === state.vulnsSelectedSource);
    });
    state.vulnsPage = 1;
    loadVulns();
  });

  // SBOM突合フィルタートグル
  vulnFilterSbom.addEventListener("click", () => {
    if (state.vulnsSbomMatched === "true") {
      state.vulnsSbomMatched = "";
      vulnFilterSbom.classList.remove("active");
    } else {
      state.vulnsSbomMatched = "true";
      vulnFilterSbom.classList.add("active");
    }
    state.vulnsPage = 1;
    loadVulns();
  });

  // 処理済みフィルタートグル
  vulnFilterProcessed.addEventListener("click", () => {
    if (state.vulnsProcessed === "true") {
      state.vulnsProcessed = "";
      vulnFilterProcessed.classList.remove("active");
    } else {
      state.vulnsProcessed = "true";
      vulnFilterProcessed.classList.add("active");
    }
    state.vulnsPage = 1;
    loadVulns();
  });

  // 脆弱性ページネーション
  vulnPrevBtn.addEventListener("click", () => {
    if (state.vulnsPage > 1) { state.vulnsPage--; loadVulns(); }
  });
  vulnNextBtn.addEventListener("click", () => {
    const totalPages = Math.ceil(state.vulnsTotal / state.vulnsPerPage);
    if (state.vulnsPage < totalPages) { state.vulnsPage++; loadVulns(); }
  });

  // 脆弱性詳細モーダル: オーバーレイクリック / Escape
  vulnDetailOverlay.addEventListener("click", (e) => {
    if (e.target === vulnDetailOverlay) closeVulnDetail();
  });

  // モーダル: キャンセル / オーバーレイクリック
  document.getElementById("modal-cancel").addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeModal();
      closeVulnDetail();
    }
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

/**
 * Automated GraphRAG Enterprise Frontend Controller (Tailwind CSS v3 Design System)
 * Connects strictly to verified backend endpoints (/api/*). Zero fabricated metrics.
 */
import {
  ENTITY_PALETTE,
  escapeHtml,
  formatBytes,
  formatTimestamp,
  renderEmptyState,
  renderEntityTypeBadge,
  renderErrorState,
  renderLoadingSkeleton,
  renderStatusBadge,
  renderStructuredGroundedAnswer,
} from "./ui-components.js";
import { InteractiveGraphRenderer } from "./graph-renderer.js";

const ROUTE_META = {
  overview: {
    breadcrumb: "Overview",
    title: "Overview Dashboard",
    subtitle:
      "Verified operational metrics from the transactional SQLite + NetworkX Knowledge Graph and Hybrid Vector Store.",
  },
  documents: {
    breadcrumb: "Document Library",
    title: "Document Library & Access Control",
    subtitle:
      "Ingest supported documents (.md, .txt, .pdf, .json, .csv), manage document-level ACLs, and inspect structure-aware chunks.",
  },
  explorer: {
    breadcrumb: "Knowledge Graph Explorer",
    title: "Knowledge Graph & Entity Resolution Explorer",
    subtitle:
      "Interactive multi-hop topology with verbatim edge provenance and tracked uncertain entity matches.",
  },
  query: {
    breadcrumb: "Query & Citations",
    title: "Evidence-Grounded Query & Citation Workspace",
    subtitle:
      "Combine dense vector similarity, BM25 lexical search, multi-hop graph paths, and community summaries with strict abstention.",
  },
  evaluation: {
    breadcrumb: "Evaluation Benchmark",
    title: "Comparative Evaluation: Vector-Only RAG vs. Hybrid GraphRAG",
    subtitle:
      "Reproducible 6-question benchmark measuring fact recall, citation accuracy, multi-document coverage, abstention, and latency.",
  },
  jobs: {
    breadcrumb: "Pipeline & Observability",
    title: "Indexing Pipeline Jobs & Security Telemetry",
    subtitle:
      "Real ingestion job stages, query routing telemetry, and prompt-injection defense audit logs.",
  },
  users: {
    breadcrumb: "User Management & RBAC",
    title: "User Management, Role Permissions & Security Audit Logs",
    subtitle:
      "Administer tenant accounts, role assignments, per-user document access scopes, active sessions, and immutable security audit events.",
  },
  config: {
    breadcrumb: "Settings & Security",
    title: "Runtime Configuration & RBAC Security Status",
    subtitle:
      "Configure LLM, embedding, and retrieval parameters (Admin role required; secrets are always redacted).",
  },
};

const state = {
  authMode: "session",
  apiKey: "",
  csrfToken: sessionStorage.getItem("graphrag_csrf_token") || "",
  sessionToken: sessionStorage.getItem("graphrag_session_token") || "",
  principal: null,
  activeTab: "overview",
  intendedDestination: null,
  documentsCache: [],
  usersCache: [],
  usersPage: 1,
  usersTotalPages: 1,
  pendingUserAction: null,
  graphData: { nodes: [], edges: [] },
  pendingDeleteDoc: null,
  theme: localStorage.getItem("graphrag_theme") || "dark",
};

let graphRenderer = null;

function applyTheme(theme) {
  state.theme = theme === "light" ? "light" : "dark";
  localStorage.setItem("graphrag_theme", state.theme);
  document.documentElement.classList.toggle("dark", state.theme === "dark");
  const label = document.getElementById("theme-label");
  if (label) {
    label.textContent = state.theme === "dark" ? "Light Mode" : "Dark Mode";
  }
}

function getHeaders(isJson = true) {
  const headers = {};
  if (state.authMode === "session") {
    if (state.csrfToken) {
      headers["X-CSRF-Token"] = state.csrfToken;
    }
    if (state.sessionToken) {
      headers["Authorization"] = `Bearer ${state.sessionToken}`;
    }
  } else if (state.apiKey) {
    headers["X-API-Key"] = state.apiKey;
  }
  if (isJson) headers["Content-Type"] = "application/json";
  return headers;
}

function showBanner(message, type = "info") {
  const banner = document.getElementById("global-banner");
  const textEl = document.getElementById("global-banner-text");
  if (!banner || !textEl) return;

  const palette = {
    info: "border-brand-300 dark:border-brand-800 bg-brand-50/90 dark:bg-brand-950/50 text-brand-900 dark:text-brand-200",
    success:
      "border-emerald-300 dark:border-emerald-800 bg-emerald-50/90 dark:bg-emerald-950/50 text-emerald-900 dark:text-emerald-200",
    error:
      "border-rose-300 dark:border-rose-800 bg-rose-50/90 dark:bg-rose-950/50 text-rose-900 dark:text-rose-200",
  };

  banner.className = `mb-5 rounded-xl border px-4 py-3 text-xs sm:text-sm flex items-center justify-between gap-3 ${
    palette[type] || palette.info
  }`;
  textEl.textContent = message;
  banner.classList.remove("hidden");
}

function sanitizeDestinationTab(tabCandidate) {
  const cleaned = String(tabCandidate || "").replace(/^#/, "").trim();
  return ROUTE_META[cleaned] ? cleaned : "overview";
}

function openLoginModal(preserveTab = null, errorMessage = "") {
  if (preserveTab) {
    state.intendedDestination = sanitizeDestinationTab(preserveTab);
  }
  const loginView = document.getElementById("login-view");
  const errBanner = document.getElementById("login-error-banner");
  const btnClose = document.getElementById("btn-close-login");
  if (errBanner) {
    if (errorMessage) {
      errBanner.textContent = errorMessage;
      errBanner.classList.remove("hidden");
    } else {
      errBanner.classList.add("hidden");
    }
  }
  if (btnClose) {
    btnClose.classList.toggle("hidden", !state.principal);
  }
  if (loginView) {
    loginView.classList.remove("hidden");
    document.getElementById("login-identifier")?.focus();
  }
}

function closeLoginModal() {
  if (!state.principal) return;
  document.getElementById("login-view")?.classList.add("hidden");
}

async function apiFetch(url, options = {}) {
  const resp = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...getHeaders(!(options.body instanceof FormData)),
      ...(options.headers || {}),
    },
  });
  if (!resp.ok) {
    let errText = `HTTP ${resp.status}`;
    try {
      const data = await resp.json();
      errText = data.detail || JSON.stringify(data);
    } catch (_) {}

    if (resp.status === 401 && !url.includes("/api/auth/login")) {
      openLoginModal(state.activeTab, errText);
    }
    throw new Error(errText);
  }
  return resp.json();
}

/**
 * Synchronize caller identity from /api/auth/whoami and gate UI write/admin controls
 * so read-only viewers see truthful disabled states before triggering 403s.
 */
async function refreshIdentity() {
  const badge = document.getElementById("principal-badge");
  const readonlyBanner = document.getElementById("rbac-readonly-banner");
  try {
    const me = await apiFetch("/api/auth/whoami");
    state.principal = me;
    if (me.csrf_token) {
      state.csrfToken = me.csrf_token;
      sessionStorage.setItem("graphrag_csrf_token", me.csrf_token);
    }

    const displayName = me.username || me.user_id;
    if (badge) {
      badge.innerHTML = `
        <div class="space-y-1">
          <div class="flex items-center justify-between gap-2">
            <span class="font-bold truncate" title="${escapeHtml(me.email || me.user_id)}">${escapeHtml(displayName)}</span>
            <span class="uppercase font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20">${escapeHtml(me.role)}</span>
          </div>
          <div class="flex items-center justify-between text-[11px] opacity-85">
            <span>${escapeHtml(me.tenant_id)}</span>
            <span class="font-mono">Active Session</span>
          </div>
        </div>
      `;
    }

    const canWrite = me.role === "admin" || me.role === "analyst";
    const isAdmin = me.role === "admin";

    if (readonlyBanner) {
      readonlyBanner.classList.toggle("hidden", canWrite);
    }

    const btnDemo = document.getElementById("btn-load-demo");
    const btnUpload = document.getElementById("btn-upload");
    const fileInput = document.getElementById("file-input");
    const visSelect = document.getElementById("upload-visibility");
    const btnEval = document.getElementById("btn-run-eval");
    const btnSaveCfg = document.getElementById("btn-save-config");

    if (btnDemo) btnDemo.disabled = !canWrite;
    if (btnUpload) btnUpload.disabled = !canWrite;
    if (fileInput) fileInput.disabled = !canWrite;
    if (visSelect) visSelect.disabled = !canWrite;
    if (btnEval) btnEval.disabled = !canWrite;

    ["cfg-llm-provider", "cfg-emb-provider", "cfg-top-k", "cfg-max-hops", "cfg-chunk-size"].forEach(
      (id) => {
        const el = document.getElementById(id);
        if (el) el.disabled = !isAdmin;
      }
    );
    if (btnSaveCfg) {
      btnSaveCfg.disabled = !isAdmin;
      btnSaveCfg.textContent = isAdmin
        ? "Save Runtime Configuration"
        : "Admin Role Required to Save Settings";
    }

    const navUsers = document.getElementById("nav-item-users");
    if (navUsers) {
      navUsers.classList.toggle("hidden", !isAdmin);
    }

    return true;
  } catch (err) {
    state.principal = null;
    if (badge) {
      badge.innerHTML = `
        <div class="text-xs text-amber-700 dark:text-amber-400 font-semibold py-1">
          Unauthenticated • Please Sign In
        </div>
      `;
    }
    return false;
  }
}

// ============================================================================
// TAB 1: OVERVIEW DASHBOARD
// ============================================================================

async function loadOverview() {
  const kpiGrid = document.getElementById("overview-kpi-grid");
  const entBars = document.getElementById("entity-type-bars");
  const relBars = document.getElementById("rel-type-bars");
  const commContainer = document.getElementById("overview-communities");

  kpiGrid.innerHTML = renderLoadingSkeleton(6);

  try {
    const [data, comms] = await Promise.all([
      apiFetch("/api/overview"),
      apiFetch("/api/graph/communities"),
    ]);

    const kpis = [
      {
        label: "Indexed Documents",
        value: `${data.documents.completed} / ${data.documents.total}`,
        sub: `${data.documents.synthetic_demo_count} demo • ${data.documents.failed} failed`,
        border: "border-l-4 border-l-blue-500",
        icon: `<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>`,
      },
      {
        label: "Preprocessed Chunks",
        value: data.knowledge_graph.chunks,
        sub: "Vector + BM25 indexed",
        border: "border-l-4 border-l-teal-500",
        icon: `<svg class="w-4 h-4 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>`,
      },
      {
        label: "Resolved Entities",
        value: data.knowledge_graph.entities,
        sub: `${data.knowledge_graph.uncertain_entity_matches} held back`,
        border: "border-l-4 border-l-indigo-500",
        icon: `<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" stroke-width="2"/><circle cx="6" cy="6" r="2" stroke-width="2"/><circle cx="18" cy="18" r="2" stroke-width="2"/></svg>`,
      },
      {
        label: "Knowledge Graph Edges",
        value: data.knowledge_graph.relationships,
        sub: `${data.knowledge_graph.explicit_relationships} explicit • ${data.knowledge_graph.inferred_relationships} inferred`,
        border: "border-l-4 border-l-emerald-500",
        icon: `<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>`,
      },
      {
        label: "Thematic Communities",
        value: data.knowledge_graph.communities,
        sub: "Modularity clusters",
        border: "border-l-4 border-l-purple-500",
        icon: `<svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg>`,
      },
      {
        label: "Queries & Telemetry",
        value: `${data.queries.total} (${data.queries.avg_latency_ms} ms)`,
        sub: `${data.queries.abstained} abstained • ${data.queries.prompt_injections_blocked} neutralized`,
        border: "border-l-4 border-l-amber-500",
        icon: `<svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`,
      },
    ];

    kpiGrid.innerHTML = kpis
      .map(
        (k) => `
      <div class="surface-card p-4 flex flex-col justify-between ${k.border} shadow-xs">
        <div class="flex items-center justify-between">
          <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">${escapeHtml(k.label)}</span>
          <span aria-hidden="true">${k.icon}</span>
        </div>
        <div class="text-2xl font-bold text-slate-900 dark:text-slate-100 my-1.5">${escapeHtml(k.value)}</div>
        <span class="text-[11px] text-slate-500 dark:text-slate-400 truncate" title="${escapeHtml(k.sub)}">${escapeHtml(k.sub)}</span>
      </div>`
      )
      .join("");

    // Entity distribution bars
    const maxEnt = Math.max(1, ...data.knowledge_graph.entity_types.map((x) => x.count));
    entBars.innerHTML = data.knowledge_graph.entity_types.length
      ? data.knowledge_graph.entity_types
          .map((e) => {
            const pct = Math.round((e.count / maxEnt) * 100);
            const hex = (ENTITY_PALETTE[e.entity_type] || ENTITY_PALETTE.CONCEPT).hex;
            return `
              <div class="flex items-center gap-3 text-xs">
                <span class="w-32 shrink-0">${renderEntityTypeBadge(e.entity_type)}</span>
                <div class="flex-1 h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div class="h-full rounded-full" style="width:${pct}%; background-color:${hex}"></div>
                </div>
                <span class="w-8 text-right font-mono font-semibold text-slate-700 dark:text-slate-300">${e.count}</span>
              </div>`;
          })
          .join("")
      : renderEmptyState({
          title: "No Entities Extracted Yet",
          description: "Load the 3-document synthetic demo corpus or upload a document to populate the knowledge graph.",
          actionLabel: state.principal.role !== "viewer" ? "Load Demo Corpus" : "",
          actionId: "load-demo",
        });

    // Relationship distribution bars
    const maxRel = Math.max(1, ...data.knowledge_graph.relationship_types.map((x) => x.count));
    relBars.innerHTML = data.knowledge_graph.relationship_types.length
      ? data.knowledge_graph.relationship_types
          .map((r) => {
            const pct = Math.round((r.count / maxRel) * 100);
            return `
              <div class="flex items-center gap-3 text-xs">
                <span class="w-36 shrink-0 font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate" title="${escapeHtml(r.relationship_type)}">${escapeHtml(r.relationship_type)}</span>
                <div class="flex-1 h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div class="h-full rounded-full bg-brand-600 dark:bg-brand-500" style="width:${pct}%"></div>
                </div>
                <span class="w-8 text-right font-mono font-semibold text-slate-700 dark:text-slate-300">${r.count}</span>
              </div>`;
          })
          .join("")
      : renderEmptyState({
          title: "No Relationships Extracted Yet",
          description: "Relationships with verbatim evidence quotes will appear here after document ingestion.",
        });

    // Communities
    commContainer.innerHTML = comms.length
      ? comms
          .map(
            (c) => `
          <div class="surface-subcard flex flex-col justify-between space-y-2">
            <div class="flex items-start justify-between gap-2">
              <h4 class="text-xs font-bold text-slate-900 dark:text-slate-100">${escapeHtml(c.title)}</h4>
              <span class="badge-brand shrink-0">${c.entity_count} entities • ${c.relationship_count} edges</span>
            </div>
            <p class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">${escapeHtml(c.summary)}</p>
            <div class="flex flex-wrap items-center gap-1.5 pt-1">
              ${(c.dominant_types || []).map((t) => renderEntityTypeBadge(t)).join("")}
            </div>
          </div>`
          )
          .join("")
      : `<div class="md:col-span-2">${renderEmptyState({
          title: "No Thematic Communities Detected",
          description: "Communities are automatically computed via Greedy Modularity when entities and edges are indexed.",
        })}</div>`;
  } catch (err) {
    kpiGrid.innerHTML = `<div class="col-span-full">${renderErrorState(err.message, "overview")}</div>`;
  }
}

// ============================================================================
// TAB 2: DOCUMENT LIBRARY & CHUNK INSPECTOR
// ============================================================================

async function loadDocuments() {
  const container = document.getElementById("documents-table-container");
  container.innerHTML = renderLoadingSkeleton(4);
  try {
    const docs = await apiFetch("/api/documents");
    state.documentsCache = docs;
    renderFilteredDocuments();
  } catch (err) {
    container.innerHTML = renderErrorState(err.message, "documents");
  }
}

function renderFilteredDocuments() {
  const container = document.getElementById("documents-table-container");
  const q = (document.getElementById("doc-search-input")?.value || "").trim().toLowerCase();
  const statusFilter = document.getElementById("doc-status-filter")?.value || "all";
  const canWrite = state.principal.role === "admin" || state.principal.role === "analyst";

  if (!state.documentsCache.length) {
    container.innerHTML = renderEmptyState({
      title: "No Documents in Tenant Scope",
      description:
        "Upload a .md, .txt, .pdf, .json, or .csv file above, or load the 3-document synthetic demo corpus to start.",
      actionLabel: canWrite ? "Load Synthetic Demo Corpus" : "",
      actionId: "load-demo",
    });
    return;
  }

  const filtered = state.documentsCache.filter((d) => {
    const matchesSearch =
      !q || d.filename.toLowerCase().includes(q) || d.sha256.toLowerCase().includes(q) || d.doc_id.toLowerCase().includes(q);
    if (!matchesSearch) return false;
    if (statusFilter === "completed") return d.status === "completed";
    if (statusFilter === "demo") return Boolean(d.is_synthetic_demo);
    if (statusFilter === "failed") return d.status === "failed";
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = renderEmptyState({
      title: "No Matching Documents",
      description: "No documents matched your search or status filter.",
    });
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Document &amp; Provenance Label</th>
            <th>Status</th>
            <th>Access Scope (ACL)</th>
            <th>Size</th>
            <th>Chunks</th>
            <th>Entities</th>
            <th>Edges</th>
            <th>Updated</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered
            .map((d) => {
              const vis = d.visibility || "tenant";
              const roles = (d.allowed_roles || ["admin", "analyst", "viewer"]).join(", ");
              const visBadge =
                vis === "private"
                  ? `<span class="badge-danger" title="Owner &amp; Admins only">PRIVATE</span>`
                  : vis === "restricted"
                  ? `<span class="badge-warning" title="Roles: ${escapeHtml(roles)}">RESTRICTED (${escapeHtml(roles)})</span>`
                  : `<span class="badge-success" title="Roles: ${escapeHtml(roles)}">TENANT (${escapeHtml(roles)})</span>`;

              const canEditAcl =
                state.principal.role === "admin" ||
                (state.principal.role === "analyst" && d.owner_user_id === state.principal.user_id);

              return `
            <tr>
              <td>
                <div class="font-semibold text-slate-900 dark:text-slate-100">${escapeHtml(d.filename)}</div>
                <div class="flex items-center gap-1.5 mt-1">
                  <code class="text-[11px] font-mono text-slate-500">${escapeHtml(d.doc_id)}</code>
                  ${
                    d.is_synthetic_demo
                      ? `<span class="badge-warning text-[10px]">[SYNTHETIC DEMO FIXTURE]</span>`
                      : ""
                  }
                </div>
                ${
                  d.error_message
                    ? `<p class="text-xs text-rose-600 dark:text-rose-400 mt-1">${escapeHtml(d.error_message)}</p>`
                    : ""
                }
              </td>
              <td>${renderStatusBadge(d.status)}</td>
              <td class="whitespace-nowrap">${visBadge}</td>
              <td class="font-mono text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">${formatBytes(d.file_size)}</td>
              <td class="font-mono font-semibold">${d.chunk_count}</td>
              <td class="font-mono font-semibold">${d.entity_count}</td>
              <td class="font-mono font-semibold">${d.relationship_count}</td>
              <td class="text-xs text-slate-500 whitespace-nowrap">${formatTimestamp(d.updated_at)}</td>
              <td class="text-right whitespace-nowrap">
                <div class="inline-flex items-center gap-1.5">
                  <button type="button" class="btn-outline btn-xs" data-action="inspect-chunks" data-doc-id="${escapeHtml(d.doc_id)}" data-filename="${escapeHtml(d.filename)}">
                    Chunks
                  </button>
                  <button type="button" class="btn-outline btn-xs" data-action="manage-acl" data-doc-id="${escapeHtml(d.doc_id)}" ${
                !canEditAcl ? "disabled title='Only Admin or document owner can modify ACL'" : ""
              }>
                    Access
                  </button>
                  <button type="button" class="btn-danger btn-xs" data-action="prompt-delete" data-doc-id="${escapeHtml(d.doc_id)}" data-filename="${escapeHtml(d.filename)}" ${
                !canWrite ? "disabled title='Viewer role cannot delete documents'" : ""
              }>
                    Delete
                  </button>
                </div>
              </td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function openDocAclModal(docId) {
  const doc = state.documentsCache.find((d) => d.doc_id === docId);
  if (!doc) return;
  document.getElementById("doc-acl-doc-id").value = doc.doc_id;
  document.getElementById("doc-acl-title").textContent = `Access Control — ${doc.filename}`;
  document.getElementById("doc-acl-visibility").value = doc.visibility || "tenant";
  const roles = doc.allowed_roles || ["admin", "analyst", "viewer"];
  document.getElementById("doc-acl-role-analyst").checked = roles.includes("analyst");
  document.getElementById("doc-acl-role-viewer").checked = roles.includes("viewer");
  document.getElementById("doc-acl-modal").classList.remove("hidden");
}

async function openChunkInspector(docId, filename) {
  const modal = document.getElementById("chunk-inspector-modal");
  const title = document.getElementById("chunk-inspector-title");
  const list = document.getElementById("chunk-inspector-list");

  modal.classList.remove("hidden");
  title.textContent = `Preprocessed Chunks — ${filename}`;
  list.innerHTML = renderLoadingSkeleton(3);

  try {
    const chunks = await apiFetch(`/api/documents/${encodeURIComponent(docId)}/chunks`);
    title.textContent = `Preprocessed Chunks — ${filename} (${chunks.length} chunks)`;
    list.innerHTML = chunks.length
      ? chunks
          .map(
            (c) => `
          <div class="surface-subcard space-y-2">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <code class="badge-brand font-mono">${escapeHtml(c.chunk_id)}</code>
                <span class="text-xs font-semibold text-slate-800 dark:text-slate-200">Page ${c.page_number} • §${escapeHtml(c.section_title)}</span>
              </div>
              <span class="text-xs font-mono text-slate-500">Chars ${c.char_start}–${c.char_end} • ${c.token_count} tokens</span>
            </div>
            <p class="text-xs text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-wrap">${escapeHtml(c.text)}</p>
          </div>`
          )
          .join("")
      : renderEmptyState({ title: "No Chunks Found", description: "This document has no indexed chunks." });
  } catch (err) {
    list.innerHTML = renderErrorState(err.message);
  }
}

function openDeleteConfirmationModal(docId, filename) {
  state.pendingDeleteDoc = { docId, filename };
  const modal = document.getElementById("delete-confirm-modal");
  const desc = document.getElementById("delete-modal-desc");
  desc.innerHTML = `Are you sure you want to delete <strong>${escapeHtml(filename)}</strong> (<code>${escapeHtml(docId)}</code>)? This atomically deletes its preprocessed chunks, relationships, and any orphaned entities while recomputing communities.`;
  modal.classList.remove("hidden");
}

async function confirmDeleteDocument() {
  if (!state.pendingDeleteDoc) return;
  const { docId, filename } = state.pendingDeleteDoc;
  const btn = document.getElementById("btn-confirm-delete");
  btn.disabled = true;
  btn.textContent = "Deleting...";

  try {
    await apiFetch(`/api/documents/${encodeURIComponent(docId)}`, { method: "DELETE" });
    document.getElementById("delete-confirm-modal").classList.add("hidden");
    state.pendingDeleteDoc = null;
    showBanner(`Deleted '${filename}' (${docId}) and cleaned orphaned graph artifacts.`, "success");
    await loadDocuments();
  } catch (err) {
    showBanner(`Delete failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Delete Document";
  }
}

// ============================================================================
// TAB 3: KNOWLEDGE GRAPH EXPLORER
// ============================================================================

async function loadGraphExplorer() {
  const search = document.getElementById("graph-search").value.trim();
  const entType = document.getElementById("graph-entity-type").value;
  const relType = document.getElementById("graph-rel-type").value;
  const incInferred = document.getElementById("graph-include-inferred").checked;

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (entType) params.set("entity_type", entType);
  if (relType) params.set("relationship_type", relType);
  params.set("include_inferred", String(incInferred));
  params.set("limit_nodes", "65");

  try {
    const [subgraph, uncertain] = await Promise.all([
      apiFetch(`/api/graph/subgraph?${params.toString()}`),
      apiFetch("/api/graph/uncertain-matches"),
    ]);

    state.graphData = subgraph;
    document.getElementById("graph-stats-badge").textContent =
      `Showing ${subgraph.returned_nodes} of ${subgraph.total_graph_nodes} nodes • ${subgraph.returned_edges} of ${subgraph.total_graph_edges} edges`;

    if (graphRenderer) {
      graphRenderer.render(subgraph.nodes, subgraph.edges);
    }

    const uncContainer = document.getElementById("uncertain-matches-container");
    uncContainer.innerHTML = uncertain.length
      ? `<div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Entity Candidate A</th>
                <th>Entity Candidate B</th>
                <th>Schema Type</th>
                <th>Surface Similarity</th>
                <th>Holdback Rationale (Why Not Merged)</th>
              </tr>
            </thead>
            <tbody>
              ${uncertain
                .map(
                  (u) => `
                <tr>
                  <td class="font-semibold text-slate-900 dark:text-slate-100">${escapeHtml(u.entity_a_name)}</td>
                  <td class="font-semibold text-slate-900 dark:text-slate-100">${escapeHtml(u.entity_b_name)}</td>
                  <td>${renderEntityTypeBadge(u.entity_type)}</td>
                  <td class="font-mono font-semibold">${(u.similarity_score * 100).toFixed(1)}%</td>
                  <td class="text-xs text-slate-600 dark:text-slate-300">${escapeHtml(u.reason)}</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
      : renderEmptyState({
          title: "No Uncertain Entity Matches Flagged",
          description: "Ambiguous entity pairs held back from automatic merging will appear here.",
        });
  } catch (err) {
    showBanner(`Graph query blocked or failed: ${err.message}`, "error");
  }
}

function renderNodeInspector(node) {
  const box = document.getElementById("graph-inspector-content");
  const relatedEdges = state.graphData.edges.filter(
    (e) => e.source_id === node.entity_id || e.target_id === node.entity_id
  );

  box.innerHTML = `
    <div class="surface-subcard space-y-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        ${renderEntityTypeBadge(node.entity_type)}
        <span class="badge-success">Confidence: ${(node.confidence * 100).toFixed(0)}%</span>
      </div>
      <h4 class="text-base font-bold text-slate-900 dark:text-slate-100">${escapeHtml(node.canonical_name)}</h4>
      <div class="text-xs font-mono text-slate-500">
        ID: ${escapeHtml(node.entity_id)} • Community: ${escapeHtml(node.community_id || "none")} • Degree: ${node.degree}
      </div>
      <p class="text-xs text-slate-700 dark:text-slate-300">
        <strong class="font-semibold">Verified Aliases:</strong>
        ${node.aliases.length ? escapeHtml(node.aliases.join(", ")) : "None"}
      </p>
      <p class="text-xs text-slate-600 dark:text-slate-400">${escapeHtml(node.description)}</p>
    </div>

    <div class="space-y-2">
      <h4 class="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
        Source Document Mentions (${node.mentions.length})
      </h4>
      ${node.mentions
        .map(
          (m) => `
        <div class="surface-subcard space-y-1 text-xs">
          <div class="flex items-center justify-between font-mono text-[11px] text-brand-600 dark:text-brand-400">
            <span>Doc: ${escapeHtml(m.doc_id)} • Chunk: ${escapeHtml(m.chunk_id)}</span>
            <button type="button" class="btn-outline btn-xs py-0.5 px-2 text-[10px]" data-action="inspect-chunks" data-doc-id="${escapeHtml(m.doc_id)}" data-filename="${escapeHtml(m.doc_id)}">Inspect Chunk</button>
          </div>
          <p class="italic text-slate-700 dark:text-slate-300">"${escapeHtml(m.evidence_quote)}"</p>
        </div>`
        )
        .join("")}
    </div>

    <div class="space-y-2">
      <h4 class="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
        Connected Relationships (${relatedEdges.length})
      </h4>
      ${relatedEdges
        .map(
          (e) => `
        <div class="surface-subcard space-y-1.5 text-xs">
          <div class="flex flex-wrap items-center gap-1.5">
            <strong class="text-slate-900 dark:text-slate-100">${escapeHtml(e.source_name)}</strong>
            <span class="${e.is_inferred ? "badge-purple" : "badge-success"} font-mono">
              ${escapeHtml(e.relationship_type)}${e.is_inferred ? " (inferred)" : ""}
            </span>
            <strong class="text-slate-900 dark:text-slate-100">${escapeHtml(e.target_name)}</strong>
          </div>
          <p class="italic text-slate-600 dark:text-slate-300">"${escapeHtml(e.evidence_quote)}"</p>
          <div class="text-[11px] font-mono text-slate-500">Source: ${escapeHtml(e.filename || e.doc_id)}</div>
        </div>`
        )
        .join("")}
    </div>
  `;
}

function renderEdgeInspector(edge) {
  const box = document.getElementById("graph-inspector-content");
  box.innerHTML = `
    <div class="surface-subcard space-y-3 text-xs">
      <div class="flex items-center justify-between gap-2">
        <span class="${edge.is_inferred ? "badge-purple" : "badge-success"}">
          ${edge.is_inferred ? "Model-Inferred Relationship" : "Explicitly Stated Relationship"}
        </span>
        <span class="badge-neutral font-mono">Confidence: ${(edge.confidence * 100).toFixed(0)}%</span>
      </div>

      <div class="p-3 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-sm font-semibold text-slate-900 dark:text-slate-100">
        ${escapeHtml(edge.source_name)}
        <span class="text-brand-600 dark:text-brand-400 font-mono text-xs mx-1">-[${escapeHtml(edge.relationship_type)}]-></span>
        ${escapeHtml(edge.target_name)}
      </div>

      <div class="space-y-1 text-slate-700 dark:text-slate-300">
        <div><strong>Source Document:</strong> ${escapeHtml(edge.filename)} (<code>${escapeHtml(edge.doc_id)}</code>)</div>
        <div><strong>Chunk Provenance:</strong> <code>${escapeHtml(edge.chunk_id)}</code> (Chars ${edge.char_start}–${edge.char_end})</div>
        <div><strong>Temporal Marker:</strong> ${escapeHtml(edge.temporal_marker || "None")}</div>
      </div>

      <div class="pt-2 border-t border-slate-200 dark:border-slate-800">
        <strong class="block uppercase tracking-wider text-[11px] text-slate-500 mb-1">Verbatim Evidence Quote</strong>
        <blockquote class="p-2.5 rounded bg-white dark:bg-slate-950 border-l-4 border-brand-500 italic text-slate-800 dark:text-slate-200">
          "${escapeHtml(edge.evidence_quote)}"
        </blockquote>
      </div>
    </div>
  `;
}

// ============================================================================
// TAB 4: QUERY & CITATION WORKSPACE
// ============================================================================

async function runQuery(e) {
  e.preventDefault();
  const question = document.getElementById("query-input").value.trim();
  if (!question) return;

  const strategy = document.getElementById("query-strategy").value;
  const maxHops = parseInt(document.getElementById("query-hops").value, 10);
  const includeInferred = document.getElementById("query-inferred").checked;
  const btn = document.getElementById("btn-run-query");

  btn.disabled = true;
  btn.textContent = "Synthesizing Grounded Response...";

  try {
    const res = await apiFetch("/api/query", {
      method: "POST",
      body: JSON.stringify({
        question,
        strategy,
        max_hops: maxHops,
        include_inferred: includeInferred,
        top_k_chunks: 6,
      }),
    });

    document.getElementById("query-result-container").classList.remove("hidden");
    document.getElementById("query-telemetry-badges").innerHTML = `
      <span class="badge-brand font-mono">Routed: ${escapeHtml(res.routed_strategy)}</span>
      ${renderStatusBadge(res.abstained ? "Abstained" : "Grounded")}
      <span class="badge-neutral font-mono">${res.latency_ms} ms</span>
    `;
    document.getElementById("query-explanation").textContent = res.retrieval_explanation;
    document.getElementById("query-answer-box").innerHTML = renderStructuredGroundedAnswer(
      res.answer,
      res.abstained
    );

    const pathsList = document.getElementById("query-paths-list");
    pathsList.innerHTML = res.graph_paths.length
      ? res.graph_paths
          .map(
            (p) => `
          <div class="surface-subcard space-y-2">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <code class="badge-brand font-mono">${escapeHtml(p.path_id)}</code>
              <span class="${p.has_inferred_edge ? "badge-purple" : "badge-success"}">
                ${p.has_inferred_edge ? "Contains Inferred Edge" : "Explicitly Stated Path"} • Conf: ${p.min_confidence}
              </span>
            </div>
            <div class="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-900 dark:text-slate-100 overflow-x-auto">
              ${escapeHtml(p.path_text)}
            </div>
            <div class="text-[11px] text-slate-500">
              Source Docs: ${p.source_doc_ids.map((d) => `<code>${escapeHtml(d)}</code>`).join(", ")}
            </div>
          </div>`
          )
          .join("")
      : renderEmptyState({
          title: "No Knowledge Graph Paths Used",
          description:
            res.routed_strategy === "vector_only"
              ? "Baseline vector_only strategy intentionally bypasses knowledge graph traversal."
              : "No matching entity paths were found within the configured hop limit.",
        });

    const citList = document.getElementById("query-citations-list");
    citList.innerHTML = res.citations.length
      ? res.citations
          .map(
            (c) => `
          <div class="surface-subcard space-y-1.5">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <strong class="text-xs font-bold text-slate-900 dark:text-slate-100">
                [${escapeHtml(c.citation_id)}] ${escapeHtml(c.filename)} (p.${c.page_number} • §${escapeHtml(c.section_title)})
              </strong>
              <span class="badge-neutral font-mono">${escapeHtml(c.retrieval_source)} • ${c.relevance_score}</span>
            </div>
            <p class="text-xs text-slate-600 dark:text-slate-300 italic leading-relaxed">"${escapeHtml(c.evidence_quote)}"</p>
            <div class="text-[11px] font-mono text-slate-500">Chunk ID: ${escapeHtml(c.chunk_id)}</div>
          </div>`
          )
          .join("")
      : renderEmptyState({
          title: "No Supporting Text Chunks",
          description: "No chunks met the relevance threshold in your tenant scope.",
        });
  } catch (err) {
    showBanner(`Query execution failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Run Grounded Query";
  }
}

// ============================================================================
// TAB 5: EVALUATION BENCHMARK
// ============================================================================

function renderInitialEvaluationState() {
  const container = document.getElementById("eval-results-container");
  if (!container || container.dataset.loaded === "true") return;
  container.innerHTML = renderEmptyState({
    title: "Benchmark Suite Ready",
    description:
      "Ensure the 3-document synthetic demo corpus is loaded, then click 'Run Live Benchmark Suite' to measure Vector-Only RAG vs. Hybrid GraphRAG.",
  });
}

async function runEvaluationSuite() {
  const btn = document.getElementById("btn-run-eval");
  const container = document.getElementById("eval-results-container");
  btn.disabled = true;
  btn.textContent = "Running 6-Question Benchmark...";
  container.innerHTML = renderLoadingSkeleton(4);

  try {
    const res = await apiFetch("/api/evaluation/run", { method: "POST" });
    container.dataset.loaded = "true";
    const v = res.vector_only_summary;
    const g = res.hybrid_graphrag_summary;

    container.innerHTML = `
      <div class="space-y-6 mt-2">
        <div class="rounded-xl border border-brand-200 dark:border-brand-800/80 bg-brand-50/70 dark:bg-brand-950/40 p-4 text-xs sm:text-sm text-brand-950 dark:text-brand-200 leading-relaxed">
          <strong class="font-bold block mb-1">Verified Trade-off Summary (${escapeHtml(res.dataset_label)})</strong>
          ${escapeHtml(res.tradeoff_analysis)}
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="surface-subcard space-y-2.5">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-bold text-slate-900 dark:text-slate-100">Baseline: Conventional Vector-Only RAG</h4>
              <span class="badge-neutral">vector_only</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs">
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Avg Fact Recall</span>
                <strong class="text-lg font-bold">${(v.avg_fact_recall * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Citation Accuracy</span>
                <strong class="text-lg font-bold">${(v.avg_citation_accuracy * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Multi-Doc Coverage</span>
                <strong class="text-lg font-bold">${(v.avg_multi_doc_coverage * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Avg Query Latency</span>
                <strong class="text-lg font-bold">${v.avg_latency_ms} ms</strong>
              </div>
            </div>
          </div>

          <div class="surface-subcard space-y-2.5 border-brand-300 dark:border-brand-800">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-bold text-slate-900 dark:text-slate-100">Automated Hybrid GraphRAG</h4>
              <span class="badge-brand">hybrid (Vector+BM25+KG+Comm)</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs">
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Avg Fact Recall</span>
                <strong class="text-lg font-bold text-emerald-600 dark:text-emerald-400">${(g.avg_fact_recall * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Citation Accuracy</span>
                <strong class="text-lg font-bold text-emerald-600 dark:text-emerald-400">${(g.avg_citation_accuracy * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Multi-Doc Coverage</span>
                <strong class="text-lg font-bold text-emerald-600 dark:text-emerald-400">${(g.avg_multi_doc_coverage * 100).toFixed(1)}%</strong>
              </div>
              <div class="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span class="text-slate-500 block">Avg Query Latency</span>
                <strong class="text-lg font-bold">${g.avg_latency_ms} ms</strong>
              </div>
            </div>
          </div>
        </div>

        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Question ID &amp; Category</th>
                <th>Benchmark Question</th>
                <th>Vector-Only Recall</th>
                <th>Hybrid GraphRAG Recall</th>
                <th>KG Paths</th>
                <th>Latency (Vec / KG)</th>
              </tr>
            </thead>
            <tbody>
              ${res.comparisons
                .map(
                  (c) => `
                <tr>
                  <td>
                    <code class="font-mono text-xs font-semibold">${escapeHtml(c.question_id)}</code>
                    <div class="mt-1"><span class="badge-neutral">${escapeHtml(c.category)}</span></div>
                  </td>
                  <td class="text-xs max-w-md">${escapeHtml(c.question)}</td>
                  <td class="font-mono">${(c.vector_only.fact_recall * 100).toFixed(0)}%</td>
                  <td class="font-mono font-bold text-emerald-600 dark:text-emerald-400">${(c.hybrid_graphrag.fact_recall * 100).toFixed(0)}%</td>
                  <td class="font-mono text-xs">${c.hybrid_graphrag.graph_path_count} paths</td>
                  <td class="font-mono text-xs whitespace-nowrap">${c.vector_only.latency_ms} ms / ${c.hybrid_graphrag.latency_ms} ms</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = renderErrorState(err.message);
  } finally {
    btn.disabled = state.principal.role === "viewer";
    btn.textContent = "Run Live Benchmark Suite";
  }
}

// ============================================================================
// TAB 6: PIPELINE JOBS & OBSERVABILITY LOGS
// ============================================================================

async function loadJobsAndLogs() {
  const jobsContainer = document.getElementById("jobs-table-container");
  const logsContainer = document.getElementById("logs-table-container");
  jobsContainer.innerHTML = renderLoadingSkeleton(3);
  logsContainer.innerHTML = renderLoadingSkeleton(3);

  try {
    const [jobs, logs] = await Promise.all([
      apiFetch("/api/jobs"),
      apiFetch("/api/observability/logs"),
    ]);

    jobsContainer.innerHTML = jobs.length
      ? `<div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Document ID</th>
                <th>Status</th>
                <th>Pipeline Stage</th>
                <th>Progress</th>
                <th>Started At</th>
              </tr>
            </thead>
            <tbody>
              ${jobs
                .map(
                  (j) => `
                <tr>
                  <td><code class="font-mono text-xs">${escapeHtml(j.job_id)}</code></td>
                  <td><code class="font-mono text-xs text-slate-500">${escapeHtml(j.doc_id || "—")}</code></td>
                  <td>${renderStatusBadge(j.status)}</td>
                  <td class="font-mono text-xs">${escapeHtml(j.stage)}</td>
                  <td>
                    <div class="flex items-center gap-2">
                      <div class="w-20 h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                        <div class="h-full bg-brand-600" style="width:${j.progress_pct}%"></div>
                      </div>
                      <span class="font-mono text-xs">${j.progress_pct}%</span>
                    </div>
                  </td>
                  <td class="text-xs text-slate-500 whitespace-nowrap">${formatTimestamp(j.started_at)}</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
      : renderEmptyState({
          title: "No Pipeline Jobs Recorded Yet",
          description: "Ingestion jobs and stage telemetry will appear here when documents are indexed.",
        });

    logsContainer.innerHTML = logs.length
      ? `<div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Query ID</th>
                <th>User</th>
                <th>Question</th>
                <th>Strategy</th>
                <th>Evidence Used</th>
                <th>Latency</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              ${logs
                .map(
                  (l) => `
                <tr>
                  <td><code class="font-mono text-xs">${escapeHtml(l.query_id)}</code></td>
                  <td class="text-xs font-medium">${escapeHtml(l.user_id)}</td>
                  <td class="text-xs max-w-sm truncate" title="${escapeHtml(l.question)}">${escapeHtml(l.question)}</td>
                  <td><span class="badge-brand font-mono">${escapeHtml(l.routed_strategy)}</span></td>
                  <td class="text-xs font-mono">${l.citation_count} cit • ${l.graph_path_count} paths</td>
                  <td class="font-mono text-xs whitespace-nowrap">${l.latency_ms} ms</td>
                  <td class="text-xs text-slate-500 whitespace-nowrap">${formatTimestamp(l.created_at)}</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
      : renderEmptyState({
          title: "No Query Telemetry Logged Yet",
          description: "Run an analytical query in the Query Workspace to record operational telemetry.",
        });
  } catch (err) {
    jobsContainer.innerHTML = renderErrorState(err.message, "jobs");
  }
}

// ============================================================================
// TAB 7: CONFIGURATION & SECURITY
// ============================================================================

async function loadConfig() {
  try {
    const data = await apiFetch("/api/config");
    document.getElementById("sanitized-config-json").textContent = JSON.stringify(data, null, 2);
    document.getElementById("cfg-llm-provider").value = data.config.llm_provider;
    document.getElementById("cfg-emb-provider").value = data.config.embedding_provider;
    document.getElementById("cfg-top-k").value = data.config.default_top_k_chunks;
    document.getElementById("cfg-max-hops").value = data.config.default_max_graph_hops;
    document.getElementById("cfg-chunk-size").value = data.config.chunk_size_chars;
  } catch (err) {
    showBanner(`Failed to load configuration: ${err.message}`, "error");
  }
}

// ============================================================================
// TAB 8: USER MANAGEMENT, RBAC & SECURITY AUDIT LOGS
// ============================================================================

async function loadUsersAndAuditLogs() {
  const deniedBox = document.getElementById("users-permission-denied");
  const adminContent = document.getElementById("users-admin-content");
  const isAdmin = state.principal?.role === "admin";

  if (!isAdmin) {
    deniedBox?.classList.remove("hidden");
    adminContent?.classList.add("hidden");
    return;
  }

  deniedBox?.classList.add("hidden");
  adminContent?.classList.remove("hidden");

  await Promise.all([loadUsersList(), loadAuditLogs(), refreshDocumentsCacheQuietly()]);
}

async function refreshDocumentsCacheQuietly() {
  try {
    state.documentsCache = await apiFetch("/api/documents");
  } catch (_) {}
}

async function loadUsersList() {
  const container = document.getElementById("users-table-container");
  const pagEl = document.getElementById("users-pagination");
  if (!container) return;

  container.innerHTML = renderLoadingSkeleton(4);

  const search = (document.getElementById("user-search-input")?.value || "").trim();
  const role = document.getElementById("user-role-filter")?.value || "";
  const isActive = document.getElementById("user-status-filter")?.value || "";

  const params = new URLSearchParams();
  params.set("page", String(state.usersPage));
  params.set("page_size", "15");
  if (search) params.set("search", search);
  if (role) params.set("role", role);
  if (isActive !== "") params.set("is_active", isActive);

  try {
    const res = await apiFetch(`/api/users?${params.toString()}`);
    state.usersCache = res.items || [];
    state.usersTotalPages = res.total_pages || 1;

    if (!state.usersCache.length) {
      container.innerHTML = renderEmptyState({
        title: "No Matching User Accounts",
        description: "No users matched your search query, role, or status filter.",
      });
      if (pagEl) pagEl.innerHTML = "";
      return;
    }

    container.innerHTML = `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>User &amp; Identity</th>
              <th>Role</th>
              <th>Status</th>
              <th>Document Access Scope</th>
              <th>Sessions</th>
              <th>Last Login</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.usersCache
              .map((u) => {
                const isSelf = u.user_id === state.principal.user_id;
                const roleBadge =
                  u.role === "admin"
                    ? `<span class="badge-brand font-mono">ADMIN</span>`
                    : u.role === "analyst"
                    ? `<span class="badge-success font-mono">ANALYST</span>`
                    : `<span class="badge-warning font-mono">VIEWER</span>`;

                const statusBadge = u.is_active
                  ? `<span class="badge-success">ACTIVE</span>`
                  : `<span class="badge-danger">DEACTIVATED</span>`;

                const docScope =
                  u.allowed_doc_ids === null || u.allowed_doc_ids === undefined
                    ? `<span class="text-xs text-slate-600 dark:text-slate-300">All Role-Authorized Docs</span>`
                    : `<span class="badge-warning">${u.allowed_doc_ids.length} Restricted Doc(s)</span>`;

                return `
              <tr>
                <td>
                  <div class="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <span>${escapeHtml(u.full_name || u.username)}</span>
                    ${isSelf ? `<span class="badge-neutral text-[10px]">YOU</span>` : ""}
                  </div>
                  <div class="text-xs text-slate-500 font-mono">
                    @${escapeHtml(u.username)} • ${escapeHtml(u.email)}
                  </div>
                </td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td>${docScope}</td>
                <td class="font-mono text-xs">${u.active_sessions || 0} active</td>
                <td class="text-xs text-slate-500 whitespace-nowrap">${
                  u.last_login_at ? formatTimestamp(u.last_login_at) : "Never"
                }</td>
                <td class="text-right whitespace-nowrap">
                  <div class="inline-flex items-center gap-1.5">
                    <button type="button" class="btn-outline btn-xs" data-user-action="edit" data-user-id="${escapeHtml(u.user_id)}">
                      Edit / Scope
                    </button>
                    <button type="button" class="btn-outline btn-xs" data-user-action="toggle-status" data-user-id="${escapeHtml(u.user_id)}" ${
                  isSelf && u.is_active
                    ? "disabled title='Admins cannot deactivate their own active account'"
                    : ""
                }>
                      ${u.is_active ? "Deactivate" : "Activate"}
                    </button>
                    <button type="button" class="btn-danger btn-xs" data-user-action="revoke-sessions" data-user-id="${escapeHtml(u.user_id)}">
                      Revoke Sessions
                    </button>
                  </div>
                </td>
              </tr>`;
              })
              .join("")}
          </tbody>
        </table>
      </div>
    `;

    if (pagEl) {
      pagEl.innerHTML = `
        <span>Showing ${state.usersCache.length} of ${res.total} user account(s) in <code>${escapeHtml(
        state.principal.tenant_id
      )}</code></span>
        <div class="inline-flex items-center gap-2">
          <button type="button" id="btn-users-prev" class="btn-outline btn-xs" ${
            state.usersPage <= 1 ? "disabled" : ""
          }>Previous</button>
          <span class="font-mono">Page ${res.page} / ${res.total_pages}</span>
          <button type="button" id="btn-users-next" class="btn-outline btn-xs" ${
            state.usersPage >= res.total_pages ? "disabled" : ""
          }>Next</button>
        </div>
      `;
    }
  } catch (err) {
    container.innerHTML = renderErrorState(err.message, "users");
  }
}

async function loadAuditLogs() {
  const container = document.getElementById("audit-logs-container");
  if (!container) return;

  container.innerHTML = renderLoadingSkeleton(3);
  const search = (document.getElementById("audit-search-input")?.value || "").trim();
  const statusFilter = document.getElementById("audit-status-filter")?.value || "";

  const params = new URLSearchParams();
  params.set("page", "1");
  params.set("page_size", "25");
  if (search) params.set("search", search);
  if (statusFilter) params.set("status", statusFilter);

  try {
    const res = await apiFetch(`/api/audit-logs?${params.toString()}`);
    const items = res.items || [];
    if (!items.length) {
      container.innerHTML = renderEmptyState({
        title: "No Security Audit Events Found",
        description: "Authentication, RBAC enforcement, and user management events will appear here.",
      });
      return;
    }

    container.innerHTML = `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Outcome</th>
              <th>IP Address</th>
              <th>Sanitized Details</th>
            </tr>
          </thead>
          <tbody>
            ${items
              .map((a) => {
                const outcomeBadge =
                  a.status === "success"
                    ? `<span class="badge-success">SUCCESS</span>`
                    : `<span class="badge-danger">${escapeHtml(a.status.toUpperCase())}</span>`;
                const detailsStr = JSON.stringify(a.details || {});
                return `
              <tr>
                <td class="text-xs text-slate-500 whitespace-nowrap">${formatTimestamp(a.created_at)}</td>
                <td class="text-xs">
                  <span class="font-semibold">${escapeHtml(a.actor_username)}</span>
                  <span class="text-slate-400 font-mono">(${escapeHtml(a.actor_role)})</span>
                </td>
                <td><code class="font-mono text-xs text-brand-600 dark:text-brand-400">${escapeHtml(a.action)}</code></td>
                <td class="text-xs font-mono">${escapeHtml(a.target_type)}: ${escapeHtml(a.target_id || "—")}</td>
                <td>${outcomeBadge}</td>
                <td class="font-mono text-xs text-slate-500">${escapeHtml(a.ip_address)}</td>
                <td class="text-xs font-mono text-slate-500 max-w-xs truncate" title="${escapeHtml(detailsStr)}">${escapeHtml(detailsStr)}</td>
              </tr>`;
              })
              .join("")}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    container.innerHTML = renderErrorState(err.message, "users");
  }
}

function renderUserDocsChecklist(selectedDocIds = null) {
  const checklist = document.getElementById("user-form-docs-checklist");
  const restrictToggle = document.getElementById("user-form-restrict-docs");
  if (!checklist || !restrictToggle) return;

  const isRestricted = Array.isArray(selectedDocIds);
  restrictToggle.checked = isRestricted;
  checklist.classList.toggle("hidden", !isRestricted);

  if (!state.documentsCache.length) {
    checklist.innerHTML = `<p class="text-xs text-slate-500 py-1">No documents currently indexed in tenant.</p>`;
    return;
  }

  const selectedSet = new Set(selectedDocIds || []);
  checklist.innerHTML = state.documentsCache
    .map(
      (d) => `
      <label class="flex items-center gap-2 text-xs cursor-pointer py-0.5">
        <input type="checkbox" class="user-doc-checkbox rounded border-slate-300 text-brand-600" value="${escapeHtml(
          d.doc_id
        )}" ${selectedSet.has(d.doc_id) ? "checked" : ""} />
        <span class="truncate font-medium">${escapeHtml(d.filename)}</span>
        <code class="text-[10px] font-mono text-slate-400">${escapeHtml(d.doc_id)}</code>
      </label>`
    )
    .join("");
}

function openCreateUserModal() {
  document.getElementById("user-modal-title").textContent = "Create New User Account";
  document.getElementById("user-modal-error").classList.add("hidden");
  document.getElementById("user-form-id").value = "";

  const uInput = document.getElementById("user-form-username");
  uInput.value = "";
  uInput.disabled = false;
  document.getElementById("user-form-email").value = "";
  document.getElementById("user-form-fullname").value = "";
  document.getElementById("user-form-role").value = "viewer";
  document.getElementById("user-form-active").checked = true;

  const pwInput = document.getElementById("user-form-password");
  pwInput.value = "";
  pwInput.required = true;
  document.getElementById("user-form-password-label").textContent = "Initial Password (min 8 chars)";

  renderUserDocsChecklist(null);
  document.getElementById("user-form-modal").classList.remove("hidden");
}

function openEditUserModal(userId) {
  const u = state.usersCache.find((x) => x.user_id === userId);
  if (!u) return;

  document.getElementById("user-modal-title").textContent = `Edit User — @${u.username}`;
  document.getElementById("user-modal-error").classList.add("hidden");
  document.getElementById("user-form-id").value = u.user_id;

  const uInput = document.getElementById("user-form-username");
  uInput.value = u.username;
  uInput.disabled = true;

  document.getElementById("user-form-email").value = u.email;
  document.getElementById("user-form-fullname").value = u.full_name || "";
  document.getElementById("user-form-role").value = u.role;
  document.getElementById("user-form-active").checked = Boolean(u.is_active);

  const pwInput = document.getElementById("user-form-password");
  pwInput.value = "";
  pwInput.required = false;
  document.getElementById("user-form-password-label").textContent =
    "Reset Password (Optional — leave blank to keep current)";

  renderUserDocsChecklist(u.allowed_doc_ids);
  document.getElementById("user-form-modal").classList.remove("hidden");
}

function openUserConfirmModal(actionType, userId) {
  const u = state.usersCache.find((x) => x.user_id === userId);
  if (!u) return;

  state.pendingUserAction = { actionType, user: u };
  const titleEl = document.getElementById("user-confirm-title");
  const descEl = document.getElementById("user-confirm-desc");
  const btnEl = document.getElementById("btn-execute-user-confirm");

  if (actionType === "toggle-status") {
    const nextActive = !u.is_active;
    titleEl.textContent = nextActive
      ? `Reactivate @${u.username}?`
      : `Deactivate @${u.username} & Revoke Sessions?`;
    descEl.textContent = nextActive
      ? `This will restore login and API access for ${u.full_name} (@${u.username}) with role '${u.role}'.`
      : `This will immediately suspend login access for ${u.full_name} (@${u.username}) and revoke all active sessions.`;
    btnEl.textContent = nextActive ? "Activate Account" : "Deactivate Account";
    btnEl.className = nextActive ? "btn-primary" : "btn-danger";
  } else if (actionType === "revoke-sessions") {
    titleEl.textContent = `Revoke Active Sessions for @${u.username}?`;
    descEl.textContent = `This will immediately invalidate all ${u.active_sessions || 0} active browser/token sessions for @${u.username}, requiring them to sign in again.`;
    btnEl.textContent = "Revoke All Sessions";
    btnEl.className = "btn-danger";
  }

  document.getElementById("user-confirm-modal").classList.remove("hidden");
}

async function executeUserConfirmAction() {
  if (!state.pendingUserAction) return;
  const { actionType, user } = state.pendingUserAction;
  const modal = document.getElementById("user-confirm-modal");

  try {
    if (actionType === "toggle-status") {
      await apiFetch(`/api/users/${encodeURIComponent(user.user_id)}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: !user.is_active }),
      });
      showBanner(
        `User @${user.username} is now ${!user.is_active ? "active" : "deactivated"}.`,
        "success"
      );
    } else if (actionType === "revoke-sessions") {
      const res = await apiFetch(
        `/api/users/${encodeURIComponent(user.user_id)}/revoke-sessions`,
        { method: "POST" }
      );
      showBanner(
        `Revoked ${res.revoked_count} active session(s) for @${user.username}.`,
        "success"
      );
    }
    modal.classList.add("hidden");
    state.pendingUserAction = null;
    await loadUsersAndAuditLogs();
  } catch (err) {
    modal.classList.add("hidden");
    showBanner(`Action failed: ${err.message}`, "error");
  }
}

// ============================================================================
// NAVIGATION & EVENT WIRING
// ============================================================================

function switchTab(tabName, updateHash = true) {
  const validTab = ROUTE_META[tabName] ? tabName : "overview";
  state.activeTab = validTab;

  if (updateHash) {
    history.replaceState(null, "", `#${validTab}`);
  }

  const meta = ROUTE_META[validTab];
  document.getElementById("page-breadcrumb").textContent = meta.breadcrumb;
  document.getElementById("page-title").textContent = meta.title;
  document.getElementById("page-subtitle").textContent = meta.subtitle;

  document.querySelectorAll(".nav-item").forEach((btn) => {
    const isActive = btn.dataset.tab === validTab;
    btn.classList.toggle("nav-item-active", isActive);
    if (isActive) {
      btn.setAttribute("aria-current", "page");
    } else {
      btn.removeAttribute("aria-current");
    }
  });

  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("hidden", panel.id !== `tab-${validTab}`);
  });

  const sidebar = document.getElementById("app-sidebar");
  const mobileBtn = document.getElementById("btn-mobile-menu");
  if (sidebar && window.innerWidth < 1024) {
    sidebar.classList.add("hidden");
    if (mobileBtn) mobileBtn.setAttribute("aria-expanded", "false");
  }

  if (validTab === "overview") loadOverview();
  if (validTab === "documents") loadDocuments();
  if (validTab === "explorer") loadGraphExplorer();
  if (validTab === "evaluation") renderInitialEvaluationState();
  if (validTab === "jobs") loadJobsAndLogs();
  if (validTab === "users") loadUsersAndAuditLogs();
  if (validTab === "config") loadConfig();
}

async function triggerDemoCorpusLoad() {
  const btn = document.getElementById("btn-load-demo");
  btn.disabled = true;
  const origText = btn.textContent;
  btn.textContent = "Indexing Demo Corpus...";
  try {
    const res = await apiFetch("/api/documents/load-demo-fixtures", { method: "POST" });
    showBanner(
      `Ingested ${res.ingested_count} synthetic demo documents with full chunk and graph provenance.`,
      "success"
    );
    switchTab(state.activeTab, false);
  } catch (err) {
    showBanner(`Cannot load demo corpus: ${err.message}`, "error");
  } finally {
    btn.disabled = state.principal.role === "viewer";
    btn.textContent = origText;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  applyTheme(state.theme);

  const svgEl = document.getElementById("graph-svg");
  if (svgEl) {
    graphRenderer = new InteractiveGraphRenderer(svgEl, {
      onSelectNode: (node) => renderNodeInspector(node),
      onSelectEdge: (edge) => renderEdgeInspector(edge),
    });
  }

  document.getElementById("btn-theme-toggle")?.addEventListener("click", () => {
    applyTheme(state.theme === "dark" ? "light" : "dark");
  });
  document.getElementById("btn-mobile-theme")?.addEventListener("click", () => {
    applyTheme(state.theme === "dark" ? "light" : "dark");
  });

  document.getElementById("btn-mobile-menu")?.addEventListener("click", (e) => {
    const sidebar = document.getElementById("app-sidebar");
    const isHidden = sidebar.classList.toggle("hidden");
    e.currentTarget.setAttribute("aria-expanded", String(!isHidden));
  });

  document.getElementById("btn-dismiss-banner")?.addEventListener("click", () => {
    document.getElementById("global-banner")?.classList.add("hidden");
  });

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.querySelectorAll("[data-jump-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.jumpTab));
  });

  // Delegated click handlers for dynamic tables, user management actions, empty state CTAs, and retries
  document.body.addEventListener("click", (e) => {
    const actionBtn = e.target.closest("[data-action]");
    if (actionBtn) {
      const action = actionBtn.dataset.action;
      const docId = actionBtn.dataset.docId;
      const filename = actionBtn.dataset.filename;
      if (action === "inspect-chunks") openChunkInspector(docId, filename);
      if (action === "manage-acl") openDocAclModal(docId);
      if (action === "prompt-delete") openDeleteConfirmationModal(docId, filename);
    }

    const userActionBtn = e.target.closest("[data-user-action]");
    if (userActionBtn) {
      const uAction = userActionBtn.dataset.userAction;
      const userId = userActionBtn.dataset.userId;
      if (uAction === "edit") openEditUserModal(userId);
      if (uAction === "toggle-status") openUserConfirmModal("toggle-status", userId);
      if (uAction === "revoke-sessions") openUserConfirmModal("revoke-sessions", userId);
    }

    const quickLoginBtn = e.target.closest("[data-quick-login]");
    if (quickLoginBtn) {
      document.getElementById("login-identifier").value = quickLoginBtn.dataset.quickLogin;
      document.getElementById("login-password").value = quickLoginBtn.dataset.quickPass;
      document.getElementById("login-error-banner")?.classList.add("hidden");
    }

    if (e.target.id === "btn-users-prev" && state.usersPage > 1) {
      state.usersPage -= 1;
      loadUsersList();
    }
    if (e.target.id === "btn-users-next" && state.usersPage < state.usersTotalPages) {
      state.usersPage += 1;
      loadUsersList();
    }

    const emptyAction = e.target.closest("[data-empty-action]");
    if (emptyAction && emptyAction.dataset.emptyAction === "load-demo") {
      triggerDemoCorpusLoad();
    }

    const citationChip = e.target.closest(".citation-chip");
    if (citationChip) {
      const ref = citationChip.dataset.citationRef;
      if (ref) {
        const targetEl = Array.from(
          document.querySelectorAll("#query-citations-list strong, #query-paths-list code")
        ).find((el) => el.textContent.includes(ref));
        if (targetEl) {
          const card = targetEl.closest(".surface-subcard");
          if (card) {
            card.scrollIntoView({ behavior: "smooth", block: "nearest" });
            card.classList.add("ring-2", "ring-brand-500", "transition-all");
            setTimeout(() => card.classList.remove("ring-2", "ring-brand-500"), 1800);
          }
        }
      }
    }

    const copyBtn = e.target.closest("#btn-copy-answer");
    if (copyBtn) {
      const box = document.getElementById("query-answer-box");
      if (box) {
        navigator.clipboard.writeText(box.innerText || box.textContent);
        showBanner("Grounded answer copied to clipboard.", "success");
      }
    }

    if (retryBtn) {
      switchTab(retryBtn.dataset.retryAction, false);
    }
  });

  // Login, Password Toggle, Logout & Session Controls
  document.getElementById("btn-open-login")?.addEventListener("click", () => {
    openLoginModal(state.activeTab);
  });
  document.getElementById("btn-users-switch-admin")?.addEventListener("click", () => {
    openLoginModal("users");
  });
  document.getElementById("btn-close-login")?.addEventListener("click", closeLoginModal);

  document.getElementById("btn-toggle-password")?.addEventListener("click", (e) => {
    const pwInput = document.getElementById("login-password");
    const btn = e.currentTarget;
    const isPassword = pwInput.type === "password";
    pwInput.type = isPassword ? "text" : "password";
    btn.textContent = isPassword ? "Hide" : "Show";
    btn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
    btn.setAttribute("aria-pressed", String(isPassword));
  });

  document.getElementById("login-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const idVal = (document.getElementById("login-identifier").value || "").trim();
    const pwVal = document.getElementById("login-password").value || "";
    const errEl = document.getElementById("login-error-banner");
    const submitBtn = document.getElementById("btn-login-submit");

    if (!idVal || !pwVal) {
      errEl.textContent = "Please enter both your username/email and password.";
      errEl.classList.remove("hidden");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Verifying Credentials...";
    errEl.classList.add("hidden");

    try {
      const resp = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier: idVal, password: pwVal }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || `Authentication failed (HTTP ${resp.status})`);
      }

      state.authMode = "session";
      state.csrfToken = data.csrf_token || "";
      state.sessionToken = data.session_token || "";
      sessionStorage.setItem("graphrag_auth_mode", "session");
      sessionStorage.setItem("graphrag_csrf_token", state.csrfToken);
      sessionStorage.setItem("graphrag_session_token", state.sessionToken);

      document.getElementById("login-password").value = "";
      closeLoginModal();
      await refreshIdentity();

      const dest = sanitizeDestinationTab(state.intendedDestination || state.activeTab);
      state.intendedDestination = null;
      showBanner(
        `Signed in as ${data.user.full_name || data.user.username} (${data.user.role}).`,
        "success"
      );
      switchTab(dest, true);
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Sign In to Workspace";
    }
  });

  document.getElementById("btn-logout")?.addEventListener("click", async () => {
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
    } catch (_) {}
    state.principal = null;
    state.csrfToken = "";
    state.sessionToken = "";
    sessionStorage.removeItem("graphrag_csrf_token");
    sessionStorage.removeItem("graphrag_session_token");
    sessionStorage.removeItem("graphrag_auth_mode");
    await refreshIdentity();
    openLoginModal("overview", "You have signed out. Sign in below to continue.");
  });

  // Change Password Modal
  document.getElementById("btn-open-password-modal")?.addEventListener("click", () => {
    document.getElementById("change-pw-error")?.classList.add("hidden");
    document.getElementById("cp-current-password").value = "";
    document.getElementById("cp-new-password").value = "";
    document.getElementById("change-password-modal")?.classList.remove("hidden");
  });
  document.getElementById("btn-close-pw-modal")?.addEventListener("click", () => {
    document.getElementById("change-password-modal")?.classList.add("hidden");
  });
  document.getElementById("btn-cancel-pw-modal")?.addEventListener("click", () => {
    document.getElementById("change-password-modal")?.classList.add("hidden");
  });
  document.getElementById("change-password-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("change-pw-error");
    errEl.classList.add("hidden");
    try {
      await apiFetch("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: document.getElementById("cp-current-password").value,
          new_password: document.getElementById("cp-new-password").value,
        }),
      });
      document.getElementById("change-password-modal").classList.add("hidden");
      showBanner("Password updated successfully.", "success");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    }
  });

  // Dev API Key RBAC switcher (if present)
  document.getElementById("api-key-select")?.addEventListener("change", async (e) => {
    state.authMode = "apikey";
    state.apiKey = e.target.value;
    sessionStorage.setItem("graphrag_auth_mode", "apikey");
    await refreshIdentity();
    switchTab(state.activeTab, false);
  });

  // Demo corpus loader & refresh
  document.getElementById("btn-load-demo")?.addEventListener("click", triggerDemoCorpusLoad);
  document.getElementById("btn-refresh")?.addEventListener("click", () => switchTab(state.activeTab, false));

  // Document upload form with ACL visibility
  document.getElementById("upload-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("file-input");
    if (!fileInput.files.length) return;
    const btn = document.getElementById("btn-upload");
    const visSelect = document.getElementById("upload-visibility");
    const visVal = visSelect ? visSelect.value : "tenant";
    btn.disabled = true;
    btn.textContent = "Indexing...";
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("visibility", visVal);
    if (visVal === "restricted") {
      formData.append("allowed_roles", "admin,analyst");
    } else if (visVal === "private") {
      formData.append("allowed_roles", "admin");
    } else {
      formData.append("allowed_roles", "admin,analyst,viewer");
    }
    try {
      const res = await apiFetch("/api/documents/upload", { method: "POST", body: formData });
      showBanner(
        `Indexed '${res.filename}': ${res.chunk_count} chunks, ${res.entity_count} entities, ${res.relationship_count} edges.`,
        "success"
      );
      fileInput.value = "";
      loadDocuments();
    } catch (err) {
      showBanner(`Upload failed: ${err.message}`, "error");
    } finally {
      btn.disabled = state.principal.role === "viewer";
      btn.textContent = "Upload & Index Document";
    }
  });

  // Document ACL Modal
  document.getElementById("btn-close-doc-acl")?.addEventListener("click", () => {
    document.getElementById("doc-acl-modal").classList.add("hidden");
  });
  document.getElementById("btn-cancel-doc-acl")?.addEventListener("click", () => {
    document.getElementById("doc-acl-modal").classList.add("hidden");
  });
  document.getElementById("doc-acl-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const docId = document.getElementById("doc-acl-doc-id").value;
    const visibility = document.getElementById("doc-acl-visibility").value;
    const allowedRoles = ["admin"];
    if (document.getElementById("doc-acl-role-analyst").checked) allowedRoles.push("analyst");
    if (document.getElementById("doc-acl-role-viewer").checked) allowedRoles.push("viewer");

    try {
      await apiFetch(`/api/documents/${encodeURIComponent(docId)}/acl`, {
        method: "PUT",
        body: JSON.stringify({
          visibility,
          allowed_roles: allowedRoles,
          allowed_user_ids: [],
        }),
      });
      document.getElementById("doc-acl-modal").classList.add("hidden");
      showBanner("Document access control updated.", "success");
      loadDocuments();
    } catch (err) {
      showBanner(`Failed to update document ACL: ${err.message}`, "error");
    }
  });

  // User Management controls & modals
  document.getElementById("btn-open-create-user")?.addEventListener("click", openCreateUserModal);
  document.getElementById("btn-close-user-modal")?.addEventListener("click", () => {
    document.getElementById("user-form-modal").classList.add("hidden");
  });
  document.getElementById("btn-cancel-user-form")?.addEventListener("click", () => {
    document.getElementById("user-form-modal").classList.add("hidden");
  });
  document.getElementById("user-form-restrict-docs")?.addEventListener("change", (e) => {
    document.getElementById("user-form-docs-checklist")?.classList.toggle("hidden", !e.target.checked);
  });

  document.getElementById("user-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("user-modal-error");
    errEl.classList.add("hidden");

    const editUserId = document.getElementById("user-form-id").value;
    const restrictDocs = document.getElementById("user-form-restrict-docs").checked;
    let allowedDocIds = null;
    if (restrictDocs) {
      allowedDocIds = Array.from(document.querySelectorAll(".user-doc-checkbox:checked")).map(
        (cb) => cb.value
      );
    }

    const payload = {
      email: document.getElementById("user-form-email").value.trim(),
      full_name: document.getElementById("user-form-fullname").value.trim(),
      role: document.getElementById("user-form-role").value,
      is_active: document.getElementById("user-form-active").checked,
      allowed_doc_ids: allowedDocIds,
    };
    const pw = document.getElementById("user-form-password").value;

    try {
      if (editUserId) {
        if (pw) payload.new_password = pw;
        await apiFetch(`/api/users/${encodeURIComponent(editUserId)}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        showBanner("User account updated.", "success");
      } else {
        payload.username = document.getElementById("user-form-username").value.trim();
        payload.password = pw;
        await apiFetch("/api/users", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        showBanner(`Created user account @${payload.username}.`, "success");
      }
      document.getElementById("user-form-modal").classList.add("hidden");
      await loadUsersAndAuditLogs();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    }
  });

  document.getElementById("btn-cancel-user-confirm")?.addEventListener("click", () => {
    document.getElementById("user-confirm-modal").classList.add("hidden");
    state.pendingUserAction = null;
  });
  document.getElementById("btn-execute-user-confirm")?.addEventListener("click", executeUserConfirmAction);

  document.getElementById("user-search-input")?.addEventListener("input", () => {
    state.usersPage = 1;
    loadUsersList();
  });
  document.getElementById("user-role-filter")?.addEventListener("change", () => {
    state.usersPage = 1;
    loadUsersList();
  });
  document.getElementById("user-status-filter")?.addEventListener("change", () => {
    state.usersPage = 1;
    loadUsersList();
  });
  document.getElementById("audit-search-input")?.addEventListener("input", loadAuditLogs);
  document.getElementById("audit-status-filter")?.addEventListener("change", loadAuditLogs);

  // Document filter controls
  document.getElementById("doc-search-input")?.addEventListener("input", renderFilteredDocuments);
  document.getElementById("doc-status-filter")?.addEventListener("change", renderFilteredDocuments);

  // Modals close & Escape key support
  document.getElementById("btn-close-chunks")?.addEventListener("click", () => {
    document.getElementById("chunk-inspector-modal").classList.add("hidden");
  });
  document.getElementById("btn-cancel-delete")?.addEventListener("click", () => {
    document.getElementById("delete-confirm-modal").classList.add("hidden");
    state.pendingDeleteDoc = null;
  });
  document.getElementById("btn-confirm-delete")?.addEventListener("click", confirmDeleteDocument);

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.getElementById("chunk-inspector-modal")?.classList.add("hidden");
      document.getElementById("delete-confirm-modal")?.classList.add("hidden");
      document.getElementById("user-form-modal")?.classList.add("hidden");
      document.getElementById("user-confirm-modal")?.classList.add("hidden");
      document.getElementById("doc-acl-modal")?.classList.add("hidden");
      document.getElementById("change-password-modal")?.classList.add("hidden");
      closeLoginModal();
    }
  });

  // Graph Explorer controls
  document.getElementById("btn-filter-graph")?.addEventListener("click", loadGraphExplorer);
  document.getElementById("btn-reset-graph-filter")?.addEventListener("click", () => {
    document.getElementById("graph-search").value = "";
    document.getElementById("graph-entity-type").value = "";
    document.getElementById("graph-rel-type").value = "";
    document.getElementById("graph-include-inferred").checked = true;
    loadGraphExplorer();
  });
  document.getElementById("graph-show-edge-labels")?.addEventListener("change", (e) => {
    if (graphRenderer) graphRenderer.setShowEdgeLabels(e.target.checked);
  });
  document.getElementById("btn-zoom-in")?.addEventListener("click", () => graphRenderer?.zoomBy(1.2));
  document.getElementById("btn-zoom-out")?.addEventListener("click", () => graphRenderer?.zoomBy(0.84));
  document.getElementById("btn-zoom-reset")?.addEventListener("click", () => graphRenderer?.resetViewport());

  // Query workspace preset chips & form
  document.querySelectorAll(".chip-btn").forEach((chip) => {
    chip.addEventListener("click", () => {
      const qInput = document.getElementById("query-input");
      qInput.value = chip.dataset.q;
      qInput.focus();
    });
  });
  document.getElementById("query-form")?.addEventListener("submit", runQuery);

  // Evaluation benchmark
  document.getElementById("btn-run-eval")?.addEventListener("click", runEvaluationSuite);

  // Configuration update form
  document.getElementById("config-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/config", {
        method: "PUT",
        body: JSON.stringify({
          llm_provider: document.getElementById("cfg-llm-provider").value,
          embedding_provider: document.getElementById("cfg-emb-provider").value,
          default_top_k_chunks: parseInt(document.getElementById("cfg-top-k").value, 10),
          default_max_graph_hops: parseInt(document.getElementById("cfg-max-hops").value, 10),
          chunk_size_chars: parseInt(document.getElementById("cfg-chunk-size").value, 10),
        }),
      });
      showBanner("Runtime configuration updated.", "success");
      loadConfig();
    } catch (err) {
      showBanner(`Configuration update denied: ${err.message}`, "error");
    }
  });

  const isAuthenticated = await refreshIdentity();
  if (isAuthenticated) {
    closeLoginModal();
    const initialHash = window.location.hash.replace("#", "");
    switchTab(ROUTE_META[initialHash] ? initialHash : "overview", false);
  } else {
    openLoginModal("overview", "Please sign in to access the Automated GraphRAG workspace.");
  }
});

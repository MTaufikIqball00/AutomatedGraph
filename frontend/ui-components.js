/**
 * Reusable Tailwind CSS Design-System Components & Safe Grounded Response Formatters
 * All untrusted document/entity text is HTML-escaped before rendering.
 */

export const ENTITY_PALETTE = {
  ORGANIZATION: { hex: "#3b82f6", badge: "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/70" },
  SYSTEM:       { hex: "#10b981", badge: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/70" },
  EVENT:        { hex: "#ef4444", badge: "bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800/70" },
  POLICY:       { hex: "#f59e0b", badge: "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/70" },
  METRIC:       { hex: "#ec4899", badge: "bg-pink-50 text-pink-700 border-pink-200 dark:bg-pink-950/60 dark:text-pink-300 dark:border-pink-800/70" },
  LOCATION:     { hex: "#8b5cf6", badge: "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/60 dark:text-purple-300 dark:border-purple-800/70" },
  PERSON:       { hex: "#06b6d4", badge: "bg-cyan-50 text-cyan-700 border-cyan-200 dark:bg-cyan-950/60 dark:text-cyan-300 dark:border-cyan-800/70" },
  TECHNOLOGY:   { hex: "#14b8a6", badge: "bg-teal-50 text-teal-700 border-teal-200 dark:bg-teal-950/60 dark:text-teal-300 dark:border-teal-800/70" },
  DATE:         { hex: "#eab308", badge: "bg-yellow-50 text-yellow-800 border-yellow-200 dark:bg-yellow-950/60 dark:text-yellow-300 dark:border-yellow-800/70" },
  CONCEPT:      { hex: "#64748b", badge: "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700" },
};

export function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return escapeHtml(iso);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch (_) {
    return escapeHtml(iso);
  }
}

export function renderEntityTypeBadge(type) {
  const style = ENTITY_PALETTE[type] || ENTITY_PALETTE.CONCEPT;
  return `<span class="badge ${style.badge} font-mono">${escapeHtml(type)}</span>`;
}

export function renderStatusBadge(status) {
  const s = String(status || "").toLowerCase();
  if (s === "completed" || s === "healthy" || s === "grounded") {
    return `<span class="badge-success"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500" aria-hidden="true"></span>${escapeHtml(status)}</span>`;
  }
  if (s === "running" || s === "indexing" || s === "queued") {
    return `<span class="badge-brand"><span class="w-1.5 h-1.5 rounded-full bg-brand-500 animate-pulse" aria-hidden="true"></span>${escapeHtml(status)}</span>`;
  }
  if (s === "failed" || s === "error") {
    return `<span class="badge-danger"><span class="w-1.5 h-1.5 rounded-full bg-rose-500" aria-hidden="true"></span>${escapeHtml(status)}</span>`;
  }
  return `<span class="badge-warning">${escapeHtml(status)}</span>`;
}

export function renderLoadingSkeleton(rows = 3) {
  return `
    <div class="space-y-3 py-2" role="status" aria-busy="true" aria-label="Loading content">
      ${Array.from({ length: rows })
        .map(
          () => `
        <div class="animate-pulse flex items-center justify-between gap-4 p-3 rounded-lg bg-slate-100/70 dark:bg-slate-800/50">
          <div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/3"></div>
          <div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/4"></div>
        </div>`
        )
        .join("")}
    </div>
  `;
}

export function renderEmptyState({ title, description, actionLabel, actionId }) {
  return `
    <div class="text-center py-10 px-4 rounded-xl border border-dashed border-slate-300 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40">
      <div class="inline-flex items-center justify-center w-11 h-11 rounded-xl bg-slate-100 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 mb-3 shadow-xs" aria-hidden="true">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.75" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
        </svg>
      </div>
      <p class="text-sm font-semibold text-slate-800 dark:text-slate-200">${escapeHtml(title)}</p>
      <p class="text-xs text-slate-500 dark:text-slate-400 mt-1.5 max-w-md mx-auto leading-relaxed">${escapeHtml(description)}</p>
      ${
        actionLabel && actionId
          ? `<div class="mt-4">
               <button type="button" data-empty-action="${escapeHtml(actionId)}" class="btn-secondary btn-xs shadow-xs">
                 ${escapeHtml(actionLabel)}
               </button>
             </div>`
          : ""
      }
    </div>
  `;
}

export function renderErrorState(message, retryActionId = "") {
  return `
    <div class="p-4 rounded-xl border border-rose-200 dark:border-rose-900/80 bg-rose-50/80 dark:bg-rose-950/40 flex items-center justify-between gap-4" role="alert">
      <div class="text-xs text-rose-800 dark:text-rose-200">
        <strong class="font-semibold block text-sm mb-0.5">Unable to load section data</strong>
        ${escapeHtml(message)}
      </div>
      ${
        retryActionId
          ? `<button type="button" data-retry-action="${escapeHtml(retryActionId)}" class="btn-danger btn-xs shrink-0">Retry</button>`
          : ""
      }
    </div>
  `;
}

/**
 * Safely formats structured markdown-like sections produced by `synthesize_grounded_answer`
 * into readable Tailwind cards with copy control and highlighted citation tags.
 */
export function renderStructuredGroundedAnswer(rawAnswer, abstained = false) {
  if (!rawAnswer) return `<p class="text-sm text-slate-500">No response generated.</p>`;

  if (abstained) {
    const lines = rawAnswer.split(/\n+/).filter((l) => l.trim().length > 0);
    const heading = lines[0]?.replace(/\*\*/g, "") || "Abstention — Insufficient Grounded Evidence";
    const body = lines.slice(1).join("\n\n");
    return `
      <div class="p-4 rounded-xl border border-amber-300 dark:border-amber-800/80 bg-amber-50/90 dark:bg-amber-950/40 text-amber-950 dark:text-amber-100 space-y-2">
        <div class="flex items-center gap-2 font-semibold text-sm text-amber-900 dark:text-amber-200">
          <span class="badge-warning">ABSTAINED</span>
          <span>${escapeHtml(heading)}</span>
        </div>
        <p class="text-sm leading-relaxed whitespace-pre-line">${escapeHtml(body)}</p>
      </div>
    `;
  }

  // Split by ### Section Headers
  const rawSections = rawAnswer.split(/^###\s+/m).filter((s) => s.trim().length > 0);
  if (rawSections.length === 0) {
    return `<div class="text-sm leading-relaxed whitespace-pre-wrap">${escapeHtml(rawAnswer)}</div>`;
  }

  return `
    <div class="space-y-4">
      <div class="flex justify-end pb-1">
        <button type="button" id="btn-copy-answer" class="btn-outline btn-xs gap-1.5" title="Copy answer text to clipboard">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
          <span>Copy Answer</span>
        </button>
      </div>
      ${rawSections
        .map((sec) => {
          const lines = sec.trim().split("\n");
          const title = lines[0].trim();
          const items = lines.slice(1).filter((l) => l.trim().length > 0);

          const isAlert = title.toLowerCase().includes("contradict") || title.toLowerCase().includes("security");
          const borderClass = isAlert
            ? "border-amber-300 dark:border-amber-800/80 bg-amber-50/50 dark:bg-amber-950/30"
            : "border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50";

          return `
            <div class="rounded-xl border ${borderClass} p-4 shadow-xs">
              <h4 class="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-2.5">
                ${escapeHtml(title)}
              </h4>
              <ul class="space-y-2 text-sm text-slate-800 dark:text-slate-200 leading-relaxed">
                ${items
                  .map((line) => {
                    const cleaned = line.replace(/^-\s*/, "");
                    const formatted = formatSafeInlineCitations(cleaned);
                    return `<li class="flex items-start gap-2">
                      <span class="text-brand-500 font-bold mt-0.5 select-none" aria-hidden="true">•</span>
                      <span class="flex-1">${formatted}</span>
                    </li>`;
                  })
                  .join("")}
              </ul>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

function formatSafeInlineCitations(rawLine) {
  let safe = escapeHtml(rawLine);
  // Highlight **[cit-XX: ...]** or **[pth-XX]** with clickable citation-chip
  safe = safe.replace(
    /\*\*\[([^\]]+)\]\*\*/g,
    `<span class="citation-chip" data-citation-ref="$1">[<span>$1</span>]</span>`
  );
  // Highlight inline backticks `...`
  safe = safe.replace(
    /`([^`]+)`/g,
    `<code class="px-1.5 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-xs font-mono text-slate-900 dark:text-slate-100">$1</code>`
  );
  // Highlight *(explicitly stated)* / *(contains model-inferred link)*
  safe = safe.replace(
    /\*\(([^)]+)\)\*/g,
    `<span class="badge-purple text-xs italic ml-1">$1</span>`
  );
  return safe;
}

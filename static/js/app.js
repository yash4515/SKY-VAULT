/* ─── TraceVault Frontend JavaScript ──────────────────────────────────────── */
"use strict";

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  lastWatermarkId: null,
  lastDocHash: null,
  lastLeakedHash: null,
};

// ── Utilities ─────────────────────────────────────────────────────────────

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  return res.json();
}

function showLoading(text = "Processing...") {
  document.getElementById("loading-text").textContent = text;
  document.getElementById("loading").classList.remove("hidden");
}

function hideLoading() {
  document.getElementById("loading").classList.add("hidden");
}

function toast(msg, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 3800);
}

function resultRow(key, val, cls = "") {
  const valClass = cls ? ` class="${cls}"` : "";
  return `<div class="result-row"><span class="result-key">${key}</span><span class="result-val${valClass}">${val}</span></div>`;
}

function resultSection(title) {
  return `<div class="result-section">${title}</div>`;
}

function shortHash(h) {
  if (!h || typeof h !== "string") return h;
  return h.length > 48 ? h.slice(0, 48) + "…" : h;
}

// ── Tab Navigation ────────────────────────────────────────────────────────

function switchTab(tabId) {
  document.querySelectorAll(".tab-section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const section = document.getElementById(`tab-${tabId}`);
  const btn = document.querySelector(`[data-tab="${tabId}"]`);
  if (section) section.classList.add("active");
  if (btn) btn.classList.add("active");
  // Lazy-load relevant data
  if (tabId === "dashboard") loadStatus();
  if (tabId === "recipients") loadRecipients();
  if (tabId === "documents") { loadDocuments(); }
  if (tabId === "decryption") { populateDecryptionSelects(); }
  if (tabId === "ledger") loadLedger();
}

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// ── Forensics sub-tabs ─────────────────────────────────────────────────────

document.querySelectorAll(".ftab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".ftab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".ftab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`ftab-${btn.dataset.ftab}`).classList.add("active");
  });
});

// ── Status ────────────────────────────────────────────────────────────────

async function loadStatus() {
  try {
    const data = await api("/api/status");
    if (!data.success) return;

    document.getElementById("stat-recipients").textContent = data.recipients.length;
    document.getElementById("stat-documents").textContent = data.documents.length;
    document.getElementById("stat-chain-height").textContent = data.chain_height;
    document.getElementById("stat-chain-valid").textContent = data.chain_valid ? "✓ Valid" : "✗ Error";
    document.getElementById("stat-chain-valid").style.color = data.chain_valid ? "var(--green)" : "var(--red)";

    document.getElementById("info-mode").textContent = data.mode;
    document.getElementById("info-kem").textContent = data.kem_algorithm;
    document.getElementById("info-sig").textContent = data.sig_algorithm;

    // Nav status
    const dot = document.querySelector(".status-dot");
    const txt = document.querySelector(".status-text");
    dot.className = "status-dot online";
    txt.textContent = `${data.mode.includes("REAL") ? "PQC Active" : "Sim Mode"} · ${data.chain_height} blocks`;

  } catch (e) {
    document.querySelector(".status-dot").className = "status-dot error";
    document.querySelector(".status-text").textContent = "Error";
  }
}

// ── Recipients ────────────────────────────────────────────────────────────

async function registerRecipient() {
  const name = document.getElementById("reg-name").value.trim();
  if (!name) { toast("Enter a recipient name", "error"); return; }

  showLoading(`Generating ML-KEM + ML-DSA keypairs for ${name}...`);
  const data = await api("/api/register", "POST", { name });
  hideLoading();

  const box = document.getElementById("reg-result");
  box.classList.remove("hidden");
  if (data.success) {
    box.className = "result-box success";
    box.innerHTML =
      resultRow("Name", data.name) +
      resultRow("Key ID", data.key_id, "green") +
      resultRow("ML-KEM pub", `${data.kem_pub_bytes} bytes`) +
      resultRow("ML-DSA pub", `${data.sig_pub_bytes} bytes`) +
      resultRow("Status", "✓ Registered", "green");
    document.getElementById("reg-name").value = "";
    loadRecipients();
    toast(`${name} registered`, "success");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
  loadStatus();
}

async function loadRecipients() {
  const data = await api("/api/recipients");
  const list = document.getElementById("recipients-list");
  const countBadge = document.getElementById("recipients-count");

  if (!data.success || !data.recipients.length) {
    list.innerHTML = '<div class="empty-state">No recipients registered yet.</div>';
    countBadge.textContent = "0";
    return;
  }

  countBadge.textContent = data.recipients.length;
  list.innerHTML = data.recipients.map(r => `
    <div class="recipient-item">
      <div class="ri-name">👤 ${r.name}</div>
      <div class="ri-meta">
        <span class="ri-keyid">${r.key_id}</span> ·
        ML-KEM: ${r.kem_pub_bytes}B · ML-DSA: ${r.sig_pub_bytes}B
      </div>
    </div>
  `).join("");
}

// ── Documents ─────────────────────────────────────────────────────────────

async function encryptDocument() {
  const text = document.getElementById("doc-text").value.trim();
  const version = parseInt(document.getElementById("doc-version").value) || 1;
  if (!text) { toast("Enter document content", "error"); return; }

  showLoading("Generating DEK, encrypting with AES-256-GCM, wrapping for recipients...");
  const data = await api("/api/encrypt", "POST", { text, version });
  hideLoading();

  const box = document.getElementById("enc-result");
  box.classList.remove("hidden");
  if (data.success) {
    state.lastDocHash = data.document_hash;
    box.className = "result-box success";
    box.innerHTML =
      resultSection("Document") +
      resultRow("Document ID", data.document_id, "green") +
      resultRow("Version", data.version) +
      resultRow("Plaintext", `${data.plaintext_bytes} bytes`) +
      resultRow("Encrypted", `${data.encrypted_bytes} bytes`) +
      resultSection("Key Wrapping") +
      resultRow("Algorithm", "ML-KEM-768 (DEK XOR-wrap)") +
      resultRow("Recipients", data.recipients_wrapped.join(", ")) +
      resultSection("Hash") +
      resultRow("SHA3-256", shortHash(data.document_hash));
    loadDocuments();
    toast("Document encrypted", "success");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
  loadStatus();
}

async function loadDocuments() {
  const data = await api("/api/documents");
  const list = document.getElementById("docs-list");
  const countBadge = document.getElementById("docs-count");

  if (!data.success || !data.documents.length) {
    list.innerHTML = '<div class="empty-state">No documents encrypted yet.</div>';
    countBadge.textContent = "0";
    return;
  }

  countBadge.textContent = data.documents.length;
  list.innerHTML = data.documents.map(d => `
    <div class="doc-item">
      <div class="ri-name">📄 ${d.document_id}</div>
      <div class="ri-meta">v${d.version} · ${d.plaintext_bytes}B plaintext · Recipients: ${d.recipients.join(", ")}</div>
      <div class="ri-meta" style="color:var(--text-dim);margin-top:2px">${shortHash(d.hash)}</div>
    </div>
  `).join("");
}

// ── Decryption ────────────────────────────────────────────────────────────

async function populateDecryptionSelects() {
  const [rData, dData] = await Promise.all([api("/api/recipients"), api("/api/documents")]);

  const rSel = document.getElementById("dec-recipient");
  rSel.innerHTML = '<option value="">— Select recipient —</option>' +
    (rData.recipients || []).map(r => `<option value="${r.name}">${r.name} (${r.key_id})</option>`).join("");

  const dSel = document.getElementById("dec-document");
  dSel.innerHTML = '<option value="">— Select document —</option>' +
    (dData.documents || []).map(d => `<option value="${d.document_id}">${d.document_id} (v${d.version})</option>`).join("");
}

function setPipelineStep(num, status) {
  const el = document.getElementById(`ps-${num}`);
  if (!el) return;
  el.classList.remove("done", "active");
  el.querySelector(".ps-status").className = `ps-status ${status}`;
  if (status === "done") {
    el.classList.add("done");
    el.querySelector(".ps-status").textContent = "✓";
  } else if (status === "active") {
    el.classList.add("active");
    el.querySelector(".ps-status").textContent = "⚡";
  } else {
    el.querySelector(".ps-status").textContent = "⏳";
  }
}

function resetPipeline() {
  for (let i = 1; i <= 6; i++) setPipelineStep(i, "pending");
}

async function requestDecryption() {
  const recipient = document.getElementById("dec-recipient").value;
  const document_id = document.getElementById("dec-document").value;
  const profile = document.getElementById("dec-profile").value;

  if (!recipient) { toast("Select a recipient", "error"); return; }
  if (!document_id) { toast("Select a document", "error"); return; }

  resetPipeline();
  const box = document.getElementById("dec-result");
  box.classList.remove("hidden");
  box.className = "result-box";
  box.innerHTML = "⚡ Executing pipeline...";

  // Animate pipeline steps
  const delay = ms => new Promise(r => setTimeout(r, ms));
  const stepLabels = ["ML-KEM Decapsulation", "In-Memory Decryption", "Tardos Fingerprint", "ZWC Watermark", "ML-DSA Signing", "Ledger Commit"];
  const animatePipeline = async (doneUpTo) => {
    for (let i = 1; i <= 6; i++) {
      if (i < doneUpTo) setPipelineStep(i, "done");
      else if (i === doneUpTo) setPipelineStep(i, "active");
      else setPipelineStep(i, "pending");
    }
  };

  // Kick off animation while waiting for response
  let step = 1;
  const animInterval = setInterval(() => {
    if (step <= 6) { animatePipeline(step); step++; }
    else clearInterval(animInterval);
  }, 350);

  showLoading(`Decrypting for ${recipient}...`);
  const data = await api("/api/decrypt", "POST", { recipient, document_id, profile });
  clearInterval(animInterval);
  hideLoading();

  if (data.success) {
    for (let i = 1; i <= 6; i++) setPipelineStep(i, "done");
    state.lastWatermarkId = data.watermark_id;
    box.className = "result-box success";
    box.innerHTML =
      resultSection("Decryption") +
      resultRow("Recipient", data.recipient) +
      resultRow("Document", data.document_id) +
      resultSection("Fingerprint") +
      resultRow("Watermark ID", data.watermark_id, "green") +
      resultRow("Session ID", shortHash(data.session_id)) +
      resultRow("Hidden ZWC chars", data.zwc_count) +
      resultSection("Signing") +
      resultRow("Signature valid", data.signature_valid ? "✓ Yes" : "✗ No", data.signature_valid ? "green" : "red") +
      resultRow("Signature size", `${data.signature_bytes} bytes`) +
      resultSection("Ledger") +
      resultRow("Block ID", `#${data.block_id}`, "green") +
      resultRow("Transaction ID", data.transaction_id) +
      resultRow("Commit time", data.commit_time) +
      resultSection("Output Hash") +
      resultRow("SHA3-256", shortHash(data.output_hash)) +
      `<div class="result-section">Document Preview (visible text)</div>
       <div style="color:var(--text-muted);font-size:11px;padding:6px 0;line-height:1.6">${data.watermarked_preview.replace(/</g,"&lt;")}</div>`;
    toast("Decryption pipeline complete", "success");
  } else {
    resetPipeline();
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
  loadStatus();
}

// ── Ledger ────────────────────────────────────────────────────────────────

async function loadLedger() {
  const [chainData, eventsData] = await Promise.all([
    api("/api/ledger/chain"),
    api("/api/ledger/events"),
  ]);

  if (chainData.success) {
    document.getElementById("ledger-height").textContent = chainData.chain_height;
    const intEl = document.getElementById("ledger-integrity");
    intEl.textContent = chainData.chain_valid ? "✓ Valid" : "✗ Compromised";
    intEl.style.color = chainData.chain_valid ? "var(--green)" : "var(--red)";
  }

  const container = document.getElementById("ledger-table-container");
  if (!eventsData.success || !eventsData.events.length) {
    container.innerHTML = '<div class="empty-state" style="padding:40px">No events committed yet.</div>';
    return;
  }

  container.innerHTML = `
    <div style="overflow-x:auto">
    <table class="ledger-table">
      <thead>
        <tr>
          <th>Block</th>
          <th>Commit Time</th>
          <th>Document ID</th>
          <th>Watermark ID</th>
          <th>Recipient Key</th>
          <th>Version</th>
          <th>Profile</th>
          <th>Output Hash</th>
        </tr>
      </thead>
      <tbody>
        ${eventsData.events.map(e => `
          <tr>
            <td class="block-id">#${e.block_id}</td>
            <td>${e.commit_time.replace("T"," ").slice(0,19)}</td>
            <td>${e.document_id || "genesis"}</td>
            <td class="wm-id">${e.watermark_id || "—"}</td>
            <td class="key-id">${e.recipient_key_id || "—"}</td>
            <td>${e.document_version || "—"}</td>
            <td>${e.watermark_profile || "—"}</td>
            <td>${e.output_hash || "—"}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    </div>
  `;
}

// ── Forensics ─────────────────────────────────────────────────────────────

async function extractWatermark() {
  const text = document.getElementById("forensic-leaked-text").value;
  if (!text.trim()) { toast("Enter leaked document text", "error"); return; }

  showLoading("Extracting ZWC watermark payload...");
  const data = await api("/api/forensic/extract", "POST", { text });
  hideLoading();

  const box = document.getElementById("extract-result");
  if (data.success) {
    const ok = data.result === "WATERMARK_RECOVERED";
    box.className = `result-box ${ok ? "success" : "error"}`;

    let html = resultRow("Result", data.result, ok ? "green" : "yellow");
    if (data.leaked_hash) html += resultRow("Leaked Hash", shortHash(data.leaked_hash));
    if (data.zwc_count)   html += resultRow("ZWC Chars", data.zwc_count);
    if (data.watermark_id) {
      html += resultRow("Watermark ID", data.watermark_id, "green");
      state.lastWatermarkId = data.watermark_id;
      // Pre-fill verify tab
      document.getElementById("verify-wm-id").value = data.watermark_id;
    }
    if (data.leaked_hash) {
      state.lastLeakedHash = data.leaked_hash;
      document.getElementById("verify-leaked-hash").value = data.leaked_hash;
    }
    if (data.watermark_data && Object.keys(data.watermark_data).length) {
      html += resultSection("Watermark Payload");
      for (const [k, v] of Object.entries(data.watermark_data)) {
        html += resultRow(k, typeof v === "string" ? v : JSON.stringify(v));
      }
    }
    if (data.reason) html += resultRow("Reason", data.reason);
    box.innerHTML = html;
    toast(ok ? "Watermark extracted!" : "No watermark found", ok ? "success" : "error");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
  }
}

async function simulateLeak() {
  const wmId = document.getElementById("sim-watermark-id").value.trim();
  showLoading("Simulating document leak...");
  const data = await api("/api/forensic/simulate_leak", "POST", { watermark_id: wmId });
  hideLoading();

  const simBox = document.getElementById("sim-result");
  const preview = document.getElementById("leak-preview");
  simBox.classList.remove("hidden");

  if (data.success) {
    simBox.className = "result-box success";
    simBox.innerHTML =
      resultRow("Watermark ID", data.watermark_id, "green") +
      resultRow("Total chars", data.char_count) +
      resultRow("ZWC chars", data.zwc_count, "yellow") +
      resultRow("Status", "⚠ Document leaked!", "red");

    preview.textContent = data.visible_preview;

    // Put the leaked text into the extraction tab
    document.getElementById("forensic-leaked-text").value = data.leaked_text;
    state.lastWatermarkId = data.watermark_id;
    toast("Leak simulated — switch to Extract tab", "success");
  } else {
    simBox.className = "result-box error";
    simBox.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
}

async function verifyEvidence() {
  const watermark_id = document.getElementById("verify-wm-id").value.trim();
  const document_hash = document.getElementById("verify-doc-hash").value.trim();
  const leaked_hash = document.getElementById("verify-leaked-hash").value.trim();

  if (!watermark_id) { toast("Enter a watermark ID", "error"); return; }

  showLoading("Running cryptographic verification pipeline...");
  const data = await api("/api/forensic/verify", "POST", {
    watermark_id,
    document_hash: document_hash || null,
    leaked_hash: leaked_hash || null,
  });
  hideLoading();

  const box = document.getElementById("verify-result");
  if (data.success) {
    const verified = data.result === "CRYPTOGRAPHICALLY VERIFIED";
    box.className = `result-box ${verified ? "success" : "error"}`;

    let html =
      resultSection("Verdict") +
      resultRow("Result", data.result, verified ? "green" : "red") +
      resultRow("Confidence", (data.confidence * 100).toFixed(0) + "%", verified ? "green" : "yellow") +
      resultRow("Timestamp", data.verification_timestamp);

    if (data.attributed_name) {
      html += resultSection("Attribution");
      html += resultRow("Attributed To", data.attributed_name, "red");
      html += resultRow("Key ID", data.recipient_key_id, "yellow");
      html += `<div style="color:var(--text-muted);font-size:10.5px;padding:8px 0;line-height:1.6">
        ⚠ This establishes that <strong style="color:var(--red)">${data.attributed_name}</strong>'s credential
        authenticated the decryption event. It does not claim intentional leaking.
      </div>`;
    }

    if (data.steps && data.steps.length) {
      html += resultSection("Verification Steps");
      for (const step of data.steps) {
        const icon = step.status === "PASSED" ? "✓" : step.status === "FAILED" ? "✗" : "–";
        const cls  = step.status === "PASSED" ? "green" : step.status === "FAILED" ? "red" : "";
        html += resultRow(`${icon} ${step.step}`, step.status, cls);
        if (step.reason) html += `<div style="color:var(--text-muted);font-size:10px;padding:2px 0 4px 6px">  ↳ ${step.reason}</div>`;
      }
    }

    box.innerHTML = html;
    toast(verified ? "Cryptographically verified!" : data.result, verified ? "success" : "error");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
}

// ── Demo ──────────────────────────────────────────────────────────────────

function colorizeLogTag(entry) {
  return entry.replace(/^\[([A-Z]+)\]/, (_, tag) => {
    return `<span class="tag tag-${tag.toLowerCase()}">[${tag}]</span>`;
  });
}

async function runDemo() {
  const btn = document.getElementById("run-demo-btn");
  btn.disabled = true;
  btn.textContent = "⏳ Running...";

  const logEl = document.getElementById("demo-log");
  const logEntries = document.getElementById("demo-log-entries");
  const resultEl = document.getElementById("demo-result");
  logEl.classList.remove("hidden");
  resultEl.classList.add("hidden");
  logEntries.innerHTML = "";

  showLoading("Running full MVP demo...");
  const data = await api("/api/demo/run", "POST");
  hideLoading();

  btn.disabled = false;
  btn.textContent = "▶ Run Again";

  if (!data.success) {
    logEntries.innerHTML = `<div class="demo-log-entry" style="color:var(--red)">Error: ${data.error}</div>`;
    toast(data.error, "error");
    return;
  }

  // Render log
  document.getElementById("demo-log-count").textContent = data.log.length;
  logEntries.innerHTML = data.log.map(line =>
    `<div class="demo-log-entry">${colorizeLogTag(escapeHtml(line))}</div>`
  ).join("");

  // Render verdict
  const verified = data.result === "CRYPTOGRAPHICALLY VERIFIED";
  const verdictEl = document.getElementById("demo-verdict");
  verdictEl.style.borderColor = verified ? "var(--green)" : "var(--yellow)";
  verdictEl.innerHTML = `
    <div class="verdict-icon">${verified ? "🔍✅" : "⚠️"}</div>
    <div class="verdict-title" style="color:${verified ? "var(--green)" : "var(--yellow)"}">${data.result}</div>
    <div class="verdict-sub">Confidence: ${(data.confidence * 100).toFixed(0)}%</div>
    ${verified ? `
    <div class="verdict-detail">
      Watermark ID: ${data.watermark_id}<br>
      Attributed to: <span style="color:var(--red);font-weight:700">${data.leaker}</span><br>
      Key ID: ${data.attributed_key}<br>
      Chain height: ${data.chain_height} blocks
    </div>
    ` : ""}
  `;

  // Render steps table
  const stepsEl = document.getElementById("demo-steps-table");
  if (data.steps && data.steps.length) {
    stepsEl.innerHTML = `
      <div class="dst-header">Verification Steps</div>
      ${data.steps.map(step => {
        const icon = step.status === "PASSED" ? "✅" : step.status === "FAILED" ? "❌" : "⏭";
        const cls  = step.status === "PASSED" ? "passed" : step.status === "FAILED" ? "failed" : "skipped";
        return `<div class="dst-row">
          <span class="dst-icon">${icon}</span>
          <span class="dst-step">${step.step}</span>
          <span class="dst-status ${cls}">${step.status}</span>
        </div>`;
      }).join("")}
    `;
  }

  resultEl.classList.remove("hidden");
  loadStatus();
  toast("Demo complete!", "success");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── Reset ─────────────────────────────────────────────────────────────────

async function resetSystem() {
  if (!confirm("Reset all in-memory state? This will clear all recipients, documents, and ledger data.")) return;
  showLoading("Resetting system...");
  const data = await api("/api/reset", "POST");
  hideLoading();
  if (data.success) {
    toast("System reset", "success");
    loadStatus();
    loadRecipients();
    loadDocuments();
  }
}

// ── Init ──────────────────────────────────────────────────────────────────

(async function init() {
  await loadStatus();
})();

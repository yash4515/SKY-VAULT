/* SKY-VAULT Frontend JavaScript */
"use strict";

// State
const state = {
  lastWatermarkId: null,
  lastDocHash: null,
  lastLeakedHash: null,
  customDomain: "skyvault.internal",
};

// Utilities

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  return res.json();
}

function showLoading(text = "Processing...") {
  const el = document.getElementById("loading-text");
  if (el) el.textContent = text;
  const overlay = document.getElementById("loading");
  if (overlay) overlay.classList.remove("hidden");
}

function hideLoading() {
  const overlay = document.getElementById("loading");
  if (overlay) overlay.classList.add("hidden");
}

function toast(msg, type = "info") {
  const el = document.getElementById("toast");
  if (!el) return;
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
  return h.length > 48 ? h.slice(0, 48) + "..." : h;
}

// Tab Navigation

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
  if (tabId === "documents") loadDocuments();
  if (tabId === "decryption") populateDecryptionSelects();
  if (tabId === "ledger") loadLedger();
  if (tabId === "domain") loadDomain();
}

document.querySelectorAll(".nav-btn[data-tab]").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// Forensics sub-tabs

document.querySelectorAll(".ftab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".ftab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".ftab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    const target = document.getElementById(`ftab-${btn.dataset.ftab}`);
    if (target) target.classList.add("active");
  });
});

// Status & Telemetry

async function loadStatus() {
  try {
    const data = await api("/api/status");
    if (!data.success) return;

    const rEl = document.getElementById("stat-recipients");
    const dEl = document.getElementById("stat-documents");
    const hEl = document.getElementById("stat-chain-height");
    const vEl = document.getElementById("stat-chain-valid");

    if (rEl) rEl.textContent = data.recipients.length;
    if (dEl) dEl.textContent = data.documents.length;
    if (hEl) hEl.textContent = data.chain_height;
    if (vEl) {
      vEl.textContent = data.chain_valid ? "VALID" : "ERROR";
      vEl.style.color = data.chain_valid ? "var(--green)" : "var(--red)";
    }

    const mEl = document.getElementById("info-mode");
    const kEl = document.getElementById("info-kem");
    const sEl = document.getElementById("info-sig");

    if (mEl) mEl.textContent = data.mode;
    if (kEl) kEl.textContent = data.kem_algorithm;
    if (sEl) sEl.textContent = data.sig_algorithm;

    if (data.custom_domain) {
      state.customDomain = data.custom_domain;
      const navDom = document.getElementById("nav-domain-name");
      if (navDom) navDom.textContent = data.custom_domain;
    }

    const dot = document.querySelector(".status-dot");
    const txt = document.querySelector(".status-text");
    if (dot && txt) {
      dot.className = "status-dot online";
      txt.textContent = `${data.mode.includes("REAL") ? "PQC Active" : "Sim Mode"} | ${data.chain_height} blocks`;
    }
  } catch (e) {
    const dot = document.querySelector(".status-dot");
    const txt = document.querySelector(".status-text");
    if (dot && txt) {
      dot.className = "status-dot error";
      txt.textContent = "Offline / Connection Error";
    }
  }
}

// Custom Domain Management

async function loadDomain() {
  try {
    const data = await api("/api/domain");
    if (data.success) {
      state.customDomain = data.domain;
      const inp = document.getElementById("custom-domain-input");
      const status = document.getElementById("domain-binding-status");
      const navDom = document.getElementById("nav-domain-name");
      const nginx = document.getElementById("nginx-domain-display");
      const hosts = document.getElementById("hosts-domain-display");

      if (inp) inp.value = data.domain;
      if (status) status.textContent = data.status || "CONFIGURED";
      if (navDom) navDom.textContent = data.domain;
      if (nginx) nginx.textContent = data.domain;
      if (hosts) hosts.textContent = data.domain;
    }
  } catch (e) {
    console.error("Failed to load custom domain:", e);
  }
}

async function updateCustomDomain() {
  const inp = document.getElementById("custom-domain-input");
  const domain = (inp ? inp.value : "").trim();
  if (!domain) {
    toast("Please enter a valid domain name", "error");
    return;
  }

  showLoading(`Binding domain to ${domain}...`);
  const data = await api("/api/domain", "POST", { domain });
  hideLoading();

  const box = document.getElementById("domain-result");
  if (data.success) {
    state.customDomain = data.domain;
    const navDom = document.getElementById("nav-domain-name");
    const nginx = document.getElementById("nginx-domain-display");
    const hosts = document.getElementById("hosts-domain-display");
    if (navDom) navDom.textContent = data.domain;
    if (nginx) nginx.textContent = data.domain;
    if (hosts) hosts.textContent = data.domain;

    if (box) {
      box.classList.remove("hidden");
      box.className = "result-box success";
      box.innerHTML =
        resultRow("Custom Domain", data.domain, "green") +
        resultRow("Status", data.status, "green") +
        resultRow("Network Policy", "Air-Gapped Private FQDN") +
        resultRow("Host Header", window.location.host);
    }
    toast(data.message, "success");
  } else {
    if (box) {
      box.classList.remove("hidden");
      box.className = "result-box error";
      box.innerHTML = resultRow("Error", data.error, "red");
    }
    toast(data.error, "error");
  }
}

// Recipients

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
      resultRow("Identity Name", data.name) +
      resultRow("Key ID", data.key_id, "green") +
      resultRow("ML-KEM-768 Public Key", `${data.kem_pub_bytes} bytes`) +
      resultRow("ML-DSA-65 Public Key", `${data.sig_pub_bytes} bytes`) +
      resultRow("Status", "REGISTERED", "green");
    document.getElementById("reg-name").value = "";
    loadRecipients();
    toast(`Recipient ${name} registered`, "success");
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
    list.innerHTML = '<div class="empty-state">No recipients registered in local directory.</div>';
    countBadge.textContent = "0";
    return;
  }

  countBadge.textContent = data.recipients.length;
  list.innerHTML = data.recipients.map(r => `
    <div class="recipient-item">
      <div class="ri-name">${escapeHtml(r.name)}</div>
      <div class="ri-meta">
        <span class="ri-keyid">${r.key_id}</span> |
        ML-KEM: ${r.kem_pub_bytes}B | ML-DSA: ${r.sig_pub_bytes}B
      </div>
    </div>
  `).join("");
}

// Documents

async function encryptDocument() {
  const text = document.getElementById("doc-text").value.trim();
  const version = parseInt(document.getElementById("doc-version").value) || 1;
  if (!text) { toast("Enter document content", "error"); return; }

  showLoading("Generating DEK, encrypting with AES-256-GCM, wrapping via ML-KEM...");
  const data = await api("/api/encrypt", "POST", { text, version });
  hideLoading();

  const box = document.getElementById("enc-result");
  box.classList.remove("hidden");
  if (data.success) {
    state.lastDocHash = data.document_hash;
    box.className = "result-box success";
    box.innerHTML =
      resultSection("Document Payload") +
      resultRow("Document ID", data.document_id, "green") +
      resultRow("Version", data.version) +
      resultRow("Plaintext Size", `${data.plaintext_bytes} bytes`) +
      resultRow("Ciphertext Size", `${data.encrypted_bytes} bytes`) +
      resultSection("Post-Quantum Key Encapsulation") +
      resultRow("Algorithm", "ML-KEM-768 (DEK Encapsulation)") +
      resultRow("Recipients Bound", data.recipients_wrapped.join(", ")) +
      resultSection("Cryptographic Digest") +
      resultRow("SHA3-256", shortHash(data.document_hash));
    loadDocuments();
    toast("Document encrypted with AES-256-GCM", "success");
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
      <div class="ri-name">${escapeHtml(d.document_id)}</div>
      <div class="ri-meta">v${d.version} | ${d.plaintext_bytes}B plaintext | Recipients: ${d.recipients.join(", ")}</div>
      <div class="ri-meta" style="color:var(--text-dim);margin-top:2px">${shortHash(d.hash)}</div>
    </div>
  `).join("");
}

// Decryption

async function populateDecryptionSelects() {
  const [rData, dData] = await Promise.all([api("/api/recipients"), api("/api/documents")]);

  const rSel = document.getElementById("dec-recipient");
  rSel.innerHTML = '<option value="">Select recipient...</option>' +
    (rData.recipients || []).map(r => `<option value="${r.name}">${r.name} (${r.key_id})</option>`).join("");

  const dSel = document.getElementById("dec-document");
  dSel.innerHTML = '<option value="">Select document...</option>' +
    (dData.documents || []).map(d => `<option value="${d.document_id}">${d.document_id} (v${d.version})</option>`).join("");
}

function setPipelineStep(num, status) {
  const el = document.getElementById(`ps-${num}`);
  if (!el) return;
  el.classList.remove("done", "active");
  const statEl = el.querySelector(".ps-status");
  statEl.className = `ps-status ${status}`;
  if (status === "done") {
    el.classList.add("done");
    statEl.textContent = "DONE";
  } else if (status === "active") {
    el.classList.add("active");
    statEl.textContent = "ACTIVE";
  } else {
    statEl.textContent = "PENDING";
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
  box.innerHTML = "Executing cryptographic pipeline in RAM...";

  let step = 1;
  const animInterval = setInterval(() => {
    if (step <= 6) {
      for (let i = 1; i <= 6; i++) {
        if (i < step) setPipelineStep(i, "done");
        else if (i === step) setPipelineStep(i, "active");
        else setPipelineStep(i, "pending");
      }
      step++;
    } else {
      clearInterval(animInterval);
    }
  }, 250);

  showLoading(`Executing secure decryption for ${recipient}...`);
  const data = await api("/api/decrypt", "POST", { recipient, document_id, profile });
  clearInterval(animInterval);
  hideLoading();

  if (data.success) {
    for (let i = 1; i <= 6; i++) setPipelineStep(i, "done");
    state.lastWatermarkId = data.watermark_id;
    box.className = "result-box success";
    box.innerHTML =
      resultSection("Decryption Context") +
      resultRow("Recipient Identity", data.recipient) +
      resultRow("Document ID", data.document_id) +
      resultSection("Forensic Fingerprint") +
      resultRow("Watermark ID", data.watermark_id, "green") +
      resultRow("Session ID", shortHash(data.session_id)) +
      resultRow("Hidden ZWC Chars", data.zwc_count) +
      resultSection("ML-DSA Event Signing") +
      resultRow("Signature Status", data.signature_valid ? "VALID" : "INVALID", data.signature_valid ? "green" : "red") +
      resultRow("Signature Digest", `${data.signature_bytes} bytes (ML-DSA-65)`) +
      resultSection("Permissioned Ledger Commit") +
      resultRow("Block Height", `#${data.block_id}`, "green") +
      resultRow("Transaction ID", data.transaction_id) +
      resultRow("Commit Timestamp", data.commit_time) +
      resultSection("Output Hash Binding") +
      resultRow("SHA3-256", shortHash(data.output_hash)) +
      `<div class="result-section">Document Preview (Visible Plaintext)</div>
       <div style="color:var(--text-muted);font-size:11px;padding:6px 0;line-height:1.6;font-family:var(--mono)">${escapeHtml(data.watermarked_preview)}</div>`;
    toast("Decryption and watermarking complete", "success");
  } else {
    resetPipeline();
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
  loadStatus();
}

// Ledger

async function loadLedger() {
  const [chainData, eventsData] = await Promise.all([
    api("/api/ledger/chain"),
    api("/api/ledger/events"),
  ]);

  if (chainData.success) {
    const hEl = document.getElementById("ledger-height");
    const intEl = document.getElementById("ledger-integrity");
    if (hEl) hEl.textContent = chainData.chain_height;
    if (intEl) {
      intEl.textContent = chainData.chain_valid ? "VALID" : "COMPROMISED";
      intEl.style.color = chainData.chain_valid ? "var(--green)" : "var(--red)";
    }
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
            <td>${escapeHtml(e.document_id || "genesis")}</td>
            <td class="wm-id">${escapeHtml(e.watermark_id || "--")}</td>
            <td class="key-id">${escapeHtml(e.recipient_key_id || "--")}</td>
            <td>${e.document_version || "--"}</td>
            <td>${escapeHtml(e.watermark_profile || "--")}</td>
            <td>${escapeHtml(shortHash(e.output_hash) || "--")}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    </div>
  `;
}

// Forensics

async function extractWatermark() {
  const text = document.getElementById("forensic-leaked-text").value;
  if (!text.trim()) { toast("Enter leaked document text", "error"); return; }

  showLoading("Extracting steganographic watermark payload...");
  const data = await api("/api/forensic/extract", "POST", { text });
  hideLoading();

  const box = document.getElementById("extract-result");
  if (data.success) {
    const ok = data.result === "WATERMARK_RECOVERED";
    box.className = `result-box ${ok ? "success" : "error"}`;

    let html = resultRow("Extraction Result", data.result, ok ? "green" : "yellow");
    if (data.leaked_hash) html += resultRow("Leaked Hash", shortHash(data.leaked_hash));
    if (data.zwc_count)   html += resultRow("ZWC Stego Chars", data.zwc_count);
    if (data.watermark_id) {
      html += resultRow("Watermark ID", data.watermark_id, "green");
      state.lastWatermarkId = data.watermark_id;
      const vWm = document.getElementById("verify-wm-id");
      if (vWm) vWm.value = data.watermark_id;
    }
    if (data.leaked_hash) {
      state.lastLeakedHash = data.leaked_hash;
      const vLh = document.getElementById("verify-leaked-hash");
      if (vLh) vLh.value = data.leaked_hash;
    }
    if (data.watermark_data && Object.keys(data.watermark_data).length) {
      html += resultSection("Decoded Payload Content");
      for (const [k, v] of Object.entries(data.watermark_data)) {
        html += resultRow(k, typeof v === "string" ? escapeHtml(v) : JSON.stringify(v));
      }
    }
    if (data.reason) html += resultRow("Diagnostic", escapeHtml(data.reason));
    box.innerHTML = html;
    toast(ok ? "Watermark payload recovered" : "Watermark extraction inconclusive", ok ? "success" : "error");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
  }
}

async function simulateLeak() {
  const wmId = document.getElementById("sim-watermark-id").value.trim();
  showLoading("Simulating unauthorized leak event...");
  const data = await api("/api/forensic/simulate_leak", "POST", { watermark_id: wmId });
  hideLoading();

  const simBox = document.getElementById("sim-result");
  const preview = document.getElementById("leak-preview");
  simBox.classList.remove("hidden");

  if (data.success) {
    simBox.className = "result-box success";
    simBox.innerHTML =
      resultRow("Watermark ID", data.watermark_id, "green") +
      resultRow("Total Characters", data.char_count) +
      resultRow("Zero-Width Stego Chars", data.zwc_count, "yellow") +
      resultRow("Distribution Status", "Leaked copy loaded", "red");

    if (preview) preview.textContent = data.visible_preview;

    const fText = document.getElementById("forensic-leaked-text");
    if (fText) fText.value = data.leaked_text;
    state.lastWatermarkId = data.watermark_id;
    toast("Leak simulated : switch to Extract tab", "success");
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

  showLoading("Executing full cryptographic evidence verification...");
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
      resultSection("Cryptographic Verdict") +
      resultRow("Verification Result", data.result, verified ? "green" : "red") +
      resultRow("Confidence Score", (data.confidence * 100).toFixed(0) + "%", verified ? "green" : "yellow") +
      resultRow("Timestamp", data.verification_timestamp);

    if (data.attributed_name) {
      html += resultSection("Attribution Finding");
      html += resultRow("Attributed Identity", data.attributed_name, "red");
      html += resultRow("Recipient Key ID", data.recipient_key_id, "yellow");
      html += `<div style="color:var(--text-muted);font-size:10.5px;padding:8px 0;line-height:1.6">
        [NOTE] This mathematically establishes that the private credential of <strong>${escapeHtml(data.attributed_name)}</strong>
        authenticated the decryption event. It certifies credential usage without claiming physical human intent.
      </div>`;
    }

    if (data.steps && data.steps.length) {
      html += resultSection("Verification Step Results");
      for (const step of data.steps) {
        const tag = step.status === "PASSED" ? "[PASS]" : step.status === "FAILED" ? "[FAIL]" : "[SKIP]";
        const cls = step.status === "PASSED" ? "green" : step.status === "FAILED" ? "red" : "";
        html += resultRow(`${tag} ${step.step}`, step.status, cls);
        if (step.reason) html += `<div style="color:var(--text-muted);font-size:10px;padding:2px 0 4px 6px">  -> ${escapeHtml(step.reason)}</div>`;
      }
    }

    box.innerHTML = html;
    toast(verified ? "Cryptographically verified" : data.result, verified ? "success" : "error");
  } else {
    box.className = "result-box error";
    box.innerHTML = resultRow("Error", data.error, "red");
    toast(data.error, "error");
  }
}

// Demo Execution

function colorizeLogTag(entry) {
  return entry.replace(/^\[([A-Z]+)\]/, (_, tag) => {
    return `<span class="tag tag-${tag.toLowerCase()}">[${tag}]</span>`;
  });
}

async function runDemo() {
  const btn = document.getElementById("run-demo-btn");
  btn.disabled = true;
  btn.textContent = "Executing Pipeline...";

  const logEl = document.getElementById("demo-log");
  const logEntries = document.getElementById("demo-log-entries");
  const resultEl = document.getElementById("demo-result");
  logEl.classList.remove("hidden");
  resultEl.classList.add("hidden");
  logEntries.innerHTML = "";

  showLoading("Executing full 15-phase MVP demonstration...");
  const data = await api("/api/demo/run", "POST");
  hideLoading();

  btn.disabled = false;
  btn.textContent = "Run Again";

  if (!data.success) {
    logEntries.innerHTML = `<div class="demo-log-entry" style="color:var(--red)">Error: ${escapeHtml(data.error)}</div>`;
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
    <span class="verdict-tag ${verified ? 'verified' : 'unverified'}">${escapeHtml(data.result)}</span>
    <div class="verdict-title">${verified ? "Cryptographic Attribution Established" : "Attribution Inconclusive"}</div>
    <div class="verdict-sub">Confidence Score: ${(data.confidence * 100).toFixed(0)}%</div>
    ${verified ? `
    <div class="verdict-detail">
      Watermark ID: ${escapeHtml(data.watermark_id)}<br>
      Attributed Credential: <strong style="color:var(--red)">${escapeHtml(data.leaker)}</strong><br>
      Recipient Key ID: ${escapeHtml(data.attributed_key)}<br>
      Ledger Height: ${data.chain_height} blocks
    </div>
    ` : ""}
  `;

  // Render steps table
  const stepsEl = document.getElementById("demo-steps-table");
  if (data.steps && data.steps.length) {
    stepsEl.innerHTML = `
      <div class="dst-header">Cryptographic Verification Steps</div>
      ${data.steps.map(step => {
        const cls = step.status === "PASSED" ? "passed" : step.status === "FAILED" ? "failed" : "skipped";
        return `<div class="dst-row">
          <span class="dst-tag ${cls}">[${step.status}]</span>
          <span class="dst-step">${escapeHtml(step.step)}</span>
          <span class="dst-status ${cls}">${step.status}</span>
        </div>`;
      }).join("")}
    `;
  }

  resultEl.classList.remove("hidden");
  loadStatus();
  toast("MVP pipeline execution complete", "success");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Reset System

async function resetSystem() {
  if (!confirm("Reset in-memory state? This will purge all active recipients, documents, and ledger blocks.")) return;
  showLoading("Resetting system state...");
  const data = await api("/api/reset", "POST");
  hideLoading();
  if (data.success) {
    toast("System state reset", "success");
    loadStatus();
    loadRecipients();
    loadDocuments();
    loadLedger();
  }
}

// Initialization

(async function init() {
  await loadStatus();
  await loadDomain();
})();

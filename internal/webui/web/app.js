(function () {
  const POLL_MS = 2000;
  let meta = null;
  let rulesDraft = [];
  let editable = false;

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
    });
  });

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      const t = await r.text();
      throw new Error(t || r.statusText);
    }
    if (r.status === 204) return null;
    return r.json();
  }

  function fmtBytes(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
    if (n >= 1e6) return (n / 1e6).toFixed(2) + " MB";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
    return String(n);
  }

  function renderStatus(st) {
    editable = st.policy_editable;
    document.getElementById("policy-note").textContent = st.policy_note || "";
    const cards = [
      ["Czas pracy", Math.floor(st.uptime_sec) + " s"],
      ["Pakiety/s", st.packets_per_s.toFixed(1)],
      ["Aktywne przepływy", st.active_flows],
      ["Dostarczone", st.capture.Delivered],
      ["Drop jądra", st.capture.KernelDropped],
      ["Enforce applied", st.enforcer.Applied],
    ];
    document.getElementById("status-cards").innerHTML = cards
      .map(([l, v]) => `<div class="card"><div class="label">${l}</div><div class="value">${v}</div></div>`)
      .join("");
    const hitsBody = document.querySelector("#hits-table tbody");
    hitsBody.innerHTML = Object.entries(st.rule_hits || {})
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, n]) => `<tr><td>${escapeHtml(name)}</td><td>${n}</td></tr>`)
      .join("") || "<tr><td colspan=2>—</td></tr>";
    document.getElementById("btn-apply").disabled = !editable;
    document.getElementById("btn-save").disabled = !editable;
    document.getElementById("btn-add-rule").disabled = !editable;
    document.getElementById("rules-readonly").classList.toggle("hidden", editable);
  }

  function renderSummary(rows) {
    const tbody = document.querySelector("#summary-table tbody");
    tbody.innerHTML = (rows || [])
      .map((r) => `<tr><td>${escapeHtml(r.Name)}</td><td>${r.Flows}</td><td>${r.Packets}</td><td>${fmtBytes(r.Bytes)}</td></tr>`)
      .join("") || "<tr><td colspan=4>—</td></tr>";
  }

  async function loadFlows() {
    const q = document.getElementById("flow-filter").value.trim();
    const url = "/api/flows?limit=200" + (q ? "&q=" + encodeURIComponent(q) : "");
    const flows = await api(url);
    const tbody = document.querySelector("#flows-table tbody");
    tbody.innerHTML = flows
      .map(
        (f) =>
          `<tr><td>${escapeHtml(f.Key)}</td><td>${escapeHtml(f.Protocol)}</td><td>${escapeHtml(f.Category)}</td><td>${f.Packets}</td><td>${fmtBytes(f.Bytes)}</td><td>${escapeHtml(f.PolicyRule || "—")}</td><td>${f.PolicyMark ? "0x" + f.PolicyMark.toString(16) : "—"}</td></tr>`
      )
      .join("") || "<tr><td colspan=7>—</td></tr>";
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderRulesEditor(data) {
    rulesDraft = JSON.parse(JSON.stringify(data.rules || []));
    const nft = data.nftables || {};
    document.getElementById("nft-info").textContent =
      `nftables (tylko odczyt): tabela=${nft.table || "dpi"}, hooki=${(nft.hooks || []).join(",")}, drop_mark=0x${(nft.drop_mark || 0).toString(16)}`;
    const root = document.getElementById("rules-editor");
    root.innerHTML = "";
    rulesDraft.forEach((rule, idx) => root.appendChild(ruleRow(rule, idx)));
  }

  function ruleRow(rule, idx) {
    const div = document.createElement("div");
    div.className = "rule-row";
    const matchKey = Object.keys(rule.match || {})[0] || "protocol";
    const matchVal = (rule.match || {})[matchKey] || "";
    div.innerHTML = `
      <input type="text" data-f="name" value="${escapeHtml(rule.name || "")}" placeholder="nazwa" ${editable ? "" : "disabled"}>
      <select data-f="matchKey" ${editable ? "" : "disabled"}>${matchFieldOptions(matchKey)}</select>
      <input type="text" data-f="matchVal" value="${escapeHtml(matchVal)}" placeholder="wartość" ${editable ? "" : "disabled"}>
      <select data-f="action" ${editable ? "" : "disabled"}><option value="mark" ${rule.action === "mark" ? "selected" : ""}>mark</option><option value="drop" ${rule.action === "drop" ? "selected" : ""}>drop</option></select>
      <input type="text" data-f="mark" value="${rule.mark ? "0x" + rule.mark.toString(16) : ""}" placeholder="mark" ${editable ? "" : "disabled"}>
      <button type="button" data-del ${editable ? "" : "disabled"}>Usuń</button>
    `;
    div.querySelector("[data-del]").addEventListener("click", () => {
      rulesDraft.splice(idx, 1);
      renderRulesEditor({ rules: rulesDraft, nftables: {} });
    });
    div.querySelectorAll("[data-f]").forEach((el) => {
      el.addEventListener("change", () => syncRuleFromRow(div, idx));
      el.addEventListener("input", () => syncRuleFromRow(div, idx));
    });
    return div;
  }

  function matchFieldOptions(selected) {
    const fields = (meta && meta.MatchFields) || ["protocol", "master", "app", "category"];
    return fields.map((f) => `<option value="${f}" ${f === selected ? "selected" : ""}>${f}</option>`).join("");
  }

  function parseMark(s) {
    s = (s || "").trim();
    if (!s) return 0;
    if (s.startsWith("0x") || s.startsWith("0X")) return parseInt(s, 16);
    return parseInt(s, 10);
  }

  function syncRuleFromRow(div, idx) {
    const name = div.querySelector('[data-f="name"]').value.trim();
    const matchKey = div.querySelector('[data-f="matchKey"]').value;
    const matchVal = div.querySelector('[data-f="matchVal"]').value.trim();
    const action = div.querySelector('[data-f="action"]').value;
    const mark = parseMark(div.querySelector('[data-f="mark"]').value);
    rulesDraft[idx] = {
      name,
      match: { [matchKey]: matchVal },
      action,
      mark: action === "mark" ? mark : 0,
    };
  }

  function collectRules() {
    document.querySelectorAll("#rules-editor .rule-row").forEach((div, idx) => syncRuleFromRow(div, idx));
    return rulesDraft;
  }

  document.getElementById("btn-add-rule").addEventListener("click", () => {
    rulesDraft.push({ name: "new-rule", match: { protocol: "DNS" }, action: "mark", mark: 0x10 });
    renderRulesEditor({ rules: rulesDraft });
  });

  document.getElementById("btn-apply").addEventListener("click", async () => {
    const msg = document.getElementById("rules-msg");
    msg.textContent = "";
    try {
      const rules = collectRules();
      await api("/api/rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules }),
      });
      msg.textContent = "Reguły zastosowane w locie.";
    } catch (e) {
      msg.textContent = "Błąd: " + e.message;
    }
  });

  document.getElementById("btn-save").addEventListener("click", async () => {
    const msg = document.getElementById("rules-msg");
    try {
      await api("/api/rules/save", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      msg.textContent = "Zapisano do pliku konfiguracji.";
    } catch (e) {
      msg.textContent = "Błąd zapisu: " + e.message;
    }
  });

  document.getElementById("flow-filter").addEventListener("input", () => loadFlows().catch(() => {}));

  async function tick() {
    try {
      const [st, summary, rules] = await Promise.all([
        api("/api/status"),
        api("/api/summary"),
        api("/api/rules"),
      ]);
      renderStatus(st);
      renderSummary(summary);
      if (!document.getElementById("rules-editor").children.length) {
        renderRulesEditor(rules);
      }
      if (document.getElementById("panel-flows").classList.contains("active")) {
        await loadFlows();
      }
    } catch (e) {
      console.error(e);
    }
  }

  api("/api/meta").then((m) => {
    meta = m;
    tick();
    setInterval(tick, POLL_MS);
  });
})();

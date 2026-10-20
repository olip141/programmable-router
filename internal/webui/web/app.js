(function () {
  const POLL_MS = 2000;
  const OBSERVED_REFRESH_MS = 10000;

  let meta = null;
  let editable = false;
  let networkLoaded = false;
  let netInfo = { qos: {}, routing: {} };
  let markHints = [];

  // Rules editor state. A draft rule is {name, conds: [{field, value}], action, mark}
  // where mark is the text typed by the user.
  let nft = {};
  let rulesDraft = [];
  let appliedJSON = "[]";
  let rulesLoaded = false;
  let ruleHits = {};
  let cardRefs = [];
  let lastFlows = [];
  let observedAt = 0;
  const observed = { protocol: new Set(), master: new Set(), app: new Set(), category: new Set(), host: new Set() };

  const FIELDS = {
    app: {
      label: "Aplikacja",
      short: "aplikacja",
      placeholder: "np. YouTube",
      hint: "Usługa rozpoznana przez nDPI, np. YouTube, Netflix, Google, WhatsApp.",
    },
    master: {
      label: "Protokół bazowy",
      short: "protokół bazowy",
      placeholder: "np. TLS",
      hint: "Protokół, którym płynie ruch, np. TLS, QUIC, HTTP, SSH, DNS.",
    },
    protocol: {
      label: "Pełna etykieta nDPI",
      short: "etykieta",
      placeholder: "np. TLS.YouTube",
      hint: "Dokładnie to, co w kolumnie „Protokół” przepływów, np. TLS.YouTube, DNS, BitTorrent.",
    },
    category: {
      label: "Kategoria",
      short: "kategoria",
      placeholder: "np. Media",
      hint: "Grupa usług nDPI, np. Media, Streaming, Web, Network, SocialNetwork.",
    },
    host: {
      label: "Host / SNI",
      short: "host",
      placeholder: "np. *.youtube.com",
      hint: "Nazwa z SNI, nagłówka Host lub zapytania DNS. Gwiazdka to wildcard: *.youtube.com obejmuje też youtube.com.",
    },
    risk: {
      label: "Ryzyko nDPI",
      short: "ryzyko",
      placeholder: "np. Unidirectional Traffic",
      hint: "Przepływ pasuje, jeśli nDPI zgłosiło dla niego to ryzyko.",
    },
    confidence: {
      label: "Pewność klasyfikacji",
      short: "pewność",
      placeholder: "np. DPI",
      hint: "Jak nDPI rozpoznało ruch: DPI = po treści pakietów, Match by port = tylko po numerze portu.",
    },
  };
  const FIELD_ORDER = ["app", "master", "protocol", "category", "host", "risk", "confidence"];

  // ---------- helpers ----------

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (k === "value") node.value = v;
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  }

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      const t = (await r.text()).trim();
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

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function hex(n) {
    return "0x" + Number(n).toString(16);
  }

  function parseMark(s) {
    s = String(s || "").trim();
    if (!s) return 0;
    if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    return NaN;
  }

  function hitsLabel(n) {
    const mod10 = n % 10;
    const mod100 = n % 100;
    if (n === 1) return "1 trafienie";
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return n + " trafienia";
    return n + " trafień";
  }

  function inList(list, value) {
    const v = String(value).toLowerCase();
    return (list || []).some((x) => x.toLowerCase() === v);
  }

  function setMsg(id, kind, text) {
    const m = document.getElementById(id);
    m.classList.remove("msg-ok", "msg-err");
    if (kind) m.classList.add("msg-" + kind);
    m.textContent = text;
  }

  function activateTab(name) {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "panel-" + name));
    if (name === "network") {
      if (!networkLoaded) loadNetworkPanels().catch(console.error);
      else loadInterfaces();
    }
    if (name === "rules") refreshObserved(true).catch(() => {});
    if (name === "flows") loadFlows().catch(() => {});
  }

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });

  // ---------- overview & flows ----------

  function renderStatus(st) {
    editable = st.policy_editable;
    document.getElementById("policy-note").textContent = st.policy_note || "";
    const cards = [
      ["Czas pracy", Math.floor(st.uptime_sec) + " s"],
      ["Pakiety/s", st.packets_per_s.toFixed(1)],
      ["Aktywne przepływy", st.active_flows],
      ["Dostarczone", st.capture.Delivered],
      ["Drop jądra", st.capture.KernelDropped],
      ["Zastosowane w nft", st.enforcer.Applied],
    ];
    document.getElementById("status-cards").innerHTML = cards
      .map(([l, v]) => `<div class="card"><div class="label">${l}</div><div class="value">${v}</div></div>`)
      .join("");
    const hitsBody = document.querySelector("#hits-table tbody");
    hitsBody.innerHTML = Object.entries(st.rule_hits || {})
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, n]) => `<tr><td>${escapeHtml(name)}</td><td>${n}</td></tr>`)
      .join("") || "<tr><td colspan=2>—</td></tr>";
    for (const id of ["btn-apply", "btn-save", "btn-add-rule", "btn-discard"]) {
      document.getElementById(id).disabled = !editable;
    }
    document.getElementById("rules-readonly").classList.toggle("hidden", editable);
    ruleHits = st.rule_hits || {};
    updateHits();
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
    lastFlows = await api(url);
    const tbody = document.querySelector("#flows-table tbody");
    tbody.innerHTML = lastFlows
      .map(
        (f, i) =>
          `<tr><td>${escapeHtml(f.Key)}</td><td>${escapeHtml(f.Protocol)}</td><td>${escapeHtml(f.Host || "—")}</td><td>${escapeHtml(f.Category)}</td><td>${escapeHtml(f.Confidence || "—")}</td><td>${escapeHtml((f.Risks || []).join(", ") || "—")}</td><td>${f.Packets}</td><td>${fmtBytes(f.Bytes)}</td><td>${escapeHtml(f.PolicyRule || "—")}</td><td>${f.PolicyMark ? hex(f.PolicyMark) : "—"}</td><td><button type="button" class="icon-btn" data-flow="${i}" title="Utwórz regułę z tego przepływu" ${editable ? "" : "disabled"}>＋</button></td></tr>`
      )
      .join("") || "<tr><td colspan=11>—</td></tr>";
    collectObserved(lastFlows);
  }

  document.querySelector("#flows-table tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-flow]");
    if (!btn || !editable) return;
    const f = lastFlows[Number(btn.dataset.flow)];
    if (f) createRuleFromFlow(f);
  });

  document.getElementById("flow-filter").addEventListener("input", () => loadFlows().catch(() => {}));

  // ---------- suggestions ----------

  function collectObserved(flows) {
    for (const f of flows || []) {
      if (f.Protocol && f.Protocol !== "Unknown") observed.protocol.add(f.Protocol);
      if (f.Master && f.Master !== "Unknown") observed.master.add(f.Master);
      if (f.App && f.App !== "Unknown") observed.app.add(f.App);
      if (f.Category && f.Category !== "Unknown") observed.category.add(f.Category);
      if (f.Host) {
        const host = f.Host.toLowerCase();
        observed.host.add(host);
        const labels = host.split(".");
        if (labels.length >= 3) observed.host.add("*." + labels.slice(1).join("."));
      }
    }
    renderDatalists();
  }

  async function refreshObserved(force) {
    if (!force && Date.now() - observedAt < OBSERVED_REFRESH_MS) return;
    observedAt = Date.now();
    collectObserved(await api("/api/flows?limit=500"));
  }

  function suggestions(field) {
    const m = meta || {};
    const base = {
      protocol: m.Protocols,
      master: m.Protocols,
      app: m.Protocols,
      category: m.Categories,
      host: [],
      risk: m.Risks,
      confidence: m.Confidences,
    }[field] || [];
    const seen = new Set();
    const out = [];
    for (const v of observed[field] || []) {
      if (!seen.has(v.toLowerCase())) {
        seen.add(v.toLowerCase());
        out.push([v, "w bieżącym ruchu"]);
      }
    }
    for (const v of base) {
      if (!seen.has(v.toLowerCase())) {
        seen.add(v.toLowerCase());
        out.push([v, ""]);
      }
    }
    return out;
  }

  function renderDatalists() {
    const root = document.getElementById("rule-datalists");
    for (const field of FIELD_ORDER) {
      let dl = document.getElementById("dl-" + field);
      if (!dl) {
        dl = el("datalist", { id: "dl-" + field });
        root.appendChild(dl);
      }
      dl.replaceChildren(...suggestions(field).map(([v, label]) => el("option", { value: v, label: label || undefined })));
    }
  }

  function markUsers(mark) {
    const out = [];
    for (const c of netInfo.qos.classes || []) if (c.mark === mark) out.push(`QoS „${c.name}” (${c.rate})`);
    for (const r of netInfo.routing.routes || []) if (r.mark === mark) out.push(`routing „${r.name}” → tabela ${r.table} przez ${r.gateway}`);
    return out;
  }

  function renderMarkHints(qos, routing) {
    netInfo = { qos: qos || {}, routing: routing || {} };
    markHints = [];
    (netInfo.qos.classes || []).forEach((c) => markHints.push([hex(c.mark), "QoS: " + c.name]));
    (netInfo.routing.routes || []).forEach((r) => markHints.push([hex(r.mark), "routing: " + r.name]));
    document.getElementById("mark-hints").replaceChildren(...markHints.map(([v, label]) => el("option", { value: v, label })));
    refreshValidation();
  }

  // ---------- rules model ----------

  function fromApi(rule) {
    return {
      name: rule.name || "",
      conds: Object.entries(rule.match || {}).map(([field, value]) => ({ field: field.toLowerCase(), value })),
      action: rule.action === "drop" ? "drop" : "mark",
      mark: rule.mark ? hex(rule.mark) : "",
    };
  }

  function toApi(d) {
    const match = {};
    for (const c of d.conds) {
      if (String(c.value).trim() !== "") match[c.field] = String(c.value).trim();
    }
    return {
      name: d.name.trim(),
      match,
      action: d.action,
      mark: d.action === "mark" ? parseMark(d.mark) || 0 : 0,
    };
  }

  function serialize(drafts) {
    return JSON.stringify(drafts.map(toApi));
  }

  function isDirty() {
    return rulesLoaded && serialize(rulesDraft) !== appliedJSON;
  }

  function loadRulesFromServer(payload) {
    nft = payload.nftables || {};
    rulesDraft = (payload.rules || []).map(fromApi);
    appliedJSON = serialize(rulesDraft);
    rulesLoaded = true;
    renderNftInfo();
    renderRulesEditor();
  }

  function uniqueName(base) {
    const names = new Set(rulesDraft.map((r) => r.name));
    if (!names.has(base)) return base;
    for (let i = 2; ; i++) if (!names.has(`${base}-${i}`)) return `${base}-${i}`;
  }

  function slug(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "regula";
  }

  function defaultMark() {
    return markHints.length ? markHints[0][0] : "";
  }

  function addRule(rule) {
    rulesDraft.push(rule);
    renderRulesEditor();
    focusRule(rulesDraft.length - 1);
  }

  function focusRule(idx) {
    const ref = cardRefs[idx];
    if (!ref) return;
    ref.card.scrollIntoView({ behavior: "smooth", block: "center" });
    ref.card.classList.add("flash");
    setTimeout(() => ref.card.classList.remove("flash"), 1200);
    ref.nameInput.focus();
    ref.nameInput.select();
  }

  function createRuleFromFlow(f) {
    let cond;
    if (f.App && f.App !== "Unknown") cond = { field: "app", value: f.App };
    else if (f.Master && f.Master !== "Unknown") cond = { field: "master", value: f.Master };
    else if (f.Host) cond = { field: "host", value: f.Host };
    else cond = { field: "protocol", value: f.Protocol };
    activateTab("rules");
    addRule({ name: uniqueName(slug(cond.value)), conds: [cond], action: "mark", mark: defaultMark() });
  }

  // ---------- validation ----------

  function validateRule(d, idx) {
    const res = { name: null, conds: d.conds.map(() => null), mark: null, rule: null, warnings: [] };
    const name = d.name.trim();
    if (!name) res.name = "Podaj nazwę reguły.";
    else if (rulesDraft.some((r, j) => j !== idx && r.name.trim() === name)) res.name = "Nazwa musi być unikalna.";

    if (d.conds.length === 0) res.rule = "Dodaj co najmniej jeden warunek.";
    const m = meta || {};
    const lists = { master: m.Protocols, app: m.Protocols, category: m.Categories, risk: m.Risks, confidence: m.Confidences };
    d.conds.forEach((c, i) => {
      const v = String(c.value).trim();
      if (!v) {
        res.conds[i] = "Podaj wartość.";
      } else if (lists[c.field] && lists[c.field].length && !inList(lists[c.field], v)) {
        res.conds[i] = "Nieznana wartość — wybierz z podpowiedzi.";
      } else if (c.field === "host" && /\s/.test(v)) {
        res.conds[i] = "Nazwa hosta nie może zawierać spacji.";
      } else if (c.field === "protocol" && m.Protocols && !v.split(".").every((p) => inList(m.Protocols, p))) {
        res.warnings.push(`Etykieta „${v}” nie wygląda na nazwę nDPI — sprawdź kolumnę „Protokół” w przepływach.`);
      }
    });

    if (d.action === "mark") {
      const mark = parseMark(d.mark);
      if (!String(d.mark).trim()) res.mark = "Podaj znacznik, np. 0x10.";
      else if (!Number.isFinite(mark) || mark <= 0 || mark > 0xffffffff) res.mark = "Znacznik to liczba, np. 0x10 albo 16.";
      else if (nft.drop_mark && mark === nft.drop_mark) res.mark = `${hex(mark)} jest zarezerwowany dla blokowania (drop_mark).`;
      else if (!markUsers(mark).length) res.warnings.push(`Znacznik ${hex(mark)} nie jest używany przez QoS ani routing — sam nic nie zmieni.`);
    }

    const mine = new Map(d.conds.filter((c) => String(c.value).trim()).map((c) => [c.field, String(c.value).trim().toLowerCase()]));
    for (let j = 0; j < idx; j++) {
      const prev = rulesDraft[j];
      const prevConds = prev.conds.filter((c) => String(c.value).trim());
      if (prevConds.length && prevConds.every((c) => mine.get(c.field) === String(c.value).trim().toLowerCase())) {
        res.warnings.push(`Reguła #${j + 1} „${prev.name}” jest wyżej i obejmuje ten sam ruch — ta reguła nigdy nie zadziała.`);
        break;
      }
    }
    return res;
  }

  function hasErrors(res) {
    return !!(res.name || res.mark || res.rule || res.conds.some(Boolean));
  }

  function ruleSummary(d) {
    const conds = d.conds.filter((c) => String(c.value).trim());
    if (!conds.length) return "Uzupełnij warunki reguły.";
    const parts = conds.map((c) => `${FIELDS[c.field] ? FIELDS[c.field].short : c.field} ${c.field === "host" && c.value.includes("*") ? "pasuje do" : "="} ${c.value.trim()}`);
    let then;
    if (d.action === "drop") {
      then = "zablokuj ruch";
    } else {
      const mark = parseMark(d.mark);
      const users = Number.isFinite(mark) && mark > 0 ? markUsers(mark) : [];
      then = Number.isFinite(mark) && mark > 0 ? `oznacz ${hex(mark)}` : "oznacz";
      if (users.length) then += ` → ${users.join(", ")}`;
    }
    return `Jeżeli ${parts.join(" oraz ")}, to ${then}.`;
  }

  function refreshValidation() {
    cardRefs.forEach((ref, idx) => {
      const d = rulesDraft[idx];
      if (!d) return;
      const res = validateRule(d, idx);
      setFieldError(ref.nameInput, ref.nameErr, res.name);
      ref.conds.forEach((cr, i) => setFieldError(cr.input, cr.err, res.conds[i]));
      if (ref.markInput) {
        setFieldError(ref.markInput, ref.markErr, res.mark);
        const mark = parseMark(d.mark);
        const users = Number.isFinite(mark) && mark > 0 ? markUsers(mark) : [];
        ref.markInfo.textContent = users.length ? "Używany przez: " + users.join(", ") : "";
      }
      ref.ruleErr.textContent = res.rule || "";
      ref.ruleErr.classList.toggle("hidden", !res.rule);
      ref.warnBox.replaceChildren(...res.warnings.map((w) => el("li", { text: w })));
      ref.warnBox.classList.toggle("hidden", !res.warnings.length);
      ref.summary.textContent = ruleSummary(d);
      ref.card.classList.toggle("invalid", hasErrors(res));
    });
    document.getElementById("rules-dirty").classList.toggle("hidden", !isDirty());
    document.getElementById("rules-empty").classList.toggle("hidden", rulesDraft.length > 0);
  }

  function setFieldError(input, errNode, msg) {
    input.classList.toggle("invalid", !!msg);
    errNode.textContent = msg || "";
    errNode.classList.toggle("hidden", !msg);
  }

  function updateHits() {
    cardRefs.forEach((ref, idx) => {
      const d = rulesDraft[idx];
      if (!d) return;
      const n = ruleHits[d.name.trim()] || 0;
      ref.hits.textContent = hitsLabel(n);
      ref.hits.classList.toggle("badge-muted", n === 0);
    });
  }

  // ---------- rules rendering ----------

  function renderNftInfo() {
    const hooks = (nft.hooks || []).join(", ") || "—";
    document.getElementById("nft-info").replaceChildren(
      el("span", { class: "chip", title: "Tabela nftables" }, "tabela ", el("b", { text: nft.table || "dpi" })),
      el("span", { class: "chip", title: "Hooki nftables, na których działa polityka" }, "hooki ", el("b", { text: hooks })),
      el("span", { class: "chip", title: "Znacznik używany przez akcję Zablokuj" }, "drop_mark ", el("b", { text: hex(nft.drop_mark || 0) })),
      el("span", { class: "chip muted", text: "ustawienia nftables tylko w pliku YAML" })
    );
  }

  function renderRulesEditor() {
    const root = document.getElementById("rules-editor");
    cardRefs = rulesDraft.map((d, idx) => ruleCard(d, idx));
    root.replaceChildren(...cardRefs.map((r) => r.card));
    refreshValidation();
    updateHits();
  }

  function moveRule(idx, delta) {
    const j = idx + delta;
    if (j < 0 || j >= rulesDraft.length) return;
    [rulesDraft[idx], rulesDraft[j]] = [rulesDraft[j], rulesDraft[idx]];
    renderRulesEditor();
    cardRefs[j].card.classList.add("flash");
    setTimeout(() => cardRefs[j] && cardRefs[j].card.classList.remove("flash"), 800);
  }

  function ruleCard(d, idx) {
    const ro = !editable;
    const ref = { conds: [] };

    ref.nameInput = el("input", {
      type: "text",
      class: "rule-name",
      value: d.name,
      placeholder: "nazwa reguły, np. ssh-priorytet",
      "aria-label": "Nazwa reguły",
      disabled: ro,
      oninput: (e) => {
        d.name = e.target.value;
        refreshValidation();
        updateHits();
      },
    });
    ref.nameErr = el("div", { class: "field-err hidden" });
    ref.hits = el("span", { class: "badge", title: "Ile przepływów dopasowała ta reguła od ostatniego zastosowania" });
    const tools = el(
      "div",
      { class: "rule-tools" },
      el("button", { type: "button", class: "icon-btn", title: "Przesuń wyżej", disabled: ro || idx === 0, onclick: () => moveRule(idx, -1) }, "↑"),
      el("button", { type: "button", class: "icon-btn", title: "Przesuń niżej", disabled: ro || idx === rulesDraft.length - 1, onclick: () => moveRule(idx, 1) }, "↓"),
      el("button", {
        type: "button",
        class: "icon-btn",
        title: "Duplikuj regułę",
        disabled: ro,
        onclick: () => {
          const copy = JSON.parse(JSON.stringify(d));
          copy.name = uniqueName(d.name.trim() + "-kopia");
          rulesDraft.splice(idx + 1, 0, copy);
          renderRulesEditor();
          focusRule(idx + 1);
        },
      }, "⧉"),
      el("button", {
        type: "button",
        class: "icon-btn danger",
        title: "Usuń regułę",
        disabled: ro,
        onclick: () => {
          if (d.name.trim() && !confirm(`Usunąć regułę „${d.name.trim()}”?`)) return;
          rulesDraft.splice(idx, 1);
          renderRulesEditor();
        },
      }, "✕")
    );

    // Conditions
    const used = new Set(d.conds.map((c) => c.field));
    const condList = el("div", { class: "cond-list" });
    d.conds.forEach((c, i) => {
      const def = FIELDS[c.field] || { label: c.field, placeholder: "", hint: "" };
      const select = el(
        "select",
        {
          "aria-label": "Pole warunku",
          disabled: ro,
          onchange: (e) => {
            c.field = e.target.value;
            renderRulesEditor();
            cardRefs[idx].conds[i].input.focus();
          },
        },
        FIELD_ORDER.map((f) => el("option", { value: f, selected: f === c.field, disabled: f !== c.field && used.has(f) }, FIELDS[f].label))
      );
      const input = el("input", {
        type: "text",
        value: c.value,
        list: "dl-" + c.field,
        placeholder: def.placeholder,
        "aria-label": "Wartość warunku",
        autocomplete: "off",
        spellcheck: "false",
        disabled: ro,
        oninput: (e) => {
          c.value = e.target.value;
          refreshValidation();
        },
      });
      const remove = el("button", {
        type: "button",
        class: "icon-btn",
        title: "Usuń warunek",
        disabled: ro || d.conds.length === 1,
        onclick: () => {
          d.conds.splice(i, 1);
          renderRulesEditor();
        },
      }, "✕");
      const err = el("div", { class: "field-err hidden" });
      if (i > 0) condList.appendChild(el("div", { class: "and-sep", text: "oraz" }));
      condList.appendChild(el("div", { class: "cond" }, el("div", { class: "cond-row" }, select, input, remove), err, el("div", { class: "field-hint", text: def.hint })));
      ref.conds.push({ input, err });
    });
    const freeField = FIELD_ORDER.find((f) => !used.has(f));
    const addCond = el("button", {
      type: "button",
      class: "link-btn",
      disabled: ro || !freeField,
      onclick: () => {
        d.conds.push({ field: freeField, value: "" });
        renderRulesEditor();
        const conds = cardRefs[idx].conds;
        conds[conds.length - 1].input.focus();
      },
    }, "＋ dodaj warunek (oraz)");
    ref.ruleErr = el("div", { class: "field-err hidden" });

    // Action
    const seg = el(
      "div",
      { class: "seg", role: "radiogroup", "aria-label": "Akcja" },
      ["mark", "drop"].map((a) =>
        el("button", {
          type: "button",
          role: "radio",
          "aria-checked": String(d.action === a),
          class: d.action === a ? "active" + (a === "drop" ? " danger" : "") : "",
          disabled: ro,
          onclick: () => {
            if (d.action === a) return;
            d.action = a;
            if (a === "mark" && !d.mark) d.mark = defaultMark();
            renderRulesEditor();
          },
        }, a === "mark" ? "Oznacz (mark)" : "Zablokuj (drop)")
      )
    );
    const actionBody = el("div", { class: "action-body" });
    if (d.action === "mark") {
      ref.markInput = el("input", {
        type: "text",
        class: "mark-input",
        value: d.mark,
        list: "mark-hints",
        placeholder: "np. 0x10",
        "aria-label": "Znacznik",
        autocomplete: "off",
        disabled: ro,
        oninput: (e) => {
          d.mark = e.target.value;
          refreshValidation();
        },
      });
      ref.markErr = el("div", { class: "field-err hidden" });
      ref.markInfo = el("div", { class: "field-hint" });
      actionBody.append(
        el("label", { class: "inline-label" }, "Znacznik ", ref.markInput),
        ref.markErr,
        ref.markInfo,
        el("div", { class: "field-hint", text: "Podpowiedzi pokazują znaczniki klas QoS i tras z zakładki „QoS i routing”." })
      );
    } else {
      actionBody.append(el("div", { class: "field-hint", text: `Pakiety pasujących przepływów zostaną odrzucone (drop_mark ${hex(nft.drop_mark || 0)}).` }));
    }

    ref.summary = el("div", { class: "rule-summary" });
    ref.warnBox = el("ul", { class: "rule-warn hidden" });
    ref.card = el(
      "article",
      { class: "rule-card" + (d.action === "drop" ? " is-drop" : "") },
      el("div", { class: "rule-head" }, el("span", { class: "rule-idx", title: "Kolejność sprawdzania", text: "#" + (idx + 1) }), ref.nameInput, ref.hits, tools),
      ref.nameErr,
      ref.summary,
      el(
        "div",
        { class: "rule-grid" },
        el("div", { class: "rule-col" }, el("div", { class: "section-label", text: "Jeżeli" }), condList, ref.ruleErr, addCond),
        el("div", { class: "rule-col" }, el("div", { class: "section-label", text: "To" }), seg, actionBody)
      ),
      ref.warnBox
    );
    return ref;
  }

  // ---------- rules actions ----------

  async function applyRules() {
    let firstInvalid = -1;
    rulesDraft.forEach((d, idx) => {
      if (firstInvalid < 0 && hasErrors(validateRule(d, idx))) firstInvalid = idx;
    });
    refreshValidation();
    if (firstInvalid >= 0) {
      setMsg("rules-msg", "err", `Popraw zaznaczone pola w regule #${firstInvalid + 1} przed zastosowaniem.`);
      cardRefs[firstInvalid].card.scrollIntoView({ behavior: "smooth", block: "center" });
      return false;
    }
    try {
      const res = await api("/api/rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: rulesDraft.map(toApi) }),
      });
      loadRulesFromServer(res);
      setMsg("rules-msg", "ok", `Reguły zastosowane (${rulesDraft.length}) o ${new Date().toLocaleTimeString("pl-PL")}. Obowiązują dla nowych przepływów — aby przetrwały restart, zapisz je do pliku.`);
      return true;
    } catch (e) {
      setMsg("rules-msg", "err", "Router odrzucił reguły: " + e.message);
      return false;
    }
  }

  document.getElementById("btn-add-rule").addEventListener("click", () => {
    addRule({ name: uniqueName("nowa-regula"), conds: [{ field: "app", value: "" }], action: "mark", mark: defaultMark() });
  });

  document.getElementById("btn-apply").addEventListener("click", () => applyRules());

  document.getElementById("btn-discard").addEventListener("click", async () => {
    if (isDirty() && !confirm("Odrzucić niezastosowane zmiany i wczytać reguły aktywne w routerze?")) return;
    try {
      loadRulesFromServer(await api("/api/rules"));
      setMsg("rules-msg", "", "Wczytano reguły aktywne w routerze.");
    } catch (e) {
      setMsg("rules-msg", "err", "Błąd: " + e.message);
    }
  });

  document.getElementById("btn-save").addEventListener("click", async () => {
    if (isDirty()) {
      if (!confirm("Masz niezastosowane zmiany. Zapisywane są tylko reguły aktywne w routerze — zastosować je teraz i zapisać?")) return;
      if (!(await applyRules())) return;
    }
    try {
      const res = await api("/api/rules/save", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      setMsg("rules-msg", "ok", `Zapisano do ${res.saved}.`);
    } catch (e) {
      setMsg("rules-msg", "err", "Błąd zapisu: " + e.message);
    }
  });

  window.addEventListener("beforeunload", (e) => {
    if (isDirty()) {
      e.preventDefault();
      e.returnValue = "";
    }
  });

  // ---------- QoS & routing ----------

  async function loadNetworkPanels() {
    const [qos, routing] = await Promise.all([api("/api/qos"), api("/api/routing")]);
    document.getElementById("qos-json").value = JSON.stringify(qos, null, 2);
    document.getElementById("routing-json").value = JSON.stringify(routing, null, 2);
    renderMarkHints(qos, routing);
    networkLoaded = true;
    await loadInterfaces();
  }

  const OPER_STATE = { up: "działa", down: "wyłączony", dormant: "uśpiony", lowerlayerdown: "brak łącza", unknown: "nieznany" };

  function renderInterfaceTable(rep) {
    const tbody = document.querySelector("#iface-table tbody");
    tbody.replaceChildren();
    for (const i of rep.interfaces || []) {
      if (i.loopback) continue;
      const role = i.role === "wan"
        ? el("span", { class: "badge" }, "WAN")
        : i.role === "lan" ? el("span", { class: "badge badge-muted" }, "LAN") : "—";
      const state = i.up ? OPER_STATE[i.oper_state] || i.oper_state || "działa" : "wyłączony";
      tbody.appendChild(el("tr", {},
        el("td", {}, el("b", { text: i.name }), i.name === rep.capture ? el("div", { class: "field-hint", text: "przechwytywanie (-i)" }) : null),
        el("td", {}, role),
        el("td", { text: state }),
        el("td", {}, ...(i.addrs || []).flatMap((a, n) => (n ? [el("br"), a] : [a]))),
        el("td", { text: i.gateway || "—" }),
        el("td", { text: i.speed_mbps ? i.speed_mbps + " Mbit/s" : "—" }),
        el("td", { class: "mono", text: i.mac || "—" }),
      ));
    }
    if (!tbody.children.length) tbody.appendChild(el("tr", {}, el("td", { colspan: 7, text: "—" })));
  }

  function aliasChip(name, dev, err) {
    return err
      ? el("span", { class: "chip chip-err", title: err }, el("b", { text: name }), " → nie rozpoznano")
      : el("span", { class: "chip" }, el("b", { text: name }), " → " + dev);
  }

  function renderInterfaceStatus(rep) {
    const aliases = document.getElementById("iface-aliases");
    aliases.replaceChildren(
      ...["wan", "lan"].map((a) => aliasChip(a, (rep.aliases || {})[a], (rep.alias_errors || {})[a])),
      rep.capture ? el("span", { class: "chip" }, "przechwytywanie: ", el("b", { text: rep.capture })) : el("span", { class: "chip muted", text: "brak przechwytywania na żywo" }),
    );

    const bindings = document.getElementById("qos-bindings");
    bindings.replaceChildren(...(rep.qos || []).map((b) =>
      b.error
        ? el("span", { class: "chip chip-err", title: b.error }, el("b", { text: b.name }), " → brak interfejsu")
        : el("span", { class: "chip" }, el("b", { text: b.name }), b.device !== b.name ? " → " + b.device : " ✓"),
    ));
    const bad = (rep.qos || []).filter((b) => b.error);
    if (bad.length) {
      bindings.appendChild(el("span", { class: "field-err", text: bad.map((b) => b.error).join("; ") }));
    }
  }

  function renderStatsSelect(rep) {
    const sel = document.getElementById("qos-iface");
    const prev = sel.value;
    const opts = [];
    const covered = new Set();
    for (const b of rep.qos || []) {
      if (b.error) continue;
      opts.push([b.name, b.device !== b.name ? `${b.name} → ${b.device} (QoS)` : `${b.name} (QoS)`]);
      covered.add(b.device);
    }
    for (const i of rep.interfaces || []) {
      if (i.loopback || covered.has(i.name)) continue;
      opts.push([i.name, i.name]);
    }
    sel.replaceChildren(...opts.map(([v, label]) => el("option", { value: v, text: label })));
    if (opts.some(([v]) => v === prev)) sel.value = prev;
  }

  async function loadInterfaces() {
    try {
      const rep = await api("/api/interfaces");
      renderInterfaceTable(rep);
      renderInterfaceStatus(rep);
      renderStatsSelect(rep);
    } catch (e) {
      setMsg("network-msg", "err", "Błąd odczytu interfejsów: " + e.message);
    }
  }

  document.getElementById("btn-qos-apply").addEventListener("click", async () => {
    try {
      const qos = JSON.parse(document.getElementById("qos-json").value);
      await api("/api/qos", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(qos) });
      setMsg("network-msg", "ok", "QoS zastosowany.");
      await loadNetworkPanels();
    } catch (e) {
      setMsg("network-msg", "err", "Błąd QoS: " + e.message);
    }
  });

  document.getElementById("btn-routing-apply").addEventListener("click", async () => {
    try {
      const routing = JSON.parse(document.getElementById("routing-json").value);
      await api("/api/routing", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(routing) });
      setMsg("network-msg", "ok", "Routing zastosowany.");
      await loadNetworkPanels();
    } catch (e) {
      setMsg("network-msg", "err", "Błąd routing: " + e.message);
    }
  });

  document.getElementById("btn-network-save").addEventListener("click", async () => {
    try {
      await api("/api/rules/save", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      setMsg("network-msg", "ok", "Zapisano pełną konfigurację.");
    } catch (e) {
      setMsg("network-msg", "err", "Błąd zapisu: " + e.message);
    }
  });

  async function loadQoSStats() {
    const iface = document.getElementById("qos-iface").value.trim();
    if (!iface) return;
    const tbody = document.querySelector("#qos-stats-table tbody");
    try {
      const stats = await api("/api/qos/stats?iface=" + encodeURIComponent(iface));
      tbody.innerHTML = (stats || [])
        .map((s) => `<tr><td>${escapeHtml(s.ClassID)}</td><td>${escapeHtml(s.Name || "—")}</td><td>${s.Bytes}</td><td>${s.Packets}</td><td>${s.Drops}</td></tr>`)
        .join("") || "<tr><td colspan=5>—</td></tr>";
    } catch (e) {
      setMsg("network-msg", "err", "Błąd statystyk: " + e.message);
    }
  }

  document.getElementById("btn-qos-stats").addEventListener("click", loadQoSStats);
  document.getElementById("qos-iface").addEventListener("change", loadQoSStats);

  // ---------- polling ----------

  async function tick() {
    try {
      const [st, summary] = await Promise.all([api("/api/status"), api("/api/summary")]);
      renderStatus(st);
      renderSummary(summary);
      if (!rulesLoaded) loadRulesFromServer(await api("/api/rules"));
      if (document.getElementById("panel-flows").classList.contains("active")) {
        await loadFlows();
      }
      if (document.getElementById("panel-rules").classList.contains("active")) {
        await refreshObserved(false);
      }
      if (document.getElementById("panel-network").classList.contains("active") && !networkLoaded) {
        await loadNetworkPanels();
      }
    } catch (e) {
      console.error(e);
    }
  }

  api("/api/meta").then((m) => {
    meta = m;
    renderDatalists();
    Promise.all([api("/api/qos"), api("/api/routing")])
      .then(([qos, routing]) => renderMarkHints(qos, routing))
      .catch(() => {});
    tick();
    setInterval(tick, POLL_MS);
  });
})();

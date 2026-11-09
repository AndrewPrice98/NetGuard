// NetGuard dashboard. Plain JS, no build step, no external requests.
// All network-derived text is inserted with textContent, never innerHTML.
"use strict";

// ============================================================================
// Constants
// ============================================================================
const POLL_MS = 5000;
const POLL_BUSY_MS = 1500;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STATUS_LABELS = {
  new: "New", investigating: "Investigating", resolved: "Resolved",
  false_positive: "False positive", suppressed: "Suppressed",
};
const EVENT_LABELS = {
  first_seen: "First seen", online: "Online", offline: "Offline",
  ip_change: "IP change", port_open: "Port opened", port_closed: "Port closed",
};
const SNIFFER_NAMES = { arp: "ARP", dhcp: "DHCP", port_scan: "port scan" };
const SVG_NS = "http://www.w3.org/2000/svg";

// 24x24 stroke icons (one consistent line set; no emoji).
const ICON_PATHS = {
  router: "M3 13.5h18v6H3zM7 13.5V9M17 13.5V9M6.5 16.5h.01M9.5 16.5h.01M5 6.5a10 10 0 0 1 4-2M19 6.5a10 10 0 0 0-4-2",
  computer: "M4 5h16v11H4zM2 19.5h20",
  phone: "M7.5 2.5h9v19h-9zM11 18.5h2",
  tablet: "M5 3h14v18H5zM11 18h2",
  mobile: "M7.5 2.5h9v19h-9zM11 18.5h2",
  printer: "M7 9V3h10v6M7 17H4v-6.5A1.5 1.5 0 0 1 5.5 9h13a1.5 1.5 0 0 1 1.5 1.5V17h-3M7 14h10v7H7z",
  tv: "M3 5h18v12H3zM8 21h8M12 17v4",
  speaker: "M6 2.5h12v19H6zM12 11a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 6.5h.01",
  camera: "M3 8h3.5l2-3h7l2 3H21v11H3zM12 10a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z",
  nas: "M4 3.5h16v7H4zM4 13.5h16v7H4zM7.5 7h.01M7.5 17h.01M11 7h5M11 17h5",
  server: "M4 3.5h16v7H4zM4 13.5h16v7H4zM7.5 7h.01M7.5 17h.01",
  iot: "M8 8h8v8H8zM10 3v5M14 3v5M10 16v5M14 16v5M3 10h5M3 14h5M16 10h5M16 14h5",
  console: "M6.5 8.5h11a4 4 0 0 1 4 4v1a3 3 0 0 1-5.4 1.8L15 14H9l-1.1 1.3A3 3 0 0 1 2.5 13.5v-1a4 4 0 0 1 4-4zM8 10.5v3M6.5 12h3M15.5 11.5h.01M17.5 13h.01",
  network: "M4.5 10a11 11 0 0 1 15 0M7.5 13.3a6.5 6.5 0 0 1 9 0M10.5 16.5a2 2 0 0 1 3 0M12 19.5h.01",
  sbc: "M3 6h18v12H3zM7 9.5h5v5H7zM15 10h3M15 13h3",
  vm: "M12 2.8l8 4.6v9.2l-8 4.6-8-4.6V7.4zM12 12l8-4.6M12 12v9.2M12 12L4 7.4",
  unknown: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM9.6 9.4a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.5M12 16.8h.01",
  close: "M6 6l12 12M18 6L6 18",
  download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14",
  external: "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
};

// ============================================================================
// Token (only used when the server was started with one)
// ============================================================================
const TOKEN = (() => {
  const m = location.hash.match(/token=([^&]+)/);
  let token = m ? decodeURIComponent(m[1]) : "";
  try {
    if (m) sessionStorage.setItem("netguard-token", token);
    else token = sessionStorage.getItem("netguard-token") || "";
  } catch { /* storage blocked: keep the in-memory value */ }
  if (m) history.replaceState(null, "", location.pathname + "#/overview");
  return token;
})();

// ============================================================================
// Global state
// ============================================================================
const state = {
  status: null, playbooks: {}, hosts: [],
  page: null, pageName: "", arg: "",
  timer: null, drawer: null,
};

// ============================================================================
// DOM & formatting helpers
// ============================================================================
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "value") node.value = v;
    else if (k === "checked") node.checked = !!v;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  }
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

function icon(name, size = 16, cls = "icon") {
  const s = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, class: cls, "aria-hidden": "true" });
  s.append(svg("path", { d: ICON_PATHS[name] || ICON_PATHS.unknown }));
  return s;
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const fullTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");
function stamp(iso) {  // compact, sortable-looking local timestamp: "Nov 09 15:03"
  if (!iso) return "";
  const d = new Date(iso);
  const mon = d.toLocaleString([], { month: "short" });
  const p = (n) => String(n).padStart(2, "0");
  return `${mon} ${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function ipNum(ip) {
  const p = (ip || "").split(".").map(Number);
  return p.length === 4 ? ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3] : Infinity;
}

const hostName = (h) => (h ? (h.alias || h.hostname || h.ip || h.mac) : "");
const hostByMac = (mac) => state.hosts.find((h) => h.mac === mac);
const pbTitle = (kind) => state.playbooks[kind]?.title || kind.replace(/_/g, " ");
const titleCase = (s) => s.charAt(0) + s.slice(1).toLowerCase();

function isNew(h) {
  const baseline = state.status?.baseline_at || "";
  return !!h.first_seen && h.first_seen > baseline && Date.now() - Date.parse(h.first_seen) < 86400e3;
}

// Severity: a colored square plus the word. Never color alone.
const sevTag = (sev) => el("span", { class: `sev sev-${sev}` }, el("i"), titleCase(sev));
const statusTag = (st) => el("span", { class: `st st-${st}` }, el("i"), STATUS_LABELS[st] || st);
const riskCell = (h) => el("span", { class: `risk r-${h.risk_level}`, title: `Risk score ${h.risk}/100` }, String(h.risk));

function deviceLink(mac, ip, label) {
  const h = mac ? hostByMac(mac) : null;
  const text = label || (h ? hostName(h) : (ip || mac));
  if (!h) return el("span", { class: "mono" }, text || "—");
  return el("a", { href: `#/devices/${encodeURIComponent(h.mac)}`, class: "link" }, text);
}

const empty = (text) => el("div", { class: "empty" }, text);
const dash = () => el("span", { class: "muted" }, "—");

// ============================================================================
// API
// ============================================================================
async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (TOKEN) headers["X-NetGuard-Token"] = TOKEN;
  if (method !== "GET") headers["X-NetGuard"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

async function download(path) {
  const headers = TOKEN ? { "X-NetGuard-Token": TOKEN } : {};
  try {
    const res = await fetch(path, { headers });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "export";
    const url = URL.createObjectURL(await res.blob());
    const a = el("a", { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${name}`);
  } catch (err) {
    toast(`Export failed: ${err.message}`, true);
  }
}

async function act(fn, success) {
  try {
    await fn();
    if (success) toast(success);
  } catch (err) {
    toast(err.message, true);
  }
  await refresh();
}

function toast(text, isError = false) {
  const t = el("div", { class: `toast${isError ? " err" : ""}`, role: "status" }, text);
  $("toasts").append(t);
  setTimeout(() => t.classList.add("out"), 2800);
  setTimeout(() => t.remove(), 3200);
}

const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

// ============================================================================
// Tooltip
// ============================================================================
function showTip(text, e) { const t = $("tooltip"); t.textContent = text; t.hidden = false; moveTip(e); }
function hideTip() { $("tooltip").hidden = true; }
function moveTip(e) {
  const t = $("tooltip");
  let x = e.clientX + 12, y = e.clientY + 14;
  if (x + t.offsetWidth > innerWidth - 8) x = e.clientX - t.offsetWidth - 12;
  if (y + t.offsetHeight > innerHeight - 8) y = e.clientY - t.offsetHeight - 12;
  t.style.left = `${x}px`; t.style.top = `${y}px`;
}
function tipOn(node, textFn) {
  node.addEventListener("mouseenter", (e) => showTip(textFn(), e));
  node.addEventListener("mousemove", moveTip);
  node.addEventListener("mouseleave", hideTip);
  node.addEventListener("focus", () => { const r = node.getBoundingClientRect(); showTip(textFn(), { clientX: r.right, clientY: r.top }); });
  node.addEventListener("blur", hideTip);
  return node;
}

// ============================================================================
// Top bar status
// ============================================================================
function renderStatus() {
  const data = state.status;
  if (!data) return;
  const st = data.status || {};
  const pill = $("status-pill");
  let mode = "live", text = "Monitoring";
  if (!data.monitoring) { mode = "idle"; text = "View only"; }
  else if (st.scanning) { mode = "busy"; text = "Scanning"; }
  else if (st.last_error) { mode = "err"; text = "Error"; }
  pill.className = `mon-state ${mode}`;
  pill.textContent = text;

  const facts = [];
  if (data.monitoring) {
    if (st.subnet) facts.push(st.subnet);
    if (st.last_scan) facts.push(`scanned ${ago(st.last_scan)}`);
    if (st.next_scan && !st.scanning) {
      const s = Math.max(0, Math.round(st.next_scan - Date.now() / 1000));
      facts.push(`next ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`);
    }
  }
  $("monitor-facts").textContent = facts.join("  ·  ");

  const scanBtn = $("scan-btn");
  scanBtn.disabled = !data.monitoring || !!st.scanning;
  scanBtn.title = data.monitoring ? "" : "Start with `netguard serve` to scan from here";

  const open = data.statuses.new + data.statuses.investigating;
  const navA = $("nav-alerts");
  navA.textContent = open || "";
  navA.classList.toggle("hot", data.alerts.CRITICAL + data.alerts.HIGH > 0);
  $("nav-devices").textContent = data.untrusted || "";

  const banner = $("banner");
  banner.hidden = !st.last_error;
  banner.textContent = st.last_error ? `Monitor error: ${st.last_error}` : "";

  $("foot").textContent = `NetGuard ${data.version}  ·  ${data.vendors.toLocaleString()} vendor prefixes` +
    (data.vendors < 1000 ? " (run `netguard update-oui` for the full registry)" : "");
}

// ============================================================================
// Charts (dataviz guidance: thin bars, 2px gaps, legend, hover tooltips)
// ============================================================================
function alertsChart(series) {
  const wrap = el("div", { class: "chart" });
  const legend = el("div", { class: "legend" }, SEVERITIES.map((s) =>
    el("span", {}, el("i", { class: `sw sev-bg-${s}` }), titleCase(s))));
  const plot = svg("svg", { class: "chart-svg", role: "img", "aria-label": "Alerts per day by severity" });
  wrap.append(plot, legend);

  requestAnimationFrame(() => {
    const W = plot.clientWidth || 600, H = 190;
    const pad = { l: 28, r: 4, t: 6, b: 20 };
    plot.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const totals = series.map((d) => SEVERITIES.reduce((n, s) => n + d[s], 0));
    const step = Math.ceil(Math.max(4, ...totals) / 4);
    const top = step * 4;
    const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / top);
    const band = (W - pad.l - pad.r) / series.length;
    const barW = Math.min(20, band * 0.56);

    for (let v = 0; v <= top; v += step) {
      plot.append(svg("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v), class: v ? "gridline" : "axis" }));
      const t = svg("text", { x: pad.l - 8, y: y(v) + 3.5, class: "tick", "text-anchor": "end" });
      t.textContent = v;
      plot.append(t);
    }

    series.forEach((d, i) => {
      const cx = pad.l + band * i + band / 2;
      let base = 0;
      const stack = [...SEVERITIES].reverse().filter((s) => d[s] > 0);
      stack.forEach((s, k) => {
        const y0 = y(base), y1 = y(base + d[s]);
        const h = Math.max(0, y0 - y1 - (k ? 2 : 0));  // 2px surface gap between segments
        const x = cx - barW / 2, r = k === stack.length - 1 ? Math.min(3, h, barW / 2) : 0;
        const yt = y1, yb = y1 + h;
        plot.append(svg("path", {
          class: `sev-fill-${s}`,
          d: `M${x},${yb} V${yt + r} Q${x},${yt} ${x + r},${yt} H${x + barW - r} Q${x + barW},${yt} ${x + barW},${yt + r} V${yb} Z`,
        }));
        base += d[s];
      });
      if (i % Math.ceil(series.length / 7) === 0 || i === series.length - 1) {
        const t = svg("text", { x: cx, y: H - 5, class: "tick", "text-anchor": "middle" });
        t.textContent = new Date(d.day + "T12:00:00Z").toLocaleDateString([], { month: "short", day: "numeric" });
        plot.append(t);
      }
      const hit = svg("rect", { x: cx - band / 2, y: pad.t, width: band, height: H - pad.t - pad.b, class: "hit", tabindex: "0" });
      tipOn(hit, () => {
        const date = new Date(d.day + "T12:00:00Z").toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
        const lines = SEVERITIES.filter((s) => d[s]).map((s) => `${titleCase(s).padEnd(9)} ${d[s]}`);
        return `${date}\n${lines.length ? lines.join("\n") : "No alerts"}${lines.length > 1 ? `\nTotal     ${totals[i]}` : ""}`;
      });
      plot.append(hit);
    });
  });
  return wrap;
}

function barList(items, { label, value, onClick, tone }) {
  if (!items.length) return empty("Nothing in this period.");
  const max = Math.max(...items.map(value));
  const list = el("ul", { class: "barlist" }, items.map((it) => el("li", {},
    el(onClick ? "button" : "div", { class: "barlist-row", type: onClick ? "button" : undefined,
      onclick: onClick ? () => onClick(it) : undefined },
      el("span", { class: "barlist-label" }, label(it)),
      el("span", { class: "barlist-value" }, String(value(it))),
      el("span", { class: "barlist-track" }, el("span", { class: `barlist-bar ${tone ? tone(it) : ""}`, dataset: { w: String(value(it) / max) } }))),
  )));
  // CSP forbids inline style attributes, so widths are set via CSSOM.
  requestAnimationFrame(() => list.querySelectorAll(".barlist-bar").forEach((b) => { b.style.width = `${Math.max(2, b.dataset.w * 100)}%`; }));
  return list;
}

// ============================================================================
// Network map
// ============================================================================
function networkMap(hosts, onPick) {
  const map = svg("svg", { class: "map", role: "img", "aria-label": "Network map of devices around the router" });
  requestAnimationFrame(() => drawMap(map, hosts, onPick));
  return map;
}

function drawMap(map, hosts, onPick) {
  const W = map.clientWidth || 600, H = map.clientHeight || 380;
  map.replaceChildren();
  const gatewayIp = state.status?.status?.gateway;
  let router = hosts.find((h) => h.type === "router" || h.ip === gatewayIp);
  if (!router && gatewayIp) {
    router = { ip: gatewayIp, mac: "", hostname: "", alias: "", vendor: "", type: "router",
      type_label: "Router", trusted: true, online: true, ports: [], risk: 0, risk_level: "low" };
  }
  const others = hosts.filter((h) => h !== router)
    .sort((a, b) => a.type.localeCompare(b.type) || ipNum(a.ip) - ipNum(b.ip));

  // Devices on concentric (elliptical) rings around the router, spread evenly.
  const spacing = 64, ringGap = 66, ax = Math.min(1.8, Math.max(1, W / H));
  const radii = [], caps = [];
  for (let r = 110, room = 0; room < others.length; r += ringGap) {
    const cap = Math.floor((2 * Math.PI * r * (1 + ax) / 2) / spacing);
    radii.push(r); caps.push(cap); room += cap;
  }
  const totalCap = caps.reduce((a, b) => a + b, 0) || 1;
  const counts = caps.map((c) => Math.floor((c / totalCap) * others.length));
  for (let k = 0; counts.reduce((a, b) => a + b, 0) < others.length; k++) counts[k % counts.length]++;
  const pos = [];
  radii.forEach((rr, ring) => {
    const n = counts[ring], off = ring % 2 ? Math.PI / Math.max(n, 1) : 0;
    for (let k = 0; k < n; k++) {
      const a = (2 * Math.PI * k) / n - Math.PI / 2 + off;
      pos.push([rr * ax * Math.cos(a), rr * Math.sin(a)]);
    }
  });
  const outer = radii.length ? radii[radii.length - 1] : 110;
  // Fit the outer ring; never zoom in so far that labels outgrow the UI text.
  const scale = Math.max(0.88, (outer + 44) / (H / 2), (outer * ax + 56) / (W / 2));
  map.setAttribute("viewBox", `${(-W * scale) / 2} ${(-H * scale) / 2} ${W * scale} ${H * scale}`);

  const edges = svg("g"), nodes = svg("g");
  others.forEach((h, i) => {
    const [x, y] = pos[i];
    edges.append(svg("line", { x1: 0, y1: 0, x2: x, y2: y, class: `edge${h.trusted ? "" : " bad"}${h.online ? "" : " off"}` }));
    nodes.append(mapNode(h, x, y, 15, false, onPick));
  });
  if (router) nodes.append(mapNode(router, 0, 0, 20, true, onPick));
  map.append(edges, nodes);
  if (!hosts.length) {
    const t = svg("text", { x: 0, y: 0, "text-anchor": "middle", class: "tick" });
    t.textContent = "No devices yet. The first scan builds the baseline.";
    map.append(t);
  }
}

function mapNode(h, x, y, r, isRouter, onPick) {
  const g = svg("g", {
    class: `node${h.trusted ? "" : " bad"}${isRouter ? " router" : ""}${h.online === false ? " off" : ""}`,
    transform: `translate(${x},${y})`, tabindex: "0", role: "button",
    "aria-label": `${h.type_label} ${h.ip} ${hostName(h)}`,
  });
  g.append(svg("circle", { class: "ring", r }));
  const s = r * 1.05;  // icon box, centered
  const ic = svg("path", { class: "glyph", d: ICON_PATHS[h.type] || ICON_PATHS.unknown,
    transform: `translate(${-s / 2},${-s / 2}) scale(${s / 24})` });
  g.append(ic);
  if (h.open_alerts) g.append(svg("circle", { class: "alert-dot", r: 4, cx: r * 0.75, cy: -r * 0.75 }));
  const label = svg("text", { class: "lbl", y: r + 13 });
  const name = isRouter ? h.ip : (h.alias || (h.hostname || "").split(".")[0] || "." + h.ip.split(".").pop());
  label.textContent = name.length > 16 ? name.slice(0, 15) + "…" : name;
  g.append(label);
  tipOn(g, () => [
    `${hostName(h)}${h.trusted ? "" : "  [untrusted]"}${h.online === false ? "  [offline]" : ""}`,
    `${h.ip}   ${h.mac}`,
    [h.type_label, h.vendor].filter(Boolean).join(" · "),
    h.open_alerts ? `${h.open_alerts} open alert${h.open_alerts === 1 ? "" : "s"} · risk ${h.risk}` : "",
  ].filter(Boolean).join("\n"));
  const pick = () => { hideTip(); if (h.mac) onPick(h.mac); };
  g.addEventListener("click", pick);
  g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
  return g;
}

// ============================================================================
// Layout pieces
// ============================================================================
function panel(title, meta, ...body) {
  return el("section", { class: "panel" },
    el("header", { class: "panel-head" }, el("h2", {}, title), meta ? el("div", { class: "panel-meta" }, meta) : null),
    el("div", { class: "panel-body" }, ...body));
}

function pageHead(title, sub, ...actions) {
  return el("header", { class: "page-head" },
    el("div", {}, el("h1", {}, title), sub ? el("p", {}, sub) : null),
    actions.length ? el("div", { class: "page-actions" }, ...actions) : null);
}

function stat(label, value, note, opts = {}) {
  return el(opts.href ? "a" : "div", { class: `stat${opts.alarm ? " alarm" : ""}`, href: opts.href },
    el("span", { class: "stat-label" }, label),
    el("span", { class: "stat-value" }, String(value)),
    el("span", { class: "stat-note" }, note));
}

function eventDot(kind) {
  return el("span", { class: `tl-dot ev-${kind}`, "aria-hidden": "true" });
}

function eventList(events, { showDevice = true } = {}) {
  if (!events.length) return empty("No activity recorded yet.");
  return el("ol", { class: "timeline" }, events.map((e) => el("li", {},
    eventDot(e.kind),
    el("time", { datetime: e.ts, title: fullTime(e.ts) }, stamp(e.ts)),
    el("div", { class: "tl-body" },
      el("span", { class: "tl-kind" }, EVENT_LABELS[e.kind] || e.kind),
      el("span", {}, e.message),
      showDevice && e.mac && hostByMac(e.mac) ? deviceLink(e.mac, e.ip) : null))));
}

function openReport(days = "7") {
  const q = new URLSearchParams({ days });
  if (TOKEN) q.set("token", TOKEN);
  window.open(`/report?${q}`, "_blank", "noopener");
}

// ============================================================================
// Page: Overview
// ============================================================================
const OverviewPage = {
  title: "Overview",
  sig: "",
  mount(root) {
    this.sig = "";
    const days = el("select", { "aria-label": "Report period" },
      el("option", { value: "1" }, "24 hours"), el("option", { value: "7", selected: true }, "7 days"),
      el("option", { value: "30" }, "30 days"));
    root.replaceChildren(
      pageHead("Overview", null,
        el("div", { class: "joined" }, days, el("button", { class: "btn", type: "button", onclick: () => openReport(days.value) }, "Open report"))),
      el("section", { class: "stats", id: "ov-stats" }),
      el("div", { class: "grid g-2-1" },
        panel("Alerts by day", "Last 14 days", el("div", { id: "ov-chart" })),
        panel("Top alert types", "Last 14 days", el("div", { id: "ov-kinds" }))),
      el("div", { class: "grid g-3-2" },
        panel("Network", el("span", { class: "legend" },
          el("span", {}, el("i", { class: "lg-node" }), "trusted"),
          el("span", {}, el("i", { class: "lg-node bad" }), "untrusted"),
          el("span", {}, el("i", { class: "lg-node off" }), "offline"),
          el("span", {}, el("i", { class: "lg-alert" }), "open alert")), el("div", { id: "ov-map", class: "map-box" })),
        el("div", { class: "stack" },
          panel("Needs attention", "Open high and critical", el("div", { id: "ov-urgent" })),
          panel("Highest risk devices", null, el("div", { id: "ov-risky" })))),
      panel("Recent activity", el("a", { href: "#/activity", class: "link" }, "All activity"), el("div", { id: "ov-events" })),
    );
  },
  async refresh() {
    const [ov, hosts] = await Promise.all([api("/api/overview?days=14"), api("/api/hosts")]);
    state.hosts = hosts;
    this.renderStats();
    const sig = JSON.stringify([ov, hosts]);
    if (sig === this.sig) return;
    this.sig = sig;

    $("ov-chart").replaceChildren(alertsChart(ov.series));
    $("ov-kinds").replaceChildren(barList(ov.top_kinds, {
      label: (k) => k.title, value: (k) => k.count, tone: (k) => `sev-bg-${k.severity}`,
      onClick: (k) => { AlertsPage.filters = { ...AlertsPage.defaults(), kind: k.kind, status: "all", days: "14" }; go("alerts"); },
    }));
    $("ov-map").replaceChildren(networkMap(hosts, (mac) => go("devices", mac)));

    $("ov-urgent").replaceChildren(ov.urgent.length
      ? el("ul", { class: "rows" }, ov.urgent.map((a) => el("li", {},
          el("a", { href: `#/alerts/${a.id}`, class: "row-link" },
            sevTag(a.severity),
            el("span", { class: "row-main" }, el("b", {}, pbTitle(a.kind)), el("small", {}, a.message)),
            el("time", { class: "muted", title: fullTime(a.ts) }, ago(a.ts))))))
      : empty("No open high or critical alerts."));

    const risky = [...hosts].filter((h) => h.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 5);
    $("ov-risky").replaceChildren(risky.length
      ? el("ul", { class: "rows" }, risky.map((h) => el("li", {},
          el("a", { href: `#/devices/${encodeURIComponent(h.mac)}`, class: "row-link" },
            riskCell(h),
            el("span", { class: "row-main" }, el("b", {}, hostName(h)),
              el("small", { class: "mono" }, `${h.ip}  ${h.type_label.toLowerCase()}${h.trusted ? "" : "  untrusted"}`)),
            el("span", { class: "muted" }, h.open_alerts ? `${h.open_alerts} open` : "")))))
      : empty("Every device scores low risk."));

    $("ov-events").replaceChildren(eventList(ov.events));
  },
  renderStats() {
    const s = state.status;
    if (!s) return;
    const a = s.alerts, urgent = a.CRITICAL + a.HIGH;
    const open = s.statuses.new + s.statuses.investigating;
    const sn = s.status?.sniffer || [];
    $("ov-stats").replaceChildren(
      stat("Open alerts", open, urgent ? `${a.CRITICAL} critical, ${a.HIGH} high` : "none high or critical", { alarm: urgent > 0, href: "#/alerts" }),
      stat("Investigating", s.statuses.investigating, "assigned to triage", { href: "#/alerts" }),
      stat("Devices online", `${s.online} / ${s.hosts}`, s.hosts - s.online ? `${s.hosts - s.online} offline` : "all present", { href: "#/devices" }),
      stat("Untrusted", s.untrusted, s.untrusted ? "awaiting review" : "all in baseline", { alarm: s.untrusted > 0, href: "#/devices" }),
      stat("Live capture", sn.length ? "On" : "Off", sn.length ? sn.map((n) => SNIFFER_NAMES[n]).join(", ") : "scan-based detection"),
    );
  },
};

// ============================================================================
// Page: Alerts (triage queue)
// ============================================================================
const AlertsPage = {
  title: "Alerts",
  defaults: () => ({ status: "open", min: "INFO", kind: "", q: "", days: "", mac: "" }),
  filters: null,
  selected: new Set(),
  rows: [],
  sig: "",
  mount(root) {
    this.filters = this.filters || this.defaults();
    this.selected.clear();
    this.sig = "";
    const f = this.filters;
    const kinds = Object.entries(state.playbooks).sort((a, b) => a[1].title.localeCompare(b[1].title));
    root.replaceChildren(
      pageHead("Alerts", null,
        el("button", { class: "btn", type: "button", onclick: () => download(`/api/export/alerts.csv?${this.query(5000)}`) }, icon("download", 14), "CSV"),
        el("button", { class: "btn", type: "button", onclick: () => download(`/api/export/alerts.json?${this.query(5000)}`) }, icon("download", 14), "JSON")),
      el("div", { class: "tabs", role: "tablist", id: "al-tabs" }),
      el("div", { class: "toolbar" },
        el("input", { type: "search", class: "search", placeholder: "Search messages, IPs, MACs, notes", value: f.q,
          "aria-label": "Search alerts", oninput: debounce((e) => { f.q = e.target.value; this.reload(); }, 250) }),
        el("select", { "aria-label": "Minimum severity", onchange: (e) => { f.min = e.target.value; this.reload(); } },
          [["INFO", "Any severity"], ["LOW", "Low and above"], ["MEDIUM", "Medium and above"], ["HIGH", "High and above"], ["CRITICAL", "Critical only"]]
            .map(([v, t]) => el("option", { value: v, selected: f.min === v }, t))),
        el("select", { "aria-label": "Alert type", onchange: (e) => { f.kind = e.target.value; this.reload(); } },
          el("option", { value: "" }, "Any type"),
          kinds.map(([k, p]) => el("option", { value: k, selected: f.kind === k }, p.title))),
        el("select", { "aria-label": "Time range", onchange: (e) => { f.days = e.target.value; this.reload(); } },
          [["", "Any time"], ["1", "Last 24 hours"], ["7", "Last 7 days"], ["14", "Last 14 days"], ["30", "Last 30 days"]]
            .map(([v, t]) => el("option", { value: v, selected: f.days === v }, t))),
        el("span", { id: "al-chip" }),
        el("span", { class: "toolbar-count muted", id: "al-count" })),
      el("div", { class: "bulkbar", id: "al-bulk", hidden: true }),
      el("div", { class: "panel flush" },
        el("div", { class: "table-wrap" },
          el("table", { class: "table" },
            el("thead", {}, el("tr", {},
              el("th", { class: "check" }, el("input", { type: "checkbox", id: "al-all", "aria-label": "Select all",
                onchange: (e) => { this.rows.forEach((a) => (e.target.checked ? this.selected.add(a.id) : this.selected.delete(a.id))); this.render(); } })),
              el("th", { class: "w-sev" }, "Severity"), el("th", { class: "w-time" }, "Time"), el("th", {}, "Alert"),
              el("th", {}, "Device"), el("th", {}, "ATT&CK"), el("th", {}, "Status"))),
            el("tbody", { id: "al-rows" })),
          el("div", { id: "al-empty" }))),
    );
    this.renderTabs();
  },
  query(limit = 300) {
    const f = this.filters;
    const q = new URLSearchParams({ status: f.status, min: f.min, limit: String(limit) });
    if (f.kind) q.set("kind", f.kind);
    if (f.q) q.set("q", f.q);
    if (f.days) q.set("days", f.days);
    if (f.mac) q.set("mac", f.mac);
    return q.toString();
  },
  reload() { this.sig = ""; this.refresh().catch((e) => toast(e.message, true)); },
  renderTabs() {
    const s = state.status?.statuses || {};
    const tabs = [["open", "Open", (s.new || 0) + (s.investigating || 0)], ["new", "New", s.new],
      ["investigating", "Investigating", s.investigating], ["resolved", "Resolved", s.resolved],
      ["false_positive", "False positive", s.false_positive], ["suppressed", "Suppressed", s.suppressed],
      ["all", "All", null]];
    $("al-tabs").replaceChildren(...tabs.map(([k, label, n]) => el("button", {
      type: "button", role: "tab", class: this.filters.status === k ? "on" : "", "aria-selected": String(this.filters.status === k),
      onclick: () => { this.filters.status = k; this.selected.clear(); this.renderTabs(); this.reload(); },
    }, label, n != null ? el("span", { class: "tab-n" }, String(n || 0)) : null)));
    $("al-chip")?.replaceChildren(this.filters.mac ? el("button", { class: "chip", type: "button",
      onclick: () => { this.filters.mac = ""; this.reload(); } },
      `device: ${hostName(hostByMac(this.filters.mac)) || this.filters.mac}`, icon("close", 12)) : "");
  },
  async refresh() {
    if (!state.hosts.length) state.hosts = await api("/api/hosts");
    const rows = await api(`/api/alerts?${this.query()}`);
    this.renderTabs();
    const sig = JSON.stringify(rows);
    if (sig === this.sig) return;
    this.sig = sig;
    this.rows = rows;
    const ids = new Set(rows.map((a) => a.id));
    [...this.selected].forEach((id) => ids.has(id) || this.selected.delete(id));
    this.render();
  },
  render() {
    const body = $("al-rows");
    if (!body) return;
    body.replaceChildren(...this.rows.map((a) => {
      const mitre = state.playbooks[a.kind]?.mitre || [];
      return el("tr", { class: `clickable sevrow-${a.severity}${this.selected.has(a.id) ? " selected" : ""}`, tabindex: "0",
        onclick: (e) => { if (!e.target.closest("input,a")) go("alerts", String(a.id)); },
        onkeydown: (e) => { if (e.key === "Enter") go("alerts", String(a.id)); } },
        el("td", { class: "check" }, el("input", { type: "checkbox", checked: this.selected.has(a.id), "aria-label": `Select alert ${a.id}`,
          onchange: (e) => { e.target.checked ? this.selected.add(a.id) : this.selected.delete(a.id); this.render(); } })),
        el("td", {}, sevTag(a.severity)),
        el("td", { class: "mono nowrap muted", title: fullTime(a.ts) }, stamp(a.ts)),
        el("td", { class: "alert-cell" }, el("b", {}, pbTitle(a.kind)), el("small", {}, a.message)),
        el("td", { class: "nowrap" }, a.mac || a.ip ? deviceLink(a.mac, a.ip) : dash()),
        el("td", { class: "mono nowrap" }, mitre.length ? mitre.map((t) => el("span", { class: "tid", title: t.name }, t.id)) : dash()),
        el("td", { class: "nowrap" }, statusTag(a.status)));
    }));
    $("al-count").textContent = `${this.rows.length} shown`;
    $("al-empty").replaceChildren(this.rows.length ? "" : empty(this.filters.status === "open" ? "No open alerts." : "No alerts match these filters."));
    const all = $("al-all");
    all.checked = this.rows.length > 0 && this.rows.every((a) => this.selected.has(a.id));
    all.indeterminate = !all.checked && this.rows.some((a) => this.selected.has(a.id));

    const bulk = $("al-bulk");
    bulk.hidden = this.selected.size === 0;
    const ids = [...this.selected];
    const setAll = (status) => act(() => api("/api/alerts/bulk", { method: "POST", body: { ids, status } })
      .then(() => this.selected.clear()), `${ids.length} alert${ids.length === 1 ? "" : "s"} marked ${STATUS_LABELS[status].toLowerCase()}`);
    bulk.replaceChildren(
      el("span", {}, `${this.selected.size} selected`),
      el("button", { class: "btn", type: "button", onclick: () => setAll("investigating") }, "Investigate"),
      el("button", { class: "btn", type: "button", onclick: () => setAll("resolved") }, "Resolve"),
      el("button", { class: "btn", type: "button", onclick: () => setAll("false_positive") }, "False positive"),
      el("button", { class: "btn", type: "button", onclick: () => setAll("new") }, "Reopen"),
      el("button", { class: "btn quiet", type: "button", onclick: () => { this.selected.clear(); this.render(); } }, "Clear selection"));
  },
};

// ============================================================================
// Page: Devices (asset inventory)
// ============================================================================
const DevicesPage = {
  title: "Devices",
  filter: "all", q: "", sort: { key: "risk", desc: true }, sig: "",
  mount(root) {
    this.sig = "";
    const cols = [["status", "", false], ["risk", "Risk"], ["ip", "IP address"], ["name", "Name"], ["type", "Type"],
      ["vendor", "Vendor"], ["mac", "MAC"], ["ports", "Open ports", false], ["alerts", "Alerts"], ["last_seen", "Last seen"]];
    root.replaceChildren(
      pageHead("Devices", null,
        el("button", { class: "btn", type: "button", onclick: () => download("/api/export/hosts.csv") }, icon("download", 14), "CSV")),
      el("div", { class: "toolbar" },
        el("input", { type: "search", class: "search", placeholder: "Search names, IPs, MACs, vendors, notes", value: this.q,
          "aria-label": "Search devices", oninput: (e) => { this.q = e.target.value; this.render(); } }),
        el("div", { class: "seg", role: "group", "aria-label": "Filter devices", id: "dv-seg" },
          [["all", "All"], ["untrusted", "Untrusted"], ["online", "Online"], ["offline", "Offline"], ["new", "New today"]]
            .map(([k, t]) => el("button", { type: "button", class: this.filter === k ? "on" : "", dataset: { f: k },
              onclick: () => { this.filter = k; document.querySelectorAll("#dv-seg button").forEach((b) => b.classList.toggle("on", b.dataset.f === k)); this.render(); } }, t))),
        el("span", { class: "toolbar-count muted", id: "dv-count" })),
      el("div", { class: "panel flush" },
        el("div", { class: "table-wrap" },
          el("table", { class: "table" },
            el("thead", {}, el("tr", {}, cols.map(([k, label, sortable]) => el("th", {
              dataset: sortable === false ? {} : { sort: k }, class: sortable === false ? "" : "sortable",
              onclick: sortable === false ? undefined : () => { this.sort = { key: k, desc: this.sort.key === k ? !this.sort.desc : k === "risk" || k === "alerts" }; this.render(); },
            }, label)))),
            el("tbody", { id: "dv-rows" })),
          el("div", { id: "dv-empty" }))),
    );
  },
  async refresh() {
    const hosts = await api("/api/hosts");
    state.hosts = hosts;
    const sig = JSON.stringify(hosts);
    if (sig === this.sig) return;
    this.sig = sig;
    this.render();
  },
  render() {
    const q = this.q.toLowerCase();
    const sorters = {
      risk: (a, b) => a.risk - b.risk, ip: (a, b) => ipNum(a.ip) - ipNum(b.ip),
      name: (a, b) => hostName(a).localeCompare(hostName(b)), type: (a, b) => a.type_label.localeCompare(b.type_label),
      vendor: (a, b) => (a.vendor || "~").localeCompare(b.vendor || "~"), mac: (a, b) => a.mac.localeCompare(b.mac),
      alerts: (a, b) => a.open_alerts - b.open_alerts, last_seen: (a, b) => (a.last_seen || "").localeCompare(b.last_seen || ""),
    };
    const rows = state.hosts.filter((h) => {
      if (this.filter === "untrusted" && h.trusted) return false;
      if (this.filter === "online" && !h.online) return false;
      if (this.filter === "offline" && h.online) return false;
      if (this.filter === "new" && !isNew(h)) return false;
      return !q || [h.ip, h.hostname, h.alias, h.mac, h.vendor, h.type_label, h.notes].some((v) => (v || "").toLowerCase().includes(q));
    }).sort((a, b) => sorters[this.sort.key](a, b) || ipNum(a.ip) - ipNum(b.ip));
    if (this.sort.desc) rows.reverse();

    document.querySelectorAll(".table th[data-sort]").forEach((th) => {
      th.classList.toggle("sorted", th.dataset.sort === this.sort.key);
      th.classList.toggle("desc", th.dataset.sort === this.sort.key && this.sort.desc);
    });
    const body = $("dv-rows");
    if (!body) return;
    body.replaceChildren(...rows.map((h) => el("tr", {
      class: `clickable${h.trusted ? "" : " untrusted"}${h.online ? "" : " offline"}`, tabindex: "0",
      onclick: () => go("devices", h.mac), onkeydown: (e) => { if (e.key === "Enter") go("devices", h.mac); } },
      el("td", { class: "w-dot" }, el("span", { class: `presence ${h.online ? "on" : "off"}`, title: h.online ? "Online" : "Offline" })),
      el("td", {}, riskCell(h)),
      el("td", { class: "mono nowrap" }, h.ip),
      el("td", { class: "name-cell" },
        el("b", {}, h.alias || h.hostname || el("span", { class: "muted" }, "unnamed")),
        h.alias && h.hostname ? el("small", { class: "mono" }, h.hostname) : null,
        h.trusted ? null : el("span", { class: "flag" }, "untrusted"),
        isNew(h) ? el("span", { class: "flag new" }, "new") : null),
      el("td", { class: "nowrap type-cell" }, icon(h.type, 15), h.type_label),
      el("td", {}, h.vendor || dash()),
      el("td", { class: "mono nowrap muted" }, h.mac),
      el("td", {}, portList(h.ports.filter((p) => p.open))),
      el("td", { class: "num" }, h.open_alerts ? el("span", { class: "alert-n" }, String(h.open_alerts)) : dash()),
      el("td", { class: "nowrap muted", title: fullTime(h.last_seen) }, ago(h.last_seen)),
    )));
    $("dv-count").textContent = `${rows.length} of ${state.hosts.length}`;
    $("dv-empty").replaceChildren(rows.length ? "" : empty(state.hosts.length ? "No devices match." : "No devices yet."));
  },
};

function portList(ports) {
  if (!ports.length) return dash();
  return el("span", { class: "ports" }, ports.map((p) => el("span", { class: `port${p.risky ? " risky" : ""}`, title: p.service || "" }, String(p.port))));
}

// ============================================================================
// Page: Activity (event log)
// ============================================================================
const ActivityPage = {
  title: "Activity",
  kind: "", q: "", sig: "", events: [],
  mount(root) {
    this.sig = "";
    root.replaceChildren(
      pageHead("Activity", null),
      el("div", { class: "toolbar" },
        el("input", { type: "search", class: "search", placeholder: "Search activity", value: this.q, "aria-label": "Search activity",
          oninput: (e) => { this.q = e.target.value; this.render(); } }),
        el("select", { "aria-label": "Event type", onchange: (e) => { this.kind = e.target.value; this.reload(); } },
          el("option", { value: "" }, "All events"),
          Object.entries(EVENT_LABELS).map(([k, label]) => el("option", { value: k, selected: this.kind === k }, label))),
        el("span", { class: "toolbar-count muted", id: "ac-count" })),
      el("div", { class: "panel", id: "ac-list" }),
    );
  },
  reload() { this.sig = ""; this.refresh().catch((e) => toast(e.message, true)); },
  async refresh() {
    if (!state.hosts.length) state.hosts = await api("/api/hosts");
    const q = new URLSearchParams({ limit: "500" });
    if (this.kind) q.set("kind", this.kind);
    const events = await api(`/api/events?${q}`);
    const sig = JSON.stringify(events);
    if (sig === this.sig) return;
    this.sig = sig;
    this.events = events;
    this.render();
  },
  render() {
    const q = this.q.toLowerCase();
    const events = this.events.filter((e) => !q || `${e.message} ${e.ip} ${e.mac}`.toLowerCase().includes(q));
    const byDay = new Map();
    for (const e of events) {
      const day = new Date(e.ts).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
      if (!byDay.has(day)) byDay.set(day, []);
      byDay.get(day).push(e);
    }
    $("ac-count").textContent = `${events.length} events`;
    $("ac-list").replaceChildren(...(events.length
      ? [...byDay].map(([day, evs]) => el("section", { class: "day" }, el("h3", {}, day), eventList(evs)))
      : [empty("No activity matches.")]));
  },
};

// ============================================================================
// Page: Rules (suppressions)
// ============================================================================
const RulesPage = {
  title: "Rules",
  sig: "",
  mount(root) {
    this.sig = "";
    const kinds = Object.entries(state.playbooks).sort((a, b) => a[1].title.localeCompare(b[1].title));
    root.replaceChildren(
      pageHead("Suppression rules", "Matching alerts are recorded under Suppressed for audit but never notify."),
      panel("New rule", null,
        el("form", { class: "rule-form", onsubmit: (e) => {
          e.preventDefault();
          const fd = new FormData(e.target);
          act(() => api("/api/suppressions", { method: "POST", body: {
            kind: fd.get("kind"), mac: fd.get("mac") || "", reason: fd.get("reason") || "" } }).then(() => e.target.reset()), "Rule added");
        } },
          el("label", {}, el("span", {}, "Alert type"), el("select", { name: "kind", required: true },
            el("option", { value: "*" }, "Any type"), kinds.map(([k, p]) => el("option", { value: k }, p.title)))),
          el("label", {}, el("span", {}, "Device"), el("select", { name: "mac", id: "rf-mac" })),
          el("label", { class: "grow" }, el("span", {}, "Reason"), el("input", { name: "reason", placeholder: "Authorized vulnerability scanner", maxlength: "300" })),
          el("button", { class: "btn primary", type: "submit" }, "Add rule"))),
      el("div", { class: "panel flush" },
        el("div", { class: "table-wrap" },
          el("table", { class: "table" },
            el("thead", {}, el("tr", {}, ["Alert type", "Device", "Reason", "Created", "Hits", "Last hit", ""].map((t) => el("th", {}, t)))),
            el("tbody", { id: "ru-rows" })),
          el("div", { id: "ru-empty" }))),
    );
  },
  async refresh() {
    if (!state.hosts.length) state.hosts = await api("/api/hosts");
    const rules = await api("/api/suppressions");
    const macSel = $("rf-mac");
    if (macSel && macSel.options.length !== state.hosts.length + 1) {
      const cur = macSel.value;
      macSel.replaceChildren(el("option", { value: "" }, "Any device"),
        state.hosts.map((h) => el("option", { value: h.mac, selected: h.mac === cur }, `${hostName(h)}  (${h.ip})`)));
    }
    const sig = JSON.stringify(rules);
    if (sig === this.sig) return;
    this.sig = sig;
    $("ru-rows").replaceChildren(...rules.map((r) => el("tr", {},
      el("td", {}, r.kind === "*" ? "Any type" : pbTitle(r.kind)),
      el("td", {}, r.mac ? deviceLink(r.mac, r.ip) : r.ip ? el("span", { class: "mono" }, r.ip) : el("span", { class: "muted" }, "Any device")),
      el("td", {}, r.reason || dash()),
      el("td", { class: "mono nowrap muted", title: fullTime(r.created) }, stamp(r.created)),
      el("td", { class: "num" }, String(r.hits)),
      el("td", { class: "nowrap muted" }, r.last_hit ? ago(r.last_hit) : "never"),
      el("td", { class: "right" }, el("button", { class: "btn quiet danger", type: "button",
        onclick: () => confirm("Delete this rule? Matching alerts will notify again.") &&
          act(() => api(`/api/suppressions/${r.id}`, { method: "DELETE" }), "Rule deleted") }, "Delete")))));
    $("ru-empty").replaceChildren(rules.length ? "" : empty("No rules. Create one here, or use “Suppress similar” on an alert."));
  },
};

// ============================================================================
// Drawer: alert investigation
// ============================================================================
async function ensureHosts() {
  if (!state.hosts.length) state.hosts = await api("/api/hosts");
}

// Playbook text marks commands with `backticks`; render those as <code>.
const richText = (text) => text.split("`").map((part, i) => (i % 2 ? el("code", {}, part) : part));

async function openAlertDrawer(id) {
  const [a] = await Promise.all([api(`/api/alerts/${id}`), ensureHosts()]);
  const pb = a.playbook;
  const setStatus = (status, note = "") => act(() => api(`/api/alerts/${a.id}/status`, { method: "POST", body: { status, note } })
    .then(() => reopenDrawer()), `Alert marked ${STATUS_LABELS[status].toLowerCase()}`);

  const noteBox = el("textarea", { rows: "3", placeholder: "Add a note (saved with the next action, or on its own)", maxlength: "1000", "aria-label": "Investigation note" });
  const suppressForm = el("form", { class: "inset", hidden: true, onsubmit: (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    act(() => api("/api/suppressions", { method: "POST", body: {
      kind: a.kind, mac: fd.get("scope") === "device" ? a.mac : "", reason: fd.get("reason") || "", alert_id: a.id } })
      .then(() => reopenDrawer()), "Rule created, alert closed as false positive");
  } },
    el("b", {}, `Suppress “${pb.title}”`),
    a.mac ? el("label", { class: "radio" }, el("input", { type: "radio", name: "scope", value: "device", checked: true }), `from ${hostName(hostByMac(a.mac)) || a.mac} only`) : null,
    el("label", { class: "radio" }, el("input", { type: "radio", name: "scope", value: "any", checked: !a.mac }), "from any device"),
    el("input", { name: "reason", placeholder: "Reason, for the audit trail", maxlength: "300" }),
    el("div", { class: "btn-row" }, el("button", { class: "btn primary", type: "submit" }, "Create rule"),
      el("button", { class: "btn quiet", type: "button", onclick: () => { suppressForm.hidden = true; } }, "Cancel")));

  const open = a.status === "new" || a.status === "investigating";
  const actions = open
    ? [a.status === "new" ? el("button", { class: "btn", type: "button", onclick: () => setStatus("investigating", noteBox.value) }, "Investigate") : null,
       el("button", { class: "btn primary", type: "button", onclick: () => setStatus("resolved", noteBox.value) }, "Resolve"),
       el("button", { class: "btn", type: "button", onclick: () => setStatus("false_positive", noteBox.value) }, "False positive"),
       el("button", { class: "btn quiet", type: "button", onclick: () => { suppressForm.hidden = false; } }, "Suppress similar")]
    : [el("button", { class: "btn", type: "button", onclick: () => setStatus("new", noteBox.value) }, "Reopen")];

  const notes = (a.notes || "").split("\n").filter(Boolean).map((line) => {
    const m = line.match(/^\[([^\]]+)\] (.*)$/);
    return m ? el("li", {}, el("time", { class: "mono muted", title: fullTime(m[1]) }, stamp(m[1])), el("span", {}, m[2])) : el("li", {}, line);
  });

  renderDrawer(
    el("header", { class: "drawer-head" },
      el("div", {},
        el("div", { class: "eyebrow" }, sevTag(a.severity), el("span", { class: "mono muted" }, `#${a.id}`), statusTag(a.status)),
        el("h2", {}, pb.title)),
      closeBtn()),
    el("p", { class: "message" }, a.message),
    el("dl", { class: "kv" },
      el("dt", {}, "Device"), el("dd", {}, a.host ? [deviceLink(a.host.mac, a.host.ip, a.host.name || a.host.ip),
        el("span", { class: "mono muted" }, `  ${a.host.ip}`), a.host.trusted ? "" : el("span", { class: "flag" }, "untrusted")] : (a.ip || a.mac || "—")),
      el("dt", {}, "Detected"), el("dd", { class: "mono" }, fullTime(a.ts)),
      el("dt", {}, "Rule"), el("dd", { class: "mono" }, a.kind),
      pb.tactic ? [el("dt", {}, "Tactic"), el("dd", {}, pb.tactic)] : null,
      pb.mitre.length ? [el("dt", {}, "ATT&CK"), el("dd", { class: "mitre" }, pb.mitre.map((t) =>
        el("a", { class: "link", href: t.url, target: "_blank", rel: "noopener noreferrer" },
          el("span", { class: "mono" }, t.id), ` ${t.name}`, icon("external", 12))))] : null,
      el("dt", {}, "Updated"), el("dd", {}, a.updated_at ? ago(a.updated_at) : "—")),
    el("div", { class: "btn-row" }, actions),
    suppressForm,
    pb.summary ? section("Assessment", el("p", {}, richText(pb.summary))) : null,
    pb.triage.length ? section("Triage", el("ul", { class: "checklist" }, pb.triage.map((t, i) =>
      el("li", {}, el("label", {}, el("input", { type: "checkbox", id: `tri-${i}` }), el("span", {}, richText(t))))))) : null,
    pb.response.length ? section("Response", el("ol", { class: "steps" }, pb.response.map((t) => el("li", {}, richText(t))))) : null,
    section(`Notes${notes.length ? ` (${notes.length})` : ""}`,
      notes.length ? el("ul", { class: "notes" }, notes) : null,
      noteBox,
      el("div", {}, el("button", { class: "btn", type: "button", onclick: () => {
        if (!noteBox.value.trim()) return;
        act(() => api(`/api/alerts/${a.id}/note`, { method: "POST", body: { note: noteBox.value } }).then(() => reopenDrawer()), "Note added");
      } }, "Add note"))),
    a.related.length ? section(`Other alerts on this device (${a.related.length})`,
      el("ul", { class: "rows" }, a.related.slice(0, 10).map((r) => el("li", {},
        el("a", { href: `#/alerts/${r.id}`, class: "row-link" }, sevTag(r.severity),
          el("span", { class: "row-main" }, el("b", {}, pbTitle(r.kind)), el("small", {}, r.message)),
          statusTag(r.status)))))) : null,
    section("Raw event", el("pre", { class: "json" }, JSON.stringify(a.details, null, 2))),
  );
}

// ============================================================================
// Drawer: device investigation
// ============================================================================
async function openDeviceDrawer(mac) {
  const h = await api(`/api/hosts/${encodeURIComponent(mac)}`);
  const alias = el("input", { value: h.alias, placeholder: "Alex's laptop", maxlength: "80" });
  const notes = el("textarea", { rows: "3", placeholder: "Owner, purpose, location", maxlength: "4000" });
  notes.value = h.notes;

  const timeline = [
    ...h.events.map((e) => ({ ts: e.ts, node: () => el("li", {}, eventDot(e.kind),
      el("time", { datetime: e.ts, title: fullTime(e.ts) }, stamp(e.ts)),
      el("div", { class: "tl-body" }, el("span", { class: "tl-kind" }, EVENT_LABELS[e.kind] || e.kind), el("span", {}, e.message))) })),
    ...h.alerts.map((a) => ({ ts: a.ts, node: () => el("li", {}, el("span", { class: `tl-dot sev-bg-${a.severity}` }),
      el("time", { datetime: a.ts, title: fullTime(a.ts) }, stamp(a.ts)),
      el("div", { class: "tl-body" }, el("span", { class: "tl-kind" }, `${titleCase(a.severity)} alert`),
        el("a", { href: `#/alerts/${a.id}`, class: "link" }, `${pbTitle(a.kind)}: ${a.message}`),
        el("span", { class: "muted" }, STATUS_LABELS[a.status]))) })),
  ].sort((x, y) => y.ts.localeCompare(x.ts)).slice(0, 80);

  renderDrawer(
    el("header", { class: "drawer-head" },
      el("div", {},
        el("div", { class: "eyebrow" }, icon(h.type, 15), el("span", {}, h.type_label),
          el("span", { class: `presence-txt ${h.online ? "on" : "off"}` }, h.online ? "online" : "offline"),
          h.trusted ? el("span", { class: "muted" }, "trusted") : el("span", { class: "flag" }, "untrusted")),
        el("h2", {}, hostName(h)),
        el("p", { class: "mono muted" }, `${h.ip}   ${h.mac}`)),
      closeBtn()),
    el("div", { class: "btn-row" },
      h.trusted
        ? el("button", { class: "btn", type: "button", onclick: () => act(() => api(`/api/hosts/${h.mac}/untrust`, { method: "POST" }).then(reopenDrawer), "Marked untrusted") }, "Untrust")
        : el("button", { class: "btn primary", type: "button", onclick: () => act(() => api(`/api/hosts/${h.mac}/trust`, { method: "POST" }).then(reopenDrawer), "Device trusted") }, "Trust device"),
      el("button", { class: "btn", type: "button", onclick: () => { AlertsPage.filters = { ...AlertsPage.defaults(), status: "all", mac: h.mac }; go("alerts"); } }, "Show alerts"),
      el("button", { class: "btn quiet danger", type: "button", onclick: () =>
        confirm(`Forget ${hostName(h)}? It will be reported as new if seen again.`) &&
        act(() => api(`/api/hosts/${h.mac}`, { method: "DELETE" }).then(() => closeDrawer()), "Device forgotten") }, "Forget")),
    el("dl", { class: "kv" },
      el("dt", {}, "Risk"), el("dd", {}, riskCell(h), el("span", { class: "muted" }, " / 100")),
      el("dt", {}, "Vendor"), el("dd", {}, h.vendor || "—"),
      el("dt", {}, "Hostname"), el("dd", { class: "mono" }, h.hostname || "—"),
      el("dt", {}, "First seen"), el("dd", { class: "mono" }, fullTime(h.first_seen)),
      el("dt", {}, "Last seen"), el("dd", {}, ago(h.last_seen))),
    section("Risk factors", h.risk_factors.length
      ? el("ul", { class: "factors" }, h.risk_factors.map((f) => el("li", {}, el("span", { class: "mono" }, `+${f.points}`), f.reason)))
      : el("p", { class: "muted" }, "None. Trusted, no open alerts, no remote-access ports.")),
    section("Ports", h.ports.length ? el("table", { class: "table compact" },
      el("thead", {}, el("tr", {}, ["Port", "Service", "State", "First seen"].map((t) => el("th", {}, t)))),
      el("tbody", {}, h.ports.map((p) => el("tr", {},
        el("td", {}, el("span", { class: `port${p.risky ? " risky" : ""}` }, String(p.port))),
        el("td", {}, p.service || "—"),
        el("td", {}, el("span", { class: `presence-txt ${p.open ? "on" : "off"}` }, p.open ? "open" : "closed")),
        el("td", { class: "mono muted" }, stamp(p.first_seen))))))
      : el("p", { class: "muted" }, "No listening ports among the common ports checked.")),
    section("Analyst notes",
      el("label", { class: "field" }, el("span", {}, "Alias"), alias),
      el("label", { class: "field" }, el("span", {}, "Notes"), notes),
      el("div", {}, el("button", { class: "btn", type: "button", onclick: () =>
        act(() => api(`/api/hosts/${h.mac}`, { method: "POST", body: { alias: alias.value, notes: notes.value } }).then(reopenDrawer), "Saved") }, "Save"))),
    section("Timeline", timeline.length ? el("ol", { class: "timeline" }, timeline.map((t) => t.node())) : el("p", { class: "muted" }, "Nothing recorded yet.")),
  );
}

// ============================================================================
// Drawer plumbing
// ============================================================================
function section(title, ...body) {
  return el("section", { class: "dsec" }, el("h3", {}, title), ...body);
}

function closeBtn() {
  return el("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: closeDrawer }, icon("close", 16));
}

function renderDrawer(...children) {
  const d = $("drawer");
  $("drawer-body").replaceChildren(...children.flat(Infinity).filter(Boolean));
  d.classList.add("open");
  d.setAttribute("aria-hidden", "false");
  $("scrim").hidden = false;
  d.focus({ preventScroll: true });
}

function closeDrawer() {
  if (state.arg) location.hash = `#/${state.pageName}`;
  hideDrawer();
}

function hideDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("scrim").hidden = true;
  state.drawer = null;
}

async function reopenDrawer() {
  if (!state.drawer) return;
  const { type, id } = state.drawer;
  const scroll = $("drawer-body").scrollTop;
  try {
    if (type === "alert") await openAlertDrawer(id);
    else await openDeviceDrawer(id);
    $("drawer-body").scrollTop = scroll;
  } catch (err) {
    toast(err.message, true);
    closeDrawer();
  }
}

// ============================================================================
// Router & refresh loop
// ============================================================================
const PAGES = { overview: OverviewPage, alerts: AlertsPage, devices: DevicesPage, activity: ActivityPage, rules: RulesPage };

function go(page, arg = "") {
  location.hash = `#/${page}${arg ? "/" + encodeURIComponent(arg) : ""}`;
}

async function route() {
  const [, name = "overview", rawArg = ""] = location.hash.match(/^#\/([a-z]+)\/?(.*)$/) || [];
  const pageName = PAGES[name] ? name : "overview";
  const arg = decodeURIComponent(rawArg);

  if (pageName !== state.pageName) {
    state.pageName = pageName;
    state.page = PAGES[pageName];
    document.querySelectorAll(".nav a").forEach((a) => {
      const on = a.dataset.page === pageName;
      a.classList.toggle("on", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    document.title = `${state.page.title} · NetGuard`;
    state.page.mount($("page"));
    refresh();
  }

  state.arg = arg;
  if (!arg) { hideDrawer(); return; }
  const type = pageName === "alerts" ? "alert" : pageName === "devices" ? "device" : null;
  if (!type) return;
  state.drawer = { type, id: arg };
  try {
    if (type === "alert") await openAlertDrawer(arg);
    else await openDeviceDrawer(arg);
  } catch (err) {
    toast(err.message, true);
    closeDrawer();
  }
}

async function refresh() {
  clearTimeout(state.timer);
  try {
    state.status = await api("/api/status");
    renderStatus();
    if (state.page) await state.page.refresh();
  } catch (err) {
    $("status-pill").className = "mon-state err";
    $("status-pill").textContent = "Offline";
    $("banner").hidden = false;
    $("banner").textContent = `Can't reach NetGuard: ${err.message}`;
  }
  const busy = state.status?.status?.scanning;
  state.timer = setTimeout(refresh, busy ? POLL_BUSY_MS : POLL_MS);
}

// ============================================================================
// Wiring
// ============================================================================
$("scan-btn").addEventListener("click", () => act(() => api("/api/scan", { method: "POST" }), "Scan started"));
$("scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.drawer) closeDrawer(); });
window.addEventListener("hashchange", route);
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (state.page) { state.page.sig = ""; refresh(); } }, 200);
});
setInterval(renderStatus, 1000);  // keeps the countdown ticking between polls

(async () => {
  try { state.playbooks = await api("/api/playbooks"); } catch { /* shown by refresh() */ }
  if (!location.hash) history.replaceState(null, "", "#/overview");
  route();
})();

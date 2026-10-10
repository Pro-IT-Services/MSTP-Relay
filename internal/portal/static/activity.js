// Activity page: renders /activity/data and refreshes it while "Live" is on.
// All values from the server are inserted with textContent, never as HTML: device names and
// SMTP greetings are chosen by whoever connects.
(() => {
  const root = document.getElementById("activity");
  if (!root) return;

  const state = { range: "24h", kind: "", q: "", auto: true, data: null, timer: null, loading: false };
  const $ = (id) => document.getElementById(id);

  // el("td", {class: "mono"}, "text", childNode, ...)
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids) if (k != null && k !== false) n.append(k);
    return n;
  }
  const svgEl = (tag, attrs) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    return n;
  };

  const pad = (n) => String(n).padStart(2, "0");
  const fmtTime = (s) => { const d = new Date(s * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const fmtClock = (s) => { const d = new Date(s * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const fmtDay = (s) => { const d = new Date(s * 1000); return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`; };
  function ago(s) {
    const sec = Math.max(0, Math.floor(Date.now() / 1000 - s));
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
    return `${Math.floor(sec / 86400)} d ago`;
  }
  const num = (n) => Number(n).toLocaleString("en-US");

  const OUTCOMES = {
    ok: ["delivered", "ok"],
    idle: ["no message", ""],
    tls_failed: ["TLS failed", "bad"],
    auth_failed: ["login failed", "bad"],
    rejected: ["rejected", "warn"],
    failed: ["send failed", "bad"],
  };
  function pill(outcome) {
    const [label, cls] = OUTCOMES[outcome] || [outcome, ""];
    return el("span", { class: "pill " + cls, text: label });
  }

  // ---------- data ----------

  async function load() {
    if (state.loading) return;
    state.loading = true;
    try {
      const p = new URLSearchParams({ range: state.range, kind: state.kind, q: state.q });
      const res = await fetch("/activity/data?" + p, { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (res.redirected || res.status === 401 || res.status === 403) { location.href = "/login"; return; } // session ended
      if (!res.ok) throw new Error("HTTP " + res.status);
      state.data = await res.json();
      render();
      $("act-updated").textContent = "Updated " + fmtTime(state.data.generated).slice(11);
    } catch (e) {
      $("act-updated").textContent = "Update failed: " + e.message;
    } finally {
      state.loading = false;
    }
  }

  function schedule() {
    clearInterval(state.timer);
    if (state.auto) state.timer = setInterval(() => { if (!document.hidden) load(); }, 10000);
  }

  // ---------- rendering ----------

  function render() {
    const d = state.data;
    renderTiles(d);
    renderChart(d);
    renderDevices(d);
    renderBlocked(d);
    renderConns(d);
  }

  function renderTiles(d) {
    const s = d.stats;
    const tile = (label, value, bad) => el("div", { class: "tile" },
      el("span", { class: "label", text: label }),
      el("span", { class: "value" + (bad ? " bad" : ""), text: num(value) }));
    const tiles = [
      tile("Connections", s.connections),
      tile("Devices", s.devices),
      tile("Messages delivered", s.delivered),
      tile("Connections with problems", s.problems, s.problems > 0),
    ];
    if (d.firewall) tiles.push(tile("Addresses blocked by firewall", s.blocked));
    $("act-tiles").replaceChildren(...tiles);
  }

  // Stacked columns: healthy connections at the baseline, problems on top.
  function renderChart(d) {
    const box = $("act-chart");
    const total = d.buckets.reduce((a, b) => a + b.ok + b.problems, 0);
    const problems = d.buckets.reduce((a, b) => a + b.problems, 0);
    $("act-chart-sub").textContent = `Connections that reached the relay in the ${d.label}, per ${d.stepHours === 1 ? "hour" : d.stepHours === 24 ? "day" : d.stepHours + " hours"}.`;
    const key = (cls, label, n) => el("span", { class: "legend-item" }, el("span", { class: "swatch " + cls }), `${label} `, el("strong", { text: num(n) }));
    $("act-legend").replaceChildren(key("s-ok", "Delivered or no message", total - problems), key("s-problem", "Problems", problems));

    if (!total) {
      box.replaceChildren(el("p", { class: "muted empty-chart", text: "No connections in this period." }));
      return;
    }
    const W = Math.max(320, box.clientWidth), H = 220;
    const m = { l: 40, r: 8, t: 10, b: 24 };
    const pw = W - m.l - m.r, ph = H - m.t - m.b;
    const n = d.buckets.length;
    const band = pw / n;
    const bw = Math.max(2, Math.min(24, band * 0.7));
    const peak = Math.max(...d.buckets.map((b) => b.ok + b.problems));
    const step = niceStep(peak);
    const top = Math.max(step, Math.ceil(peak / step) * step);
    const y = (v) => m.t + ph - (v / top) * ph;

    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img",
      "aria-label": `Connections per period: ${total} in total, ${problems} with problems. The same data is in the Connections table below.` });
    for (let v = 0; v <= top; v += step) {
      svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: "grid" }));
      const t = svgEl("text", { x: m.l - 6, y: y(v) + 4, class: "tick", "text-anchor": "end" });
      t.textContent = num(v);
      svg.append(t);
    }
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 64)))); // one x label per ~64px
    const tip = el("div", { class: "chart-tip", hidden: true });
    d.buckets.forEach((b, i) => {
      const x = m.l + i * band + (band - bw) / 2;
      const gap = b.ok && b.problems ? 2 : 0; // surface gap between the two segments
      const hOK = b.ok ? Math.max(1, (b.ok / top) * ph - gap / 2) : 0;
      const hPr = b.problems ? Math.max(1, (b.problems / top) * ph - gap / 2) : 0;
      if (b.ok) svg.append(svgEl("path", { d: column(x, m.t + ph - hOK, bw, hOK, b.problems ? 0 : 4), class: "s-ok" }));
      if (b.problems) svg.append(svgEl("path", { d: column(x, m.t + ph - hOK - gap - hPr, bw, hPr, 4), class: "s-problem" }));
      if (i % every === 0) {
        const t = svgEl("text", { x: m.l + i * band + band / 2, y: H - 6, class: "tick", "text-anchor": "middle" });
        t.textContent = d.stepHours >= 24 ? fmtDay(b.start) : d.stepHours > 1 ? `${fmtDay(b.start)} ${fmtClock(b.start)}` : fmtClock(b.start);
        svg.append(t);
      }
      // Hit target: the whole band, far bigger than the mark.
      const hit = svgEl("rect", { x: m.l + i * band, y: m.t, width: band, height: ph, class: "hit", tabindex: 0 });
      const end = b.start + d.stepHours * 3600;
      const label = d.stepHours >= 24 ? fmtDay(b.start) : `${fmtDay(b.start)} ${fmtClock(b.start)}–${fmtClock(end)}`;
      hit.setAttribute("aria-label", `${label}: ${b.ok} delivered or no message, ${b.problems} with problems`);
      const show = () => {
        tip.replaceChildren(
          el("strong", { text: label }),
          el("div", {}, el("span", { class: "swatch s-ok" }), `Delivered or no message: ${num(b.ok)}`),
          el("div", {}, el("span", { class: "swatch s-problem" }), `Problems: ${num(b.problems)}`));
        tip.hidden = false;
        const cx = m.l + i * band + band / 2;
        tip.style.left = Math.min(Math.max(cx, 90), W - 90) + "px";
      };
      hit.addEventListener("mouseenter", show);
      hit.addEventListener("focus", show);
      hit.addEventListener("mouseleave", () => { tip.hidden = true; });
      hit.addEventListener("blur", () => { tip.hidden = true; });
      svg.append(hit);
    });
    svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: m.t + ph, y2: m.t + ph, class: "axis" }));
    box.replaceChildren(svg, tip);
  }

  // A column with a rounded top (radius r) and a square bottom.
  function column(x, y, w, h, r) {
    r = Math.min(r, w / 2, h);
    return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
  }
  function niceStep(peak) {
    for (const s of [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]) if (peak / s <= 4) return s;
    return 20000;
  }

  const NUMERIC = new Set(["Connections", "Delivered", "Problems", "Dropped attempts"]); // right-aligned columns
  function table(headers, rows, empty) {
    if (!rows.length) return el("p", { class: "muted", text: empty });
    return el("table", {},
      el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { text: h, class: NUMERIC.has(h) && "numcol" })))),
      el("tbody", {}, ...rows));
  }

  // Link to the host form with the address already filled in.
  const addHostLink = (ip) => el("a", { href: "/hosts/new?match=" + encodeURIComponent(ip), text: "Add a host" });

  function deviceCell(host, helo, ip) {
    return el("td", {},
      host ? el("strong", { text: host }) : el("span", {}, el("span", { class: "pill warn", text: "no host rule" }), " ", addHostLink(ip)),
      helo ? el("div", { class: "muted small", text: "announces: " + helo }) : null);
  }

  function renderDevices(d) {
    const q = state.q.toLowerCase();
    const list = d.devices.filter((v) => !q || [v.ip, v.host, v.helo, v.lastDetail].some((s) => (s || "").toLowerCase().includes(q)));
    const rows = list.map((v) => {
      const ip = el("button", { type: "button", class: "link mono", title: "Show only this address", text: v.ip });
      ip.addEventListener("click", () => setQuery(v.ip));
      return el("tr", {},
        deviceCell(v.host, v.helo, v.ip),
        el("td", {}, ip),
        el("td", { class: "nowrap", title: fmtTime(v.lastSeen), text: ago(v.lastSeen) }),
        el("td", { class: "numcol", text: num(v.connections) }),
        el("td", { class: "numcol", text: num(v.sent) }),
        el("td", { class: "numcol" + (v.problems ? " bad" : ""), text: num(v.problems) }),
        el("td", {}, pill(v.lastOutcome), el("div", { class: "muted small detail", text: v.lastDetail })));
    });
    $("act-devices").replaceChildren(table(
      ["Device", "Address", "Last seen", "Connections", "Delivered", "Problems", "Latest connection"],
      rows, "No device connected in this period."));
  }

  function renderBlocked(d) {
    $("act-blocked-card").hidden = !d.firewall;
    if (!d.firewall) return;
    const rows = d.blocked.map((b) => el("tr", {},
      el("td", { class: "mono", text: b.ip }),
      el("td", { class: "numcol", text: num(b.packets) }),
      el("td", { class: "nowrap", title: fmtTime(b.lastSeen), text: ago(b.lastSeen) }),
      el("td", {}, b.host
        ? el("span", {}, el("span", { class: "pill ok", text: "allowed now" }), ` by host rule “${b.host}”`)
        : el("span", {}, "No enabled host rule. ", addHostLink(b.ip), " to let it send."))));
    $("act-blocked").replaceChildren(table(["Address", "Dropped attempts", "Last attempt", ""], rows,
      "Nothing was blocked in this period."));
  }

  function renderConns(d) {
    const rows = d.conns.map((c) => el("tr", {},
      el("td", { class: "nowrap", title: ago(c.time), text: fmtTime(c.time) }),
      el("td", {}, pill(c.outcome)),
      el("td", {},
        c.host ? el("strong", { text: c.host }) : el("span", { class: "muted", text: "no host rule" }),
        el("div", { class: "mono muted", text: `${c.ip} :${c.port}` })),
      el("td", { class: "clip", title: c.helo, text: c.helo || "—" }),
      el("td", {},
        c.tls ? el("span", { text: c.tls.replace("TLS_", "") }) : el("span", { class: "muted", text: "plain text" }),
        c.tls && c.certKey ? el("div", { class: "muted small", text: c.certKey + " certificate" }) : null),
      el("td", {}, c.authUser
        ? el("span", {}, el("span", { class: "mono", text: c.authUser }), " ", el("span", { class: "pill " + (c.authOK ? "ok" : "bad"), text: c.authOK ? "ok" : "failed" }))
        : el("span", { class: "muted", text: "—" })),
      el("td", { class: "detail", text: c.detail })));
    $("act-conns-sub").textContent = d.conns.length >= 300
      ? "Newest first. Showing the latest 300; narrow the filter to see older ones."
      : `Newest first. ${num(d.conns.length)} shown.`;
    $("act-conns").replaceChildren(table(
      ["Time", "Result", "Device", "Announced name", "Encryption", "Login", "Detail"],
      rows, "No connections match."));
  }

  // ---------- controls ----------

  function setQuery(q) {
    state.q = q;
    $("act-q").value = q;
    load();
  }
  function segment(id, attr, key) {
    $(id).addEventListener("click", (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      state[key] = b.dataset[attr];
      for (const x of $(id).querySelectorAll("button")) x.classList.toggle("on", x === b);
      load();
    });
  }
  segment("act-range", "range", "range");
  segment("act-kind", "kind", "kind");
  let typing;
  $("act-q").addEventListener("input", (e) => {
    clearTimeout(typing);
    typing = setTimeout(() => { state.q = e.target.value.trim(); load(); }, 250);
  });
  $("act-auto").addEventListener("change", (e) => { state.auto = e.target.checked; schedule(); if (state.auto) load(); });
  let resizing;
  window.addEventListener("resize", () => { clearTimeout(resizing); resizing = setTimeout(() => state.data && renderChart(state.data), 150); });

  load();
  schedule();
})();

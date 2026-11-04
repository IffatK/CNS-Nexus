(() => {
  "use strict";
  const form = document.getElementById("chart-filters");
  if (!form) return;
  const themeColor = (name, fallback) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
  const colors = () => document.querySelector(".dashboard-analytics")
    ? ["#D24E57", "#E9A257", "#75C99A", "#9585E8", "#68BBD0"]
    : ["#B52A32", "#8F2029", themeColor("--success", "#557A5C"), "#C28A2C", "#8B776B"];
  const names = {
    "chart-integrity": ["verified", "invalid", "errors", "unprotected"],
    "chart-attacker": ["intercepted", "unchanged_forwarded", "modified_forwarded", "dropped"],
    "chart-scans": ["clean", "infected", "suspicious", "failed"],
    "chart-severity": ["info", "warning", "critical"],
    "chart-files": ["successful", "failed"],
    "chart-activity": ["authentication", "message and relay", "malware scanning", "file integrity and sharing", "other security"]
  };
  const labels = {
    verified: "Valid signature", invalid: "Invalid signature",
    errors: "Verification error", unprotected: "Plaintext relay", intercepted: "Intercepted",
    unchanged_forwarded: "Forwarded unchanged", modified_forwarded: "Modified and forwarded", dropped: "Dropped",
    clean: "Clean", infected: "Infected", suspicious: "Suspicious", failed: "Scan failed",
    info: "Info", warning: "Warning", critical: "Critical", successful: "Successful checks",
    authentication: "Authentication", "message and relay": "Messages and relay",
    "malware scanning": "Malware scanning", "file integrity and sharing": "Files and integrity",
    "other security": "Other security"
  };
  const el = (id) => document.getElementById(id);
  const setState = (message) => { el("chart-state").textContent = message; };

  function draw(id, series, type = "bar") {
    const canvas = el(id), ctx = canvas.getContext("2d");
    if (!ctx) return;
    const board = canvas.closest(".dashboard-analytics");
    const color = (name, fallback) => board
      ? getComputedStyle(board).getPropertyValue(name).trim() || fallback
      : themeColor(name, fallback);
    const box = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(320, box.width) * ratio;
    canvas.height = 230 * ratio;
    ctx.scale(ratio, ratio);
    const w = canvas.width / ratio, h = canvas.height / ratio;
    ctx.clearRect(0, 0, w, h);
    const flattened = series.flatMap(s => s.values.map(v => v.count));
    const max = Math.max(1, ...flattened);
    const palette = colors();
    const colorsUsed = series.map((_, i) => palette[i % palette.length]);
    const points = [];
    ctx.font = "11px system-ui";
    ctx.fillStyle = color("--chart-text", "#82746D");
    ctx.strokeStyle = color("--chart-grid", "#D7C3B0");
    ctx.lineWidth = 1;
    const left = 35, right = 8, top = 8, bottom = 38, plotH = h - top - bottom, plotW = w - left - right;
    for (let i = 0; i <= 4; i++) {
      const y = top + plotH * i / 4;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(w - right, y); ctx.stroke();
      ctx.fillText(String(Math.round(max * (4 - i) / 4)), 3, y + 4);
    }
    if (!flattened.some(n => n > 0)) {
      ctx.fillStyle = color("--chart-text", "#82746D"); ctx.textAlign = "center"; ctx.fillText("No records in this range", w / 2, h / 2); ctx.textAlign = "left";
    } else if (type === "line") {
      series.forEach((s, si) => {
        ctx.strokeStyle = colorsUsed[si]; ctx.lineWidth = 2; ctx.beginPath();
        s.values.forEach((p, i) => {
          const x = left + (s.values.length < 2 ? plotW / 2 : i * plotW / (s.values.length - 1));
          const y = top + plotH - p.count / max * plotH;
          if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
          ctx.fillStyle = colorsUsed[si]; ctx.fillRect(x - 2, y - 2, 4, 4);
          points.push({x, y, name: s.name, count: p.count, label: p.label});
        });
        ctx.stroke();
      });
    } else if (type === "donut") {
      const totals = series.map(s => s.values.reduce((a, p) => a + p.count, 0));
      const total = totals.reduce((a, n) => a + n, 0), cx = w / 2, cy = top + plotH / 2, radius = Math.min(plotH, plotW) * .39;
      let angle = -Math.PI / 2;
      totals.forEach((n, i) => {
        if (!n || !total) return;
        const end = angle + n / total * Math.PI * 2;
        ctx.beginPath(); ctx.arc(cx, cy, radius, angle, end); ctx.strokeStyle = colorsUsed[i]; ctx.lineWidth = 20; ctx.stroke(); angle = end;
      });
      ctx.fillStyle = color("--chart-center", themeColor("--charcoal", "#292322")); ctx.textAlign = "center"; ctx.fillText(String(total), cx, cy + 4); ctx.textAlign = "left";
    } else {
      const count = series[0].values.length, group = plotW / Math.max(1, count), bw = Math.max(2, Math.min(20, group * .72));
      series.forEach((s, si) => s.values.forEach((p, i) => {
        const groupW = group / series.length;
        const x = left + i * group + si * groupW + (groupW - bw) / 2;
        const bh = p.count / max * plotH;
        ctx.fillStyle = colorsUsed[si]; ctx.fillRect(x, top + plotH - bh, bw, bh);
        points.push({x: x + bw / 2, y: top + plotH - bh, name: s.name, count: p.count, label: p.label});
      }));
    }
    if (series.length && series[0].values.length) {
      const ticks = series[0].values, stride = Math.max(1, Math.ceil(ticks.length / 6));
      ctx.fillStyle = color("--chart-text", "#82746D");
      ticks.forEach((p, i) => { if (i % stride === 0 || i === ticks.length - 1) ctx.fillText(p.label.slice(5), left + i * plotW / Math.max(1, ticks.length - 1), h - 15); });
    }
    canvas.setAttribute("aria-label", `${id.replace("chart-", "")} chart. ${series.map(s => `${labels[s.name] || s.name}: ${s.values.reduce((a, p) => a + p.count, 0)}`).join("; ")}`);
    canvas.onmousemove = event => {
      const rect = canvas.getBoundingClientRect();
      const x = (event.clientX - rect.left) * w / rect.width;
      const y = (event.clientY - rect.top) * h / rect.height;
      let nearest, distance = Infinity;
      points.forEach(point => { const d = Math.hypot(point.x - x, point.y - y); if (d < distance) { nearest = point; distance = d; } });
      canvas.title = nearest && distance < 20 ? `${labels[nearest.name] || nearest.name}: ${nearest.count} (${nearest.label})` : "";
    };
    const summary = series.map(s => `${labels[s.name] || s.name}: ${s.values.reduce((a, p) => a + p.count, 0)}`).join(" · ");
    el(`${id}-summary`).textContent = summary || "No records in this range.";
    const legend = el(`${id}-legend`);
    legend.replaceChildren(...series.map((s, i) => {
      const item = document.createElement("li"), swatch = document.createElement("span"), name = document.createElement("span"), value = document.createElement("b");
      swatch.className = "legend-swatch"; swatch.style.backgroundColor = colorsUsed[i];
      name.textContent = labels[s.name] || s.name;
      value.textContent = String(s.values.reduce((a, p) => a + p.count, 0));
      item.append(swatch, name, value); return item;
    }));
    const ul = el(`${id}-data`);
    ul.replaceChildren();
    series.forEach(s => {
      const li = document.createElement("li");
      li.textContent = `${labels[s.name] || s.name}: ${s.values.reduce((a, p) => a + p.count, 0)}`;
      ul.append(li);
    });
  }

  function constantSeries(map, keys) {
    return keys.map(key => ({ name: key, values: [{ label: "total", count: Number(map[key] || 0) }] }));
  }

  async function load() {
    setState("Loading chart data…");
    const params = new URLSearchParams({ days: el("chart-days").value });
    if (params.get("days") === "custom") {
      if (!el("chart-from").value || !el("chart-to").value) { setState("Choose both custom dates."); return; }
      params.set("date_from", el("chart-from").value); params.set("date_to", el("chart-to").value);
    }
    params.set("event_type", el("chart-event-type").value);
    params.set("severity", el("chart-severity-filter").value);
    try {
      const response = await fetch(`/api/dashboard/metrics?${params}`, { headers: { Accept: "application/json" }, credentials: "same-origin" });
      if (!response.ok) throw new Error(response.status === 401 ? "Session expired. Sign in again." : "Chart data is unavailable.");
      const data = await response.json();
      const select = el("chart-event-type"), selected = select.value;
      if (select.options.length === 1) data.event_types.forEach(type => { const option = document.createElement("option"); option.value = type; option.textContent = type; select.append(option); });
      select.value = selected;
      draw("chart-timeline", [{ name: "Events", values: data.timeline }], "line");
      draw("chart-integrity", constantSeries(data.integrity, names["chart-integrity"]), "donut");
      draw("chart-attacker", constantSeries(data.attacker, names["chart-attacker"]));
      draw("chart-logins", [
        { name: "Successful", values: data.logins.successful }, { name: "Failed", values: data.logins.failed }
      ], "line");
      draw("chart-scans", constantSeries(data.scans, names["chart-scans"]));
      draw("chart-severity", constantSeries(data.severity, names["chart-severity"]));
      draw("chart-files", constantSeries(data.file_integrity, names["chart-files"]));
      draw("chart-activity", constantSeries(data.activity, names["chart-activity"]));
      setState(`Updated ${new Date().toLocaleTimeString()}`);
    } catch (error) { setState(error.message); }
  }

  el("chart-days").addEventListener("change", () => { document.querySelectorAll(".custom-date").forEach(x => x.hidden = el("chart-days").value !== "custom"); });
  form.addEventListener("submit", event => { event.preventDefault(); load(); });
  window.addEventListener("cns-theme-change", load);
  let resizeTimer;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(load, 180); });
  load();
})();

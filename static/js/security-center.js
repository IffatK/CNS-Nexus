(() => {
  const sectionLinks = [...document.querySelectorAll('.scanner-nav a[href^="#"]')];
  const sections = sectionLinks.map(link => ({link, section: document.querySelector(link.getAttribute("href"))})).filter(item => item.section);
  const markSection = section => sectionLinks.forEach(link => {
    const active = link.getAttribute("href") === `#${section?.id}`;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  });
  sectionLinks.forEach(link => link.addEventListener("click", () => markSection(document.querySelector(link.getAttribute("href")))));
  markSection(sections.find(item => item.section.id === location.hash.slice(1))?.section || sections[0]?.section);
  if ("IntersectionObserver" in window) {
    const sectionObserver = new IntersectionObserver(entries => {
      const current = entries.filter(entry => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (current) markSection(current.target);
    }, {rootMargin: "-18% 0px -70% 0px", threshold: [0, .15, .35]});
    sections.forEach(({section}) => sectionObserver.observe(section));
  }
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  async function csrf() {
    const response = await fetch("/api/csrf", {credentials: "same-origin", cache: "no-store"});
    if (!response.ok) throw new Error("Could not refresh CSRF token.");
    return (await response.json()).csrf_token;
  }
  async function cancel(id) {
    const token = await csrf();
    return fetch(`/security-center/api/scans/${id}/cancel`, {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRFToken": token}, body: "{}"});
  }
  async function watch(id, progress, button) {
    button.hidden = false;
    let cancelled = false;
    button.onclick = async () => {
      if (cancelled) return;
      cancelled = true; button.disabled = true; progress.querySelector("p").textContent = "Cancellation requested…";
      try { await cancel(id); } catch (_) { progress.querySelector("p").textContent = "Could not cancel. Checking scan state…"; }
    };
    for (let attempt = 0; attempt < 1200; attempt += 1) {
      const response = await fetch(`/security-center/api/scans/${id}`, {credentials: "same-origin", cache: "no-store"});
      if (!response.ok) throw new Error(`Status check failed (HTTP ${response.status}).`);
      const scan = await response.json();
      const bar = progress.querySelector(".progress-track span");
      const text = progress.querySelector("p");
      bar.style.width = `${Math.max(0, Math.min(100, scan.progress || 0))}%`;
      text.textContent = `Scan #${id} · ${scan.status[0].toUpperCase()}${scan.status.slice(1)} · ${scan.progress}%`;
      if (["completed", "partial", "failed", "cancelled"].includes(scan.status)) {
        text.textContent = scan.error ? `${scan.status.toUpperCase()} · ${scan.error}` : `${scan.status.toUpperCase()} · opening report…`;
        button.hidden = true;
        window.location.assign(scan.detail_url);
        return;
      }
      await pause(700);
    }
    throw new Error("Scan status timed out. Open the Security Analysis Center to check its saved state.");
  }
  document.querySelectorAll("form[data-scan-form]").forEach(form => {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      const progress = form.querySelector(".scan-progress");
      const status = progress.querySelector("p");
      const cancelButton = progress.querySelector(".cancel-scan");
      const bar = progress.querySelector(".progress-track span");
      button.disabled = true; button.setAttribute("aria-busy", "true");
      status.textContent = "Submitting scan…"; progress.classList.add("active"); bar.style.width = "4%";
      try {
        const token = await csrf();
        const response = await fetch(form.action, {method: "POST", credentials: "same-origin", body: new FormData(form),
          headers: {"Accept": "application/json", "X-CSRFToken": token}});
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || `Scan request failed (HTTP ${response.status}).`);
        if (!result.id) throw new Error("The scan was accepted without a status identifier.");
        status.textContent = `Scan #${result.id} accepted · ${result.status}`;
        await watch(result.id, progress, cancelButton);
      } catch (error) {
        status.textContent = error.message || "Could not start the scan.";
        bar.style.width = "0"; cancelButton.hidden = true;
        button.disabled = false; button.removeAttribute("aria-busy");
      }
    });
  });
  const detail = document.querySelector("[data-detail-scan]");
  if (detail) {
    const id = detail.dataset.detailScan;
    const button = detail.querySelector(".cancel-detail");
    watch(id, detail, button).catch(error => { const p = detail.querySelector("p"); if (p) p.textContent = error.message; });
  }
  const mode = document.querySelector("#scan-mode");
  const estimate = document.querySelector("[data-scan-estimate]");
  if (mode && estimate) mode.addEventListener("change", () => {
    estimate.textContent = mode.value === "comprehensive"
      ? "Typical duration: several seconds; includes up to five additional same-host requests. DNS and target response times vary."
      : "Typical duration: a few seconds, depending on DNS and target response.";
  });
})();

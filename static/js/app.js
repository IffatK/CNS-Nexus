(function () {
  "use strict";
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.content : "";

  async function post(url, body) {
    for (var attempt = 0; attempt < 2; attempt += 1) {
      var csrf = await fetch("/api/csrf", {credentials: "same-origin", cache: "no-store"});
      if (!csrf.ok) return csrf;
      token = (await csrf.json()).csrf_token;
      var response = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRFToken": token},
      body: JSON.stringify(body || {})
      });
      if (response.status !== 400 || attempt > 0) return response;
      var payload = await response.clone().json().catch(function () { return {}; });
      if (payload.error !== "CSRF validation failed") return response;
    }
  }
  window.cnsPostJSON = post;

  function updateThemeButtons() {
    var dark = document.documentElement.dataset.theme === "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      button.setAttribute("aria-pressed", String(dark));
      button.setAttribute("aria-label", "Switch to " + (dark ? "light" : "dark") + " theme");
      button.textContent = dark ? "☼ Light" : "◐ Dark";
    });
  }
  updateThemeButtons();
  document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
    button.addEventListener("click", function () {
      var next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("cns-theme", next); } catch (_) {}
      updateThemeButtons();
      window.dispatchEvent(new CustomEvent("cns-theme-change", {detail: {theme: next}}));
    });
  });

  // Explicitly control the Security tools menu rather than relying on native
  // disclosure behavior inside a narrow/scrollable navigation bar.
  var toolsToggle = document.querySelector(".nav-tools-toggle");
  var toolsMenu = document.getElementById("security-tools-menu");
  if (toolsToggle && toolsMenu) {
    var toolsGroup = toolsToggle.closest(".nav-more");
    var setToolsOpen = function (open) {
      toolsToggle.setAttribute("aria-expanded", String(open));
      toolsMenu.hidden = !open;
      if (toolsGroup) toolsGroup.classList.toggle("is-open", open);
    };
    setToolsOpen(false);
    toolsToggle.addEventListener("click", function () {
      setToolsOpen(toolsToggle.getAttribute("aria-expanded") !== "true");
    });
    toolsMenu.addEventListener("click", function (event) {
      if (event.target.closest("a")) setToolsOpen(false);
    });
    document.addEventListener("click", function (event) {
      if (toolsGroup && !toolsGroup.contains(event.target)) setToolsOpen(false);
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toolsToggle.getAttribute("aria-expanded") === "true") {
        setToolsOpen(false);
        toolsToggle.focus();
      }
    });
  }

  var drawer = document.querySelector(".nav-drawer");
  if (drawer) {
    var mobileNav = window.matchMedia("(max-width: 780px)");
    drawer.open = !mobileNav.matches;
    mobileNav.addEventListener("change", function (event) { drawer.open = !event.matches; });
  }

  // Progressive enhancement: prevent duplicate auth submissions and provide a
  // visible password control while preserving normal Flask form handling.
  document.querySelectorAll(".password-toggle").forEach(function (toggle) {
    toggle.addEventListener("click", function () {
      var input = document.getElementById(toggle.getAttribute("aria-controls"));
      if (!input) return;
      var visible = input.type === "password";
      input.type = visible ? "text" : "password";
      toggle.textContent = visible ? "Hide" : "Show";
      toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    });
  });
  document.querySelectorAll("#auth-form").forEach(function (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector('button[type="submit"]');
      if (!button || button.disabled) return;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.textContent = (button.getAttribute("data-submit-label") || button.textContent) + "…";
    });
  });

  // Compose: live character counter
  var area = document.querySelector("[data-counter]");
  if (area) {
    var out = document.getElementById(area.getAttribute("data-counter"));
    var update = function () { out.textContent = String(area.value.length); };
    area.addEventListener("input", update); update();
  }

  // Lab: run tests and render results with textContent (no innerHTML)
  var table = document.getElementById("lab-results");
  document.querySelectorAll("[data-lab]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var msg = document.getElementById("lab-msg");
      msg.textContent = "Running...";
      post("/lab/run/" + encodeURIComponent(btn.getAttribute("data-lab")))
        .then(function (r) { return r.json().then(function (j) { return {ok: r.ok, j: j}; }); })
        .then(function (res) {
          if (!res.ok) { msg.textContent = "Error: " + (res.j.error || "request failed"); return; }
          var tb = table.querySelector("tbody"); tb.textContent = "";
          res.j.results.forEach(function (r) {
            var tr = document.createElement("tr");
            [r.name, r.expected, r.observed, r.passed === null ? "N/A" : r.passed ? "PASS" : "FAIL"].forEach(function (t) {
              var td = document.createElement("td"); td.textContent = t; tr.appendChild(td);
            });
            tb.appendChild(tr);
          });
          table.hidden = false;
          msg.textContent = "Done. Reload to see the logged events below.";
        }).catch(function () { msg.textContent = "Network error"; });
    });
  });

  // Status: live health re-check
  var rc = document.getElementById("recheck");
  if (rc) rc.addEventListener("click", function () {
    var box = document.getElementById("health-out");
    fetch("/api/health", {credentials: "same-origin"}).then(function (r) { return r.json(); })
      .then(function (j) { box.textContent = JSON.stringify(j, null, 2); box.hidden = false; });
  });
})();

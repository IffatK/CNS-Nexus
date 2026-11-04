(() => {
  document.querySelectorAll("form[data-upload-progress]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!form.reportValidity()) {
        event.preventDefault();
        return;
      }
      const button = form.querySelector('button[type="submit"]');
      const loader = form.querySelector(".upload-progress");
      if (!button || !loader) return;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.textContent = "Scanning…";
      loader.hidden = false;
      form.setAttribute("aria-busy", "true");
    });
  });
})();

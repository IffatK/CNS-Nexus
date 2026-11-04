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
      const external = form.querySelector('[name="upload_file_to_virustotal"]:checked');
      const message = loader.querySelector("[data-progress-text]");
      if (message && external) message.textContent = "Submitting to VirusTotal for multi-engine scanning. Please wait…";
    });
  });
})();

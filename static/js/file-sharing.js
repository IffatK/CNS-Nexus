(() => {
  document.querySelectorAll("[data-recipient-form]").forEach(form => {
    const picker = form.querySelector(".recipient-picker");
    const boxes = [...form.querySelectorAll('input[name="recipients"]')];
    const summary = form.querySelector("[data-recipient-summary]");
    const error = form.querySelector("[data-recipient-error]");
    if (!picker || !boxes.length || !summary) return;

    const update = () => {
      const selected = boxes.filter(box => box.checked).map(box => box.value);
      summary.textContent = selected.length
        ? `${selected.length} recipient${selected.length === 1 ? "" : "s"} selected`
        : "Select recipients";
      if (selected.length) {
        error.hidden = true;
        picker.removeAttribute("aria-invalid");
      }
    };

    boxes.forEach(box => box.addEventListener("change", update));
    form.addEventListener("submit", event => {
      if (boxes.some(box => box.checked)) return;
      event.preventDefault();
      picker.open = true;
      picker.setAttribute("aria-invalid", "true");
      error.hidden = false;
      boxes[0].focus();
    });
  });
})();

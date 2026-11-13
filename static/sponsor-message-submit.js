document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll(".sponsor-message-form");

  forms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (form.dataset.submitting === "true") {
        event.preventDefault();
        return;
      }

      form.dataset.submitting = "true";
      const button = form.querySelector('button[type="submit"], button:not([type])');
      const notice = form.querySelector(".sending-notice");

      if (button) {
        button.disabled = true;
        button.setAttribute("aria-disabled", "true");
        button.textContent = button.dataset.sendingLabel || "Sending...";
      }

      if (notice) {
        notice.hidden = false;
      }
    });
  });
});

window.addEventListener("pageshow", () => {
  document.querySelectorAll(".sponsor-message-form").forEach((form) => {
    delete form.dataset.submitting;
    const button = form.querySelector('button[type="submit"], button:not([type])');
    const notice = form.querySelector(".sending-notice");

    if (button) {
      button.disabled = false;
      button.removeAttribute("aria-disabled");
      button.textContent = button.dataset.defaultLabel || "Send message";
    }
    if (notice) {
      notice.hidden = true;
    }
  });
});

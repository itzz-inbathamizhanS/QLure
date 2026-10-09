// Scanner page progress state. A scan can take up to about 30 seconds, so on submit the
// button is disabled and the status line is shown. The form works without this file: the
// page then simply waits for the server's answer, as before.
// It is a file rather than an inline script because the CSP has no 'unsafe-inline'.
(function () {
  "use strict";

  function setScanning(form, scanning) {
    var button = form.querySelector("[data-scan-button]");
    var status = form.querySelector("[data-scan-status]");
    if (button) {
      button.disabled = scanning;
    }
    if (status) {
      status.classList.toggle("is-visible", scanning);
    }
  }

  document.querySelectorAll("form[data-scan-form]").forEach(function (form) {
    form.addEventListener("submit", function () {
      setScanning(form, true);
    });
    // A page restored from the back-forward cache must not stay in the scanning state.
    window.addEventListener("pageshow", function () {
      setScanning(form, false);
    });
  });
})();

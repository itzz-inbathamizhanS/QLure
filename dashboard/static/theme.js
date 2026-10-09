// Light / dark switch for the Q-Lure dashboard.
// Loaded without defer from <head>, before app.css, so the saved theme is on <html> before
// the first paint. It is a file rather than an inline script because the CSP has no
// 'unsafe-inline'. With no saved choice, CSS follows the system setting.
(function () {
  "use strict";

  var KEY = "qlure-theme";
  var root = document.documentElement;
  var system = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try {
      var value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch (err) {
      return null;
    }
  }

  function remember(theme) {
    try {
      window.localStorage.setItem(KEY, theme);
    } catch (err) {
      // Storage is off (private mode, or blocked): the choice holds for this page only.
    }
  }

  function current() {
    var set = root.getAttribute("data-theme");
    if (set === "light" || set === "dark") {
      return set;
    }
    return system && system.matches ? "dark" : "light";
  }

  function paint() {
    var pressed = current() === "dark" ? "true" : "false";
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", pressed);
    }
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    paint();
  }

  var initial = saved();
  if (initial) {
    root.setAttribute("data-theme", initial);
  }

  // Delegated, so buttons swapped in by htmx also work.
  document.addEventListener("click", function (event) {
    var target = event.target;
    var button = target && target.closest ? target.closest("[data-theme-toggle]") : null;
    if (!button) {
      return;
    }
    var next = current() === "dark" ? "light" : "dark";
    remember(next);
    apply(next);
  });

  document.addEventListener("DOMContentLoaded", paint);
  document.addEventListener("htmx:afterSettle", paint);
  if (system && system.addEventListener) {
    system.addEventListener("change", function () {
      if (!saved()) {
        paint();
      }
    });
  }
})();

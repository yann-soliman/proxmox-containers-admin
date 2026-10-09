/* Display only. No requests, form submission, grants or renewal. */
"use strict";
const timers = document.querySelectorAll("[data-expires-at]");
function updateCountdowns() {
  for (const timer of timers) {
    const expiry = Number(timer.dataset.expiresAt);
    if (!Number.isFinite(expiry)) continue;
    const seconds = Math.max(0, Math.ceil(expiry - Date.now() / 1000));
    timer.textContent = seconds > 0
      ? `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s restantes`
      : "Échéance atteinte · actualisez l’état";
  }
}
updateCountdowns();
if (timers.length) window.setInterval(updateCountdowns, 1000);

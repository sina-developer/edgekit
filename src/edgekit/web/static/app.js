// Panel behaviour. Deliberately tiny: no framework, no build step, no external requests.
(function () {
  'use strict';

  // Confirm destructive submits. The prompt lives in data-confirm on the form.
  document.addEventListener('submit', function (event) {
    var form = event.target;
    var message = form.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
      event.preventDefault();
      return;
    }
    // Guard against double submits on slow operations (issuing certs, re-provisioning).
    var button = form.querySelector('button[type=submit]');
    if (button) {
      setTimeout(function () {
        button.disabled = true;
        button.dataset.original = button.textContent;
        button.textContent = 'Working…';
      }, 0);
    }
  });

  // Copy-to-clipboard buttons: <button data-copy="#selector">
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-copy]');
    if (!trigger) return;

    var source = document.querySelector(trigger.getAttribute('data-copy'));
    if (!source) return;

    var text = source.textContent;
    var done = function () {
      var original = trigger.textContent;
      trigger.textContent = 'Copied';
      setTimeout(function () { trigger.textContent = original; }, 1500);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done);
      return;
    }
    // The panel is usually reached over plain HTTP through an SSH tunnel, where the
    // async clipboard API is unavailable.
    var scratch = document.createElement('textarea');
    scratch.value = text;
    scratch.style.position = 'fixed';
    scratch.style.opacity = '0';
    document.body.appendChild(scratch);
    scratch.select();
    try { document.execCommand('copy'); done(); } finally { scratch.remove(); }
  });
})();

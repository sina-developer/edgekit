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

  // Diagnostics tab: the HTML is a shell. Probes run on the server via /api/health
  // so the page can paint immediately; fetch() already keeps this off the UI thread.
  var diagnosticsRoot = document.getElementById('diagnostics-app');
  if (diagnosticsRoot) {
    loadDiagnostics(diagnosticsRoot);
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch];
    });
  }

  function pillFor(level) {
    if (level === 'ok') return '<span class="pill ok">pass</span>';
    if (level === 'warn') return '<span class="pill warn">warn</span>';
    if (level === 'fail') return '<span class="pill bad">fail</span>';
    return '<span class="pill">skip</span>';
  }

  function renderDiagnostics(report) {
    var summary = document.getElementById('diagnostics-summary');
    var rows = document.getElementById('diagnostics-rows');
    if (!summary || !rows) return;

    var checks = report.checks || [];
    var failures = typeof report.failures === 'number'
      ? report.failures
      : checks.filter(function (c) { return c.level === 'fail'; }).length;
    var warnings = typeof report.warnings === 'number'
      ? report.warnings
      : checks.filter(function (c) { return c.level === 'warn'; }).length;

    summary.className = 'flash ' + (report.ok ? 'ok' : 'bad');
    var text = report.ok ? 'Every required check passed.' : (failures + ' check(s) failed.');
    if (warnings) text += ' ' + warnings + ' warning(s).';
    summary.textContent = text;

    rows.innerHTML = checks.map(function (check) {
      var detail = check.detail
        ? '<div class="muted small">' + escapeHtml(check.detail) + '</div>'
        : '';
      var remedy = check.remedy
        ? '<div class="remedy">' + escapeHtml(check.remedy) + '</div>'
        : '';
      return '<tr class="lvl-' + escapeHtml(check.level) + '">' +
        '<td class="status">' + pillFor(check.level) + '</td>' +
        '<td><strong>' + escapeHtml(check.title) + '</strong>' + detail + remedy + '</td>' +
        '</tr>';
    }).join('');
  }

  function loadDiagnostics(root) {
    var src = root.getAttribute('data-diagnostics-src') || '/api/health';
    var rerun = document.getElementById('diagnostics-rerun');
    var summary = document.getElementById('diagnostics-summary');
    var rows = document.getElementById('diagnostics-rows');

    function pending() {
      if (summary) {
        summary.className = 'flash';
        summary.textContent = 'Running checks…';
      }
      if (rows) {
        rows.innerHTML =
          '<tr class="check-pending"><td class="status"><span class="pill pulse">…</span></td>' +
          '<td><strong>Running health checks</strong>' +
          '<div class="muted small">WireGuard, Docker, NPM reachability, public TLS.</div></td></tr>';
      }
      if (rerun) rerun.disabled = true;
    }

    function run() {
      pending();
      fetch(src, { credentials: 'same-origin' })
        .then(function (response) {
          if (!response.ok) throw new Error('HTTP ' + response.status);
          return response.json();
        })
        .then(renderDiagnostics)
        .catch(function (err) {
          if (summary) {
            summary.className = 'flash bad';
            summary.textContent = 'Could not run diagnostics: ' + err.message;
          }
        })
        .finally(function () {
          if (rerun) rerun.disabled = false;
        });
    }

    if (rerun) rerun.addEventListener('click', run);
    run();
  }
})();

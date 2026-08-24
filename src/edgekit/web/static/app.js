// Panel behaviour. Deliberately tiny: no framework, no build step, no external requests.
(function () {
  'use strict';

  // Confirm destructive submits. The prompt lives in data-confirm on the form, and is
  // shown in the shared <dialog> rather than window.confirm() — a browser alert cannot be
  // styled, names the origin, and looks nothing like the rest of the panel.
  var pendingForm = null;

  function openConfirm(form, message) {
    var dialog = document.getElementById('confirm-dialog');
    if (!dialog || typeof dialog.showModal !== 'function') {
      // No dialog support: fall back rather than letting the action silently do nothing.
      if (window.confirm(message)) submitConfirmed(form);
      return;
    }

    document.getElementById('confirm-message').textContent = message;
    document.getElementById('confirm-title').textContent =
      form.getAttribute('data-confirm-title') || 'Are you sure?';

    var accept = document.getElementById('confirm-accept');
    accept.textContent = form.getAttribute('data-confirm-action') || 'Confirm';
    accept.classList.toggle('danger', form.hasAttribute('data-confirm-danger'));
    accept.classList.toggle('primary', !form.hasAttribute('data-confirm-danger'));

    // Replace the node so a previous form's listener cannot fire for this one.
    var fresh = accept.cloneNode(true);
    accept.parentNode.replaceChild(fresh, accept);
    fresh.addEventListener('click', function () {
      dialog.close();
      submitConfirmed(form);
    });

    dialog.showModal();
  }

  function submitConfirmed(form) {
    pendingForm = form;
    if (typeof form.requestSubmit === 'function') form.requestSubmit();
    else form.submit();
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    var message = form.getAttribute('data-confirm');

    if (message && form !== pendingForm) {
      event.preventDefault();
      openConfirm(form, message);
      return;
    }
    pendingForm = null;

    // Guard against double submits on slow operations (issuing certs, re-provisioning).
    var button = form.querySelector('button[type=submit]');
    if (button) {
      setTimeout(function () {
        button.disabled = true;
        // innerHTML, not textContent: these buttons carry an icon that would be deleted.
        button.dataset.originalHtml = button.innerHTML;
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
      // Swapping textContent would delete the button's SVG and leave the word "Copied"
      // inside a 32px icon button. Swap innerHTML and put the tick back afterwards.
      if (trigger.getAttribute('data-copy-busy')) return;
      trigger.setAttribute('data-copy-busy', '1');

      var original = trigger.innerHTML;
      var iconOnly = trigger.classList.contains('icon');
      trigger.innerHTML = TICK_ICON + (iconOnly ? '' : ' Copied');
      trigger.classList.add('copied');

      setTimeout(function () {
        trigger.innerHTML = original;
        trigger.classList.remove('copied');
        trigger.removeAttribute('data-copy-busy');
      }, 1500);
    };

    // The panel is usually reached over plain HTTP through an SSH tunnel, where the async
    // clipboard API is unavailable — and even on a secure origin writeText() rejects when
    // the document is not focused. Both cases fall through to the textarea.
    var fallbackCopy = function () {
      var scratch = document.createElement('textarea');
      scratch.value = text;
      scratch.style.position = 'fixed';
      scratch.style.opacity = '0';
      document.body.appendChild(scratch);
      scratch.select();
      try {
        if (document.execCommand('copy')) done();
      } finally {
        scratch.remove();
      }
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallbackCopy);
      return;
    }
    fallbackCopy();
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
    if (level === 'ok') return '<span class="pill ok">Pass</span>';
    if (level === 'warn') return '<span class="pill warn">Warn</span>';
    if (level === 'fail') return '<span class="pill bad">Fail</span>';
    return '<span class="pill">Skip</span>';
  }

  var ALERT_ICON = '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
  var CHECK_ICON = '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

  var COPY_ICON = '<svg class="i-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>';

  // Failures are the reason anyone opens this page; they must not sit under the passes.
  var LEVEL_ORDER = { fail: 0, warn: 1, skip: 2, ok: 3 };

  function rank(level) {
    // Not `|| 9`: fail ranks 0, which is falsy, and would fall through to last.
    return LEVEL_ORDER[level] === undefined ? 9 : LEVEL_ORDER[level];
  }

  function bySeverity(a, b) {
    return rank(a.level) - rank(b.level);
  }

  function markFor(level) {
    if (level === 'ok') return '<span class="chk-mark ok">&#10003;</span>';
    if (level === 'warn') return '<span class="chk-mark warn">!</span>';
    if (level === 'fail') return '<span class="chk-mark bad">&#10005;</span>';
    return '<span class="chk-mark">&#8211;</span>';
  }

  function renderDiagnostics(report) {
    var summary = document.getElementById('diagnostics-summary');
    var rows = document.getElementById('diagnostics-rows');
    if (!summary || !rows) return;

    var checks = (report.checks || []).slice().sort(bySeverity);
    var failures = typeof report.failures === 'number'
      ? report.failures
      : checks.filter(function (c) { return c.level === 'fail'; }).length;
    var warnings = typeof report.warnings === 'number'
      ? report.warnings
      : checks.filter(function (c) { return c.level === 'warn'; }).length;
    var passes = checks.filter(function (c) { return c.level === 'ok'; }).length;

    function titles(level) {
      // Escaped here: this string goes into innerHTML, joined by an entity separator.
      return checks
        .filter(function (c) { return c.level === level; })
        .map(function (c) { return escapeHtml(c.title); });
    }

    function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

    var tone, mark, headline, supporting;
    if (failures) {
      tone = 'bad';
      mark = ALERT_ICON;
      headline = plural(failures, 'check') + ' failed';
      if (warnings) headline += ', ' + plural(warnings, 'warning');
      supporting = titles('fail').join(' &middot; ');
    } else if (warnings) {
      tone = 'warn';
      mark = ALERT_ICON;
      headline = plural(warnings, 'warning');
      supporting = titles('warn').join(' &middot; ');
    } else {
      tone = 'ok';
      mark = CHECK_ICON;
      headline = 'Everything checks out';
      supporting = escapeHtml(plural(checks.length, 'check')) +
        ' ran clean — tunnel, container, firewall rules and public TLS.';
    }

    summary.className = 'flash ' + tone + ' summary-card';
    summary.innerHTML =
      '<span class="summary-mark ' + tone + '">' + mark + '</span>' +
      '<div><div class="summary-title">' + escapeHtml(headline) + '</div>' +
      '<div class="summary-sub">' + supporting + '</div></div>';

    var counts = document.getElementById('diagnostics-counts');
    if (counts) {
      counts.hidden = false;
      document.getElementById('count-ok').textContent = passes;
      document.getElementById('count-warn').textContent = warnings;
      document.getElementById('count-bad').textContent = failures;
      var bar = document.getElementById('count-bar');
      bar.innerHTML =
        (passes ? '<span class="ok" style="flex:' + passes + '"></span>' : '') +
        (warnings ? '<span class="warn" style="flex:' + warnings + '"></span>' : '') +
        (failures ? '<span class="bad" style="flex:' + failures + '"></span>' : '');
    }

    rows.innerHTML = checks.map(function (check) {
      var detail = check.detail
        ? '<p class="chk-detail">' + escapeHtml(check.detail) + '</p>'
        : '';
      // A remedy is a command to run, so it is rendered as one, with a copy button.
      var remedy = '';
      if (check.remedy) {
        var id = 'remedy-' + escapeHtml(check.key || Math.random().toString(36).slice(2));
        remedy =
          '<div class="remedy">' +
            '<code id="' + id + '">' + escapeHtml(check.remedy) + '</code>' +
            '<button class="ghost icon" type="button" data-copy="#' + id + '" ' +
              'aria-label="Copy command">' + COPY_ICON + '</button>' +
          '</div>';
      }
      return '<div class="chk lvl-' + escapeHtml(check.level) + '">' +
        markFor(check.level) +
        '<div class="chk-body">' +
          '<div class="chk-title"><strong>' + escapeHtml(check.title) + '</strong>' +
          pillFor(check.level) + '</div>' +
          detail + remedy +
        '</div>' +
      '</div>';
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
        summary.innerHTML = '<div>Running checks&hellip;</div>';
      }
      var counts = document.getElementById('diagnostics-counts');
      if (counts) counts.hidden = true;
      if (rows) {
        rows.innerHTML =
          '<div class="chk check-pending"><span class="chk-mark">&hellip;</span>' +
          '<div class="chk-body"><div class="chk-title"><strong>Running health checks</strong>' +
          '</div><p class="chk-detail">WireGuard, Docker, NPM reachability, public TLS.</p>' +
          '</div></div>';
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
            summary.innerHTML =
              '<div>Could not run diagnostics: ' + escapeHtml(err.message) + '</div>';
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

// ---------------------------------------------------------------------------
// Popovers, modals, and the settings scroll-spy.
//
// Kept in a second IIFE so it stays separable from the original panel behaviour.
// No inline handlers anywhere: the panel's CSP is script-src 'self'.
(function () {
  'use strict';

  // -------------------------------------------------------------- popovers
  //
  // A dropdown inside a table cell cannot be positioned with `position:absolute`:
  // the scroll container (.table-wrap) clips it, and z-index cannot escape an
  // overflow context. The native popover API puts the element in the top layer,
  // which is outside every clip — we only have to place it ourselves, because
  // CSS anchor positioning is not portable yet.

  var GAP = 6;

  function placePopover(panel) {
    var trigger = document.querySelector('[popovertarget="' + panel.id + '"]');
    if (!trigger) return;

    var anchor = trigger.getBoundingClientRect();
    var panelBox = panel.getBoundingClientRect();
    var margin = 8;

    // Right-aligned to the trigger, which is what a row-end action menu wants.
    var left = anchor.right - panelBox.width;
    var top = anchor.bottom + GAP;

    // Flip above the trigger when there is not enough room below.
    if (top + panelBox.height > window.innerHeight - margin) {
      var above = anchor.top - panelBox.height - GAP;
      if (above > margin) top = above;
      else top = Math.max(margin, window.innerHeight - panelBox.height - margin);
    }
    left = Math.min(Math.max(margin, left), window.innerWidth - panelBox.width - margin);

    panel.style.left = left + 'px';
    panel.style.top = top + 'px';
    // Revealed only once placed: `toggle` fires a frame after the popover is shown, so
    // without this the menu paints at 0,0 for one frame first.
    panel.classList.add('placed');
  }

  function initPopovers() {
    var panels = document.querySelectorAll('[popover].menu');
    if (!panels.length) return;

    Array.prototype.forEach.call(panels, function (panel) {
      panel.addEventListener('toggle', function (event) {
        if (event.newState === 'open') placePopover(panel);
        else panel.classList.remove('placed');
      });
    });

    // An open popover keeps its coordinates, so it would drift away from its row.
    var reposition = function () {
      Array.prototype.forEach.call(panels, function (panel) {
        if (panel.matches(':popover-open')) placePopover(panel);
      });
    };
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
  }

  // ---------------------------------------------------------------- modals

  document.addEventListener('click', function (event) {
    var opener = event.target.closest('[data-dialog]');
    if (opener) {
      var dialog = document.querySelector(opener.getAttribute('data-dialog'));
      if (dialog && typeof dialog.showModal === 'function') {
        event.preventDefault();
        // The trigger may live inside a popover; close it so both are not open.
        var host = opener.closest('[popover]');
        if (host && host.matches(':popover-open')) host.hidePopover();
        dialog.showModal();
      }
      return;
    }

    var closer = event.target.closest('[data-dialog-close]');
    if (closer) {
      event.preventDefault();
      var owner = closer.closest('dialog');
      if (owner) owner.close();
      return;
    }

    // Clicking the backdrop closes: the dialog element itself is the backdrop area.
    if (event.target.tagName === 'DIALOG' && event.target.open) {
      var box = event.target.getBoundingClientRect();
      var outside =
        event.clientX < box.left || event.clientX > box.right ||
        event.clientY < box.top || event.clientY > box.bottom;
      if (outside) event.target.close();
    }
  });

  // ------------------------------------------------------------- scroll-spy

  function initScrollSpy() {
    var nav = document.querySelector('.subnav');
    if (!nav) return;

    var picker = document.getElementById('subnav-select');
    if (picker) {
      picker.addEventListener('change', function () {
        var target = document.querySelector(picker.value);
        if (target) target.scrollIntoView({ behavior: 'smooth' });
      });
    }

    var links = {};
    var order = [];
    Array.prototype.forEach.call(nav.querySelectorAll('a[href^="#"]'), function (link) {
      var id = link.getAttribute('href').slice(1);
      links[id] = link;
      order.push(id);
    });

    var sections = order
      .map(function (id) { return document.getElementById(id); })
      .filter(Boolean);
    if (!sections.length) return;

    // Computed from geometry rather than IntersectionObserver: a section taller than the
    // observer band stays "intersecting" across a long scroll, which pinned the highlight
    // on whichever tall section came first.
    var LINE = 100; // just below the sticky header

    function update() {
      var current = sections[0];
      for (var i = 0; i < sections.length; i++) {
        if (sections[i].getBoundingClientRect().top <= LINE) current = sections[i];
      }
      // The final sections can sit below the line even at maximum scroll, so they would
      // never light up. At the bottom, the last section that is actually on screen is what
      // the reader is looking at.
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
        for (var k = sections.length - 1; k >= 0; k--) {
          if (sections[k].getBoundingClientRect().top < window.innerHeight) {
            current = sections[k];
            break;
          }
        }
      }

      for (var j = 0; j < sections.length; j++) {
        links[sections[j].id].classList.toggle('active', sections[j] === current);
      }
      // The mobile select is the same control in a different shape; keep it in step.
      if (picker && picker.value !== '#' + current.id) picker.value = '#' + current.id;
    }

    var ticking = false;
    function onScroll() {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(function () { update(); ticking = false; });
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    update();
  }

  initPopovers();
  initScrollSpy();
})();

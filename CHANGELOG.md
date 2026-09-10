# Changelog

All notable changes to edgekit are recorded here. Version numbers follow
[SemVer](https://semver.org/): MAJOR.MINOR.PATCH.

The single source of truth for the number itself is `src/edgekit/__init__.py`
(`__version__`). Keep this file in lockstep with that string.

## [Unreleased]

- A missing wheel no longer reads as a network failure. `ResolutionImpossible` and "no
  matching distributions available for your environment" are deterministic — the index has
  no build of that package for this interpreter — so the installer stops retrying them
  (three attempts with backoff bought nothing but minutes) and recovers instead: it retries
  against PyPI when a mirror is configured, then installs a compiler toolchain so pip can
  build from source. If both fail it names the package, the Python version, and the platform,
  and lists only the routes that still apply. `edgekit update` classifies the same failure
  the same way.
- `EDGEKIT_PYTHON` selects the interpreter the virtualenv is built from — the fix when the
  system Python is newer than the compiled dependencies publish wheels for. The installer
  installs that interpreter's `-venv` package, and rebuilds an existing virtualenv that was
  made with a different version.

- Installing an origin certificate is idempotent. NPM cannot update a certificate in place,
  so every install created a new record, moved every proxy host onto it and deleted the old
  one — and `edgekit provision` did that on every run. Re-installing an unchanged certificate
  now changes nothing (`--force` still re-uploads). Superseded records are swept by label
  rather than one at a time, and one is deleted only once no proxy host references it: a
  vhost left pointing at a deleted certificate is not an NPM error, it is a handshake nginx
  cannot complete, reported by Cloudflare as a 525 that looks nothing like its cause.
- Proxy host changes are verified with `nginx -t` inside the NPM container and rolled back if
  nginx refuses them. An unrunnable check (no Docker, container down) is reported as unknown,
  never as a failure.
- `edgekit provision` validates the stored certificate before installing it — key match,
  expiry, and hostname coverage — instead of only parsing it. config.yaml can be edited by
  hand, and a certificate that was valid at setup expires on its own schedule.
- `edgekit doctor` walks the TLS path in order: certificate validity and coverage, `nginx -t`,
  local TLS, TLS to the public IP (the hop Cloudflare makes), then the public path. It also
  warns as the certificate nears expiry at 30 and 7 days — Cloudflare sends no expiry notice
  for Origin CA certificates — and tells 525 (handshake failed) apart from 526 (certificate
  rejected), which have different causes and different fixes.
- Installation survives a busy or slow server. apt calls wait for whoever holds the dpkg
  lock — on a fresh VPS that is `unattended-upgrades`, for a few minutes — naming the
  process instead of failing with `Could not get lock`, and retrying if something takes the
  lock mid-run. This covers the installer, `edgekit setup`, and `edgekit update`.
- pip no longer gives up on a congested link to PyPI: a 60-second timeout (was pip's
  default 15), five retries per request, and three attempts per command, with
  `EDGEKIT_PIP_INDEX_URL` to install from a mirror where PyPI is unreachable. Downloads of
  the source archive, the git clone, and Docker's signing key retry too.
- Failures now say what to do next — which process holds apt, how to check PyPI
  reachability, which variable to raise — and Ctrl-C reports as an interruption rather than
  as a failure at a line number.

## [1.2.0] — 2026-08-24

- The panel is redesigned. The top navigation becomes a sidebar with per-section counts;
  the header carries a breadcrumb and one primary action. Every page was rebuilt on a
  single set of tokens (shadcn/ui's neutral palette in oklch, light only), with Lucide
  icons inlined as template partials so nothing is fetched at runtime — the panel still
  works offline behind a tunnel, and the CSP is unchanged.
- Overview shows what was already collected but never displayed: the audit actor, the
  container's restart count, and a per-peer connected/offline/disabled breakdown. When the
  tunnel or the container is down it now says so at the top, with the command that fixes
  it, instead of leaving four red tiles to interpret.
- Diagnostics sorts failures first and states the outcome in one line. Remedies are
  rendered as commands with a copy button.
- Destructive actions confirm in a dialog naming the consequence ("its address 10.50.0.2
  is released for reuse") rather than a browser alert.
- Row action menus render in the top layer, so the last row of a table is no longer
  clipped by the scroll container. Proxy host edits open a modal.
- Small screens get a navigation drawer, and Settings swaps its section list for a select.
- `tools/preview.py` runs the panel locally against fixtures — no root, no WireGuard, no
  Docker — with populated, healthy, empty and degraded scenarios. Developer tooling only;
  it is not part of the distributed package.

## [1.1.2] — 2026-08-22

- Firewall rules now name the Docker network Nginx Proxy Manager is really on. Compose
  puts NPM on its own project network (`nginx-proxy-manager_default`, typically
  `172.18.0.0/16` on a `br-<hash>` interface), not the default bridge, so the ufw rule
  that let NPM reach the panel allowed `172.17.0.0/16` and matched nothing: with ufw on,
  `edgekit.<zone>` timed out while 80/443 looked healthy. The docker→WireGuard forwarding
  and NAT rules had the same wrong interface and subnet.
- The stale default-bridge opening on the panel port is revoked when it is found, so the
  panel is not left reachable from unrelated containers on docker0.

## [1.1.1] — 2026-08-22

- `edgekit firewall setup` restarts Docker after enabling ufw, so published 80/443
  and the docker0↔WireGuard rules survive ufw rewriting iptables.
- ufw allows the Docker bridge to reach the panel on the WireGuard hub IP (8088 stays
  closed from the internet). Without that, NPM hangs on HTTPS after ufw is enabled.

## [1.1.0] — 2026-08-22

- Setup asks whether to renew the Cloudflare origin certificate when keys already
  exist on disk or in config; declining keeps the current pair and skips the paste.

## [1.0.0] — 2026-08-22

Initial tagged release of the current tree.

- Interactive installer (`install.sh` / `edgekit setup`) that waits for TTY input
  even when run via `curl | sudo bash`.
- Management panel, WireGuard hub, Nginx Proxy Manager, and origin-certificate flow.
- `edgekit update` refreshes the install from git without re-running setup.
- Diagnostics tab loads immediately; health checks run in the background.
- `edgekit firewall setup` / `edgekit firewall check` for host ufw, plus a
  post-install cloud-firewall port list.
- jsDelivr cache purge workflow so `@master/install.sh` tracks GitHub.

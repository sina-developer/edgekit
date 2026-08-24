# Changelog

All notable changes to edgekit are recorded here. Version numbers follow
[SemVer](https://semver.org/): MAJOR.MINOR.PATCH.

The single source of truth for the number itself is `src/edgekit/__init__.py`
(`__version__`). Keep this file in lockstep with that string.

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
- Static assets are cache-busted by file mtime instead of the package version. A CSS fix
  shipped without a version bump previously never reached a browser holding the old file.
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

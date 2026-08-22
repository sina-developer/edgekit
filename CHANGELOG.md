# Changelog

All notable changes to edgekit are recorded here. Version numbers follow
[SemVer](https://semver.org/): MAJOR.MINOR.PATCH.

The single source of truth for the number itself is `src/edgekit/__init__.py`
(`__version__`). Keep this file in lockstep with that string.

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

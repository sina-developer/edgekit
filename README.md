# edgekit

Turns a fresh Ubuntu/Debian server into a **WireGuard hub + Nginx Proxy Manager edge**, in one
command, and leaves behind a web panel for managing peers and published services.

It is the [blockey-wireguard-nginx-proxy-manager-guide](blockey-wireguard-nginx-proxy-manager-guide.md)
turned into software: every manual step in that guide — installing WireGuard, writing
`wg0.conf`, enabling IP forwarding, the Docker-to-WireGuard `iptables` rules, deploying NPM,
the Cloudflare DNS records, Full (strict) SSL, the origin certificate, the proxy hosts — is a
step the installer performs and the panel keeps managing.

```
Internet → Cloudflare (Full strict) → this server ─┬─ Nginx Proxy Manager :80 :443
                                                    └─ WireGuard wg0 10.50.0.1/24
                                                            │  encrypted tunnel
                                                            └─ peers 10.50.0.2+ (Pi, VPS, laptop)
```

---

## Install

On the server, as root:

```bash
sudo ./install.sh
```

That is the whole thing. The installer checks the OS, installs Python, creates an isolated
virtualenv at `/opt/edgekit`, then hands over to an interview:

- public IP (auto-detected, you confirm)
- tunnel subnet and WireGuard UDP port
- Nginx Proxy Manager ports and admin account
- Cloudflare zone, API token, SSL mode
- panel port and admin account

Then it provisions everything and prints your panel credentials. Re-running it is safe.

### Unattended

Every question can be answered from the environment, so a server can be built with no
interaction at all:

```bash
sudo EDGEKIT_PUBLIC_IP=52.56.216.78 \
     EDGEKIT_WG_SUBNET=10.50.0.0/24 \
     EDGEKIT_CF_ZONE=blockey.ir \
     EDGEKIT_CF_TOKEN=cf_xxx \
     EDGEKIT_PANEL_PASSWORD='a-long-password' \
     ./install.sh --non-interactive
```

| Variable | Meaning |
|---|---|
| `EDGEKIT_PUBLIC_IP` | Public IPv4 of this server |
| `EDGEKIT_WG_SUBNET` / `EDGEKIT_WG_PORT` | Tunnel subnet, WireGuard UDP port |
| `EDGEKIT_NPM_EMAIL` / `EDGEKIT_NPM_PASSWORD` | Nginx Proxy Manager admin account |
| `EDGEKIT_NPM_HTTP_PORT` / `EDGEKIT_NPM_HTTPS_PORT` / `EDGEKIT_NPM_ADMIN_PORT` | Proxy ports |
| `EDGEKIT_CF_ENABLED` / `EDGEKIT_CF_ZONE` / `EDGEKIT_CF_TOKEN` | Cloudflare integration |
| `EDGEKIT_CF_ORIGIN_CA_KEY` | Only if the token cannot issue origin certificates |
| `EDGEKIT_CF_PROXIED` | Orange-cloud the DNS records (default yes) |
| `EDGEKIT_PANEL_USER` / `EDGEKIT_PANEL_PASSWORD` / `EDGEKIT_PANEL_PORT` | Panel account |

Installing from somewhere other than a local checkout:

```bash
sudo EDGEKIT_REPO=https://github.com/you/edgekit.git ./install.sh
sudo EDGEKIT_ARCHIVE=https://example.com/edgekit.tar.gz ./install.sh
```

### The one thing edgekit cannot do for you

Your **cloud provider's firewall** (AWS security group, Hetzner firewall, …) lives outside the
server, so it must be opened by hand:

| Port | Protocol | Why |
|---|---|---|
| 51820 | UDP | WireGuard |
| 80 | TCP | HTTP / ACME |
| 443 | TCP | HTTPS |

Do **not** open the NPM admin port or the panel port. Both are bound to loopback.

---

## The panel

Bound to `127.0.0.1` by default, because it holds every credential on the box. Reach it over
an SSH tunnel:

```bash
ssh -L 8088:127.0.0.1:8088 root@YOUR_SERVER_IP
```

then open <http://127.0.0.1:8088>.

To reach it over the tunnel instead, answer yes to "expose the panel on the WireGuard
address" during setup — it then binds to `10.50.0.1` and is reachable from any connected peer.

**Overview** — tunnel state, per-peer handshake and traffic, NPM container health,
certificate expiry, recent activity.

**Peers** — add a peer and get a ready client config plus a QR code for the mobile apps.
Enable/disable, rotate keys, route extra networks behind a peer. Every change regenerates
`wg0.conf` and hot-applies it with `wg syncconf`, so adding a peer never drops the tunnels
already up.

**Proxy hosts** — publish a service in one form: creates the Cloudflare A record, then the NPM
proxy host pointed at the peer's tunnel address with the origin certificate attached.

**Diagnostics** — the guide's §21 troubleshooting and §23 verification matrix as live checks,
each failure paired with the command that fixes it.

**Settings** — Cloudflare credentials, WireGuard port and MTU, certificate issue/reissue,
manual certificate upload, and a button to re-run the whole provisioner.

**Audit** — append-only log of every state change, from the panel or the CLI.

---

## Command line

Everything the panel does is available without a browser.

```bash
edgekit status                      # one-screen summary
edgekit doctor                      # health checks with remedies
edgekit provision                   # re-run provisioning (idempotent)

edgekit peer add raspberry-pi       # register a peer, print its config
edgekit peer add pi --public-key K  # client-generated key; edgekit never sees the private key
edgekit peer list
edgekit peer show raspberry-pi
edgekit peer remove raspberry-pi
edgekit peer sync                   # regenerate wg0.conf and hot-apply

edgekit host add retro.blockey.ir 3001 --peer raspberry-pi
edgekit host list
edgekit host remove retro.blockey.ir --remove-dns

edgekit cert issue [--force]
edgekit cert status

edgekit user create alice
edgekit user passwd admin
```

Adding a service, end to end:

```bash
edgekit host add api.blockey.ir 8080 --peer raspberry-pi
```

DNS record, proxy host, SSL — done. No Nginx config editing, no new WireGuard peer.

---

## How it is put together

```
install.sh                  bootstrap: deps → virtualenv → `edgekit setup`
src/edgekit/
  cli.py                    Typer CLI; `setup` is what the installer calls
  wizard.py                 the interview (flags → environment → prompt)
  config.py                 typed config; secrets encrypted at rest
  crypto.py                 Fernet secret handling
  models.py  db.py          SQLAlchemy models and session management
  security.py               password hashing, signed sessions, login throttle
  rendering.py              Jinja2 environment for generated artifacts
  service_unit.py           systemd unit for the panel
  templates/                wg0.conf, peer.conf, docker-compose.yml
  system/                   host interaction: shell, packages, wireguard, firewall, docker
  services/
    provision.py            the guide as ordered, idempotent, resumable steps
    peers.py  hosts.py      peer and proxy-host lifecycle
    npm.py  cloudflare.py   API clients
    certificates.py         origin certificate issuance and installation
    health.py               the §23 verification matrix
  web/                      FastAPI panel: routers, templates, static assets
tests/                      142 tests
```

**Design decisions worth knowing:**

*Idempotency everywhere.* Every provisioning step checks before it acts, so a half-finished
run converges instead of erroring or duplicating state. That is what makes it safe to run on
server after server, and to re-run after changing the public IP or Cloudflare zone.

*The database is the source of truth.* `wg0.conf` is a rendered artifact, regenerated from the
peer table on every change. The file and the running interface cannot drift.

*The origin private key never leaves the box.* Cloudflare will generate the keypair for you
and return the private key over the wire; edgekit generates the key locally and sends only a
CSR.

*Firewall rules are a script, not `iptables -A`.* The guide's commands are neither idempotent
nor reboot-safe. edgekit writes `/usr/local/lib/edgekit/firewall.sh` — each rule added only if
an identical one is absent — plus a systemd unit that replays it after `docker.service`.

*Nothing is exposed by default.* The NPM admin UI binds to `127.0.0.1`, the panel binds to
`127.0.0.1`, and `0.0.0.0` is never offered as a choice.

### Files on disk

| Path | Contents |
|---|---|
| `/etc/edgekit/config.yaml` | Configuration, secrets encrypted (`0600`) |
| `/etc/edgekit/secret.key` | Encryption key (`0600`) |
| `/var/lib/edgekit/edgekit.db` | Peers, hosts, users, audit log (`0600`) |
| `/var/log/edgekit/edgekit.log` | Application log |
| `/etc/wireguard/wg0.conf` | Generated; edits are overwritten |
| `/opt/nginx-proxy-manager/` | Compose file and NPM data |
| `/usr/local/lib/edgekit/firewall.sh` | Generated forwarding rules |

Back up `/etc/edgekit/` and `/var/lib/edgekit/` together — the database is useless without the
key that decrypts its secrets.

---

## Security notes

- Panel passwords are bcrypt-hashed; sessions are signed, `HttpOnly`, `SameSite=Strict`.
- All state-changing routes require a CSRF token bound to the session.
- Failed logins are throttled per client address (5 attempts, 5-minute lockout).
- Stored secrets are encrypted with a key in a `0600` file. This keeps credentials out of
  backups, `grep`, and log scrapes — it does **not** defend against root on the box, which can
  read the key. Treat root on this server as equivalent to holding every credential it stores.
- Peer private keys are stored only when edgekit generated them, so the panel can re-serve the
  config. Register a peer with `--public-key` and the private key is generated on the client
  and never touches this host.
- The panel runs as root because it edits `/etc/wireguard` and calls `wg` and `iptables`. Its
  systemd unit strips everything it does not need (`ProtectSystem=full`, `NoNewPrivileges`,
  an explicit `ReadWritePaths` allowlist).

---

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/ tests/
```

Tests set `EDGEKIT_ROOT` to a temporary directory, so nothing touches `/etc` or `/var`. The
`wg` binary and Docker are stubbed; the API clients are tested against mocked HTTP.

## Requirements

Debian or Ubuntu (or a derivative), kernel 5.6+ preferred for in-tree WireGuard, Python 3.10+,
root access. Docker and WireGuard are installed for you.

# edgekit

Turns a fresh Ubuntu/Debian server into a **WireGuard hub + Nginx Proxy Manager edge**, in one
command, and leaves behind a web panel for managing peers and published services.

It is the [blockey-wireguard-nginx-proxy-manager-guide](blockey-wireguard-nginx-proxy-manager-guide.md)
turned into software: every manual step in that guide — installing WireGuard, writing
`wg0.conf`, enabling IP forwarding, the Docker-to-WireGuard `iptables` rules, deploying NPM,
the origin certificate, the proxy hosts — is a step the installer performs and the panel keeps
managing. The three Cloudflare dashboard actions it cannot do for you are printed as a
checklist with your real values filled in.

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
- your domain, then the origin certificate to install
- panel port and admin account

Then it provisions everything and prints your panel credentials. Re-running it is safe.

### Unattended

Every question can be answered from the environment, so a server can be built with no
interaction at all:

```bash
sudo EDGEKIT_PUBLIC_IP=52.56.216.78 \
     EDGEKIT_WG_SUBNET=10.50.0.0/24 \
     EDGEKIT_ZONE=blockey.ir \
     EDGEKIT_CERT_PATH=/root/origin.pem \
     EDGEKIT_KEY_PATH=/root/origin.key \
     EDGEKIT_PANEL_PASSWORD='a-long-password' \
     ./install.sh --non-interactive
```

| Variable | Meaning |
|---|---|
| `EDGEKIT_PUBLIC_IP` | Public IPv4 of this server |
| `EDGEKIT_WG_SUBNET` / `EDGEKIT_WG_PORT` | Tunnel subnet, WireGuard UDP port |
| `EDGEKIT_NPM_EMAIL` / `EDGEKIT_NPM_PASSWORD` | Nginx Proxy Manager admin account |
| `EDGEKIT_NPM_HTTP_PORT` / `EDGEKIT_NPM_HTTPS_PORT` / `EDGEKIT_NPM_ADMIN_PORT` | Proxy ports |
| `EDGEKIT_ZONE` | Your root domain, e.g. `example.com` |
| `EDGEKIT_CERT_PATH` / `EDGEKIT_KEY_PATH` | Origin certificate and key to install |
| `EDGEKIT_PANEL_USER` / `EDGEKIT_PANEL_PASSWORD` / `EDGEKIT_PANEL_PORT` | Panel account |

Installing from somewhere other than a local checkout:

```bash
sudo EDGEKIT_REPO=https://github.com/you/edgekit.git ./install.sh
sudo EDGEKIT_ARCHIVE=https://example.com/edgekit.tar.gz ./install.sh
```

### Cloudflare: three one-time clicks

edgekit does not need Cloudflare API credentials. These are one-time dashboard actions, and
setup prints this checklist with your real IP filled in.

**1. DNS** (DNS → Records) — two proxied A records:

| Type | Name | Content | Proxy |
|---|---|---|---|
| A | `@` | your server IP | Proxied |
| A | `*` | your server IP | Proxied |

The wildcard covers every subdomain you will ever add.

**2. SSL/TLS** (SSL/TLS → Overview) — set the mode to **Full (strict)**. Not Flexible:
Flexible leaves the Cloudflare-to-server hop unencrypted.

**3. Origin certificate** (SSL/TLS → Origin Server → Create Certificate) — accept the
defaults, set the hostnames to `*.yourdomain` and `yourdomain`. Cloudflare shows an **Origin
Certificate** and a **Private Key**; the key is shown once only. Save both to the server and
point setup at them, or install them later:

```bash
sudo edgekit cert install --cert /root/origin.pem --key /root/origin.key
```

One certificate serves every subdomain for 15 years. edgekit checks that the key matches the
certificate and that it has not expired before installing — a mismatched pair otherwise shows
up much later as a Cloudflare 525.

After that, adding a service needs no Cloudflare work at all: the wildcard DNS record and the
wildcard certificate already cover it.

<details>
<summary>Optional: automating DNS through the Cloudflare API</summary>

If you would rather have edgekit create a DNS record per proxy host, enable the API under
Settings → Cloudflare API, or:

```bash
sudo edgekit cloudflare token --zone example.com
```

The token needs **Zone:Read**, **DNS:Edit** and **Zone Settings:Edit**, with Zone Resources
including the zone. `edgekit cloudflare verify` prints a per-permission tick list.

Note that Cloudflare's Origin CA endpoint is **user-scoped**: an account-owned token (created
from `dash.cloudflare.com/<account-id>/api-tokens`) can manage DNS but cannot issue
certificates. Pass `--origin-ca-key` if you want that automated too. This is exactly the
complexity the manual path avoids.

</details>

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

**Proxy hosts** — publish a service in one form: creates the NPM proxy host pointed at the
peer's tunnel address, with the origin certificate attached. The wildcard DNS record already
covers the hostname, so there is nothing to do in Cloudflare.

**Diagnostics** — the guide's §21 troubleshooting and §23 verification matrix as live checks,
each failure paired with the command that fixes it.

**Settings** — the origin certificate, WireGuard port and MTU, NPM credentials, optional
Cloudflare API access, and a button to re-run the whole provisioner.

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

edgekit cert install --cert origin.pem --key origin.key
edgekit cert status
edgekit host resync                  # re-attach the certificate to existing hosts

edgekit npm diagnose                 # what NPM is, and which credentials it accepts
edgekit npm password                 # re-sync edgekit's copy of the NPM password
edgekit npm reset                    # wipe NPM's data and redeploy (destructive)

edgekit user create alice
edgekit user passwd admin
```

Adding a service, end to end:

```bash
edgekit host add api.blockey.ir 8080 --peer raspberry-pi
```

DNS record, proxy host, SSL — done. No Nginx config editing, no new WireGuard peer.

---

## Upgrading an already-installed server

```bash
cd ~/edgekit && git pull          # or scp the updated source across
sudo /opt/edgekit/venv/bin/pip install --upgrade .
sudo systemctl restart edgekit-panel
sudo edgekit provision            # idempotent; fixes whatever is out of step
```

`edgekit provision` is the repair tool. It is safe to run repeatedly and will re-do only the
steps that are not already in the desired state.

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
server after server, and to re-run after changing the public IP or the certificate.

*The database is the source of truth.* `wg0.conf` is a rendered artifact, regenerated from the
peer table on every change. The file and the running interface cannot drift.

*Certificates are validated before installation.* A key that does not match its certificate,
or an already-expired certificate, is rejected at the point of entry rather than surfacing
later as a Cloudflare 525. When the optional API path is used, the private key is generated
locally and only a CSR is sent.

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

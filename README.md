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

On a fresh Ubuntu/Debian server:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/sina-developer/edgekit@master/install.sh | sudo bash
```

Or from a local checkout:

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
     EDGEKIT_CF_TOKEN='cloudflare-api-token' \
     EDGEKIT_SSL_MODE=proxied \
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
| `EDGEKIT_CF_TOKEN` | Cloudflare API token — required, see [SSL](#ssl-proxied-or-direct) |
| `EDGEKIT_CF_ORIGIN_CA_KEY` | Optional Origin CA Key, for issuing the origin certificate via the API |
| `EDGEKIT_SSL_MODE` | `proxied` (default) or `direct` |
| `EDGEKIT_CERT_PATH` / `EDGEKIT_KEY_PATH` | Origin certificate and key to install (proxied mode) |
| `EDGEKIT_PANEL_USER` / `EDGEKIT_PANEL_PASSWORD` / `EDGEKIT_PANEL_PORT` | Panel account |
| `EDGEKIT_PANEL_BIND` | Panel listen address (default: WireGuard hub IP) |
| `EDGEKIT_PANEL_SUBDOMAIN` | Public panel hostname label (default: `edgekit`) |

Override the source if needed:

```bash
sudo EDGEKIT_REPO=https://github.com/you/edgekit.git ./install.sh
sudo EDGEKIT_ARCHIVE=https://example.com/edgekit.tar.gz ./install.sh
```

### When the server is busy or the network is slow

Two things go wrong on a freshly provisioned VPS, and neither is edgekit's fault:

- **`Could not get lock /var/lib/dpkg/lock-frontend`.** `unattended-upgrades` runs on first
  boot and holds apt for a few minutes. The installer now names the process holding the lock
  and waits for it (15 minutes by default) instead of failing. Nothing to do but let it run.
- **`ReadTimeoutError … pypi.org`.** pip's default 15-second timeout is not enough on a
  congested or filtered link. The installer uses a 60-second timeout, five retries per
  request, and three attempts per command. If PyPI is unreachable from your server, point it
  at a mirror.

```bash
sudo EDGEKIT_PIP_INDEX_URL=https://mirror.example.org/pypi/simple ./install.sh
```

- **`ResolutionImpossible`, or `no matching distributions available for your environment`.**
  Not a network problem: the index answered, but has no build of something (usually `cffi`)
  for this Python on this machine. Either the system Python is newer than the packages
  publish wheels for, or the index is a mirror carrying only part of PyPI. The installer
  retries against PyPI, then installs a compiler toolchain so pip can build from source, and
  if both fail it says which package and which Python. The direct fix is to build the
  virtualenv from a Python the dependencies support:

```bash
sudo apt install python3.12 python3.12-venv
sudo EDGEKIT_PYTHON=python3.12 ./install.sh
```

| Variable | Meaning |
|---|---|
| `EDGEKIT_APT_LOCK_WAIT` | Seconds to wait for a busy apt (default `900`) |
| `EDGEKIT_PIP_INDEX_URL` / `EDGEKIT_PIP_EXTRA_INDEX_URL` | PyPI mirror to install from |
| `EDGEKIT_PIP_TIMEOUT` / `EDGEKIT_PIP_RETRIES` | Per-request pip timeout and retries (`60`, `5`) |
| `EDGEKIT_PIP_ATTEMPTS` | Times to retry the whole pip command (default `3`) |
| `EDGEKIT_PYTHON` | Interpreter to build the virtualenv from (default `python3`) |

The same variables apply to `edgekit setup` and `edgekit update`, which install WireGuard,
Docker, and Python packages the same way.

### SSL: proxied or direct

Setup asks for a Cloudflare API token and an SSL mode, then makes three things agree: the DNS
records' proxy status, the zone's SSL/TLS mode, and the certificate on this server. They have
to — the certificate a browser is shown depends on all three, and one out of step is enough
for a "Not secure" page. A DNS-only record in front of a Cloudflare Origin certificate, for
example, hands browsers a certificate that only Cloudflare's proxy trusts.

| | `proxied` (default) | `direct` |
|---|---|---|
| Visitors connect to | Cloudflare (orange cloud) | this server (DNS only, grey cloud) |
| Certificate on this server | Cloudflare Origin CA, `*.zone` + `zone` | Let's Encrypt, `*.zone` + `zone` |
| Cloudflare SSL/TLS mode | Full (strict), set by edgekit | not in the path |
| Renewal | none needed for 15 years | NPM renews it automatically |
| Choose it when | Cloudflare can reach this server on 443 | Cloudflare answers **525**: its connection to this server is blocked or reset |

Every A record pointing at this server — hand-made ones included — gets the proxy status the
mode calls for. Provisioning then connects to every hostname the way a browser does and
**fails if a browser would reject the certificate it is shown**, waiting out a DNS change it
has only just made. Switch modes at any time; this re-applies DNS, SSL mode and certificate,
then verifies:

```bash
sudo edgekit ssl mode direct
sudo edgekit ssl verify
```

**The token** — dash.cloudflare.com/profile/api-tokens → Create Token → Custom token, with Zone
Resources including your zone — needs **Zone:Read**, **DNS:Edit** and **Zone Settings:Edit**.
Add **SSL and Certificates:Edit** if you want edgekit to issue the origin certificate itself;
Cloudflare's Origin CA endpoint is user-scoped, so an account-owned token cannot do that part
(paste the certificate instead, or pass `--origin-ca-key`). `edgekit cloudflare verify` prints
a per-permission tick list.

**Proxied mode's certificate** — paste it during setup, or create it under SSL/TLS → Origin
Server → Create Certificate with the hostnames `*.yourdomain` and `yourdomain` and install it:

```bash
sudo edgekit cert install --cert /root/origin.pem --key /root/origin.key
```

edgekit checks that the key matches the certificate, that it has not expired, and that it
covers the hostnames this edge serves before installing — a mismatched pair otherwise shows up
much later as a Cloudflare 525. Installing the certificate that is already installed is a
no-op: NPM cannot update one in place, so a re-upload would rewrite every proxy host's SSL
configuration for nothing.

**Direct mode's certificate** is issued by Nginx Proxy Manager through a Cloudflare DNS
challenge, so Let's Encrypt never needs to reach this server on port 80. Let's Encrypt
registers it under the NPM admin email, which therefore has to be a real address rather than
`admin@example.com`. The NPM container installs `certbot-dns-cloudflare` from PyPI and calls
`acme-v02.api.letsencrypt.org`; both must be reachable from this server.

Either way, adding a service later needs no Cloudflare work: the wildcard record and the
wildcard certificate already cover it.

### Diagnosing TLS

`edgekit doctor` walks the TLS path one layer at a time, in the order the request travels, so
a failure names the layer that broke instead of leaving symptoms to correlate:

| Check | What it proves |
|---|---|
| `cf_dns_proxy`, `cf_ssl_mode` | DNS records and the zone's SSL mode match the mode, read from the Cloudflare API |
| `origin_cert`, `cert_expiry`, `cert_coverage` | a certificate is installed, still valid, and names every host you serve |
| `nginx_config` | `nginx -t` inside the NPM container — a vhost it refuses cannot complete a handshake |
| `local_tls_<host>` | TLS to `127.0.0.1:443` with the vhost as SNI |
| `origin_tls_<host>` | the same TLS to your public IP — the hop Cloudflare makes |
| `public_<host>` | what a browser is shown: where DNS points and whether the certificate verifies |

Read it as:

- **Public check shows the Cloudflare Origin certificate** — browsers are bypassing Cloudflare:
  a DNS-only record in proxied mode. `edgekit provision` proxies it.
- **Local TLS good, origin TLS bad** — port 443 is not reaching the host: a cloud-firewall
  problem, not a certificate one.
- **Both good but Cloudflare answers 525** — Cloudflare's own connection to this server fails.
  If nothing on the server explains it, `edgekit ssl mode direct` takes that hop out.
- **526** — the handshake worked and Cloudflare would not accept the certificate (expired,
  wrong hostname, or a CA it does not trust under Full (strict)).
- **Handshake ok, no HTTP response** — TLS is fine; the service behind the host is down or
  slow (an offline peer looks exactly like this).

### The one thing edgekit cannot do for you

Your **cloud provider's firewall** (AWS security group, Hetzner firewall, …) lives outside the
server, so it must be opened by hand:

| Port | Protocol | Action |
|---|---|---|
| 22 | TCP | Open — SSH (keep if you administer over SSH) |
| 51820 | UDP | Open — WireGuard |
| 80 | TCP | Open — HTTP / ACME |
| 443 | TCP | Open — HTTPS |
| 8181 | TCP | Keep closed — NPM admin (localhost) |
| 8088 | TCP | Keep closed — edgekit panel |

Those values are the defaults; setup prints the real ones if you changed them.

---

## The panel

Setup binds the panel to the WireGuard hub IP (e.g. `10.50.0.1:8088`) and publishes it at
`https://edgekit.yourdomain` through Nginx Proxy Manager, with the origin certificate
attached. That is how NPM (running in Docker) can reach the panel — `127.0.0.1` inside the
container is not the host. The hub IP is a *local* address, so that packet hits ufw's INPUT
chain: `edgekit firewall setup` opens the panel port to NPM's Docker subnet only, and to
nothing else.

Keep the panel port **closed** on your cloud firewall; only UDP 51820 and TCP 80/443 need to
be open. For loopback-only access instead, set `EDGEKIT_PANEL_BIND=127.0.0.1` before setup
and use an SSH tunnel:

```bash
ssh -i your-key.pem -L 8088:127.0.0.1:8088 ubuntu@YOUR_SERVER_IP
```

Override the public hostname label with `EDGEKIT_PANEL_SUBDOMAIN=panel` (default `edgekit`).

Forgotten the password? `sudo edgekit user passwd admin` prints a new one.

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
edgekit update                      # git pull, reinstall, re-provision (keeps settings)
edgekit provision                   # re-run provisioning (idempotent)

edgekit firewall setup              # enable ufw, allow OPEN ports, print result
edgekit firewall check              # verify ufw is on and ports match

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
sudo edgekit update
```

That fetches the latest tree from git, reinstalls into `/opt/edgekit`, restarts the panel,
and re-runs provisioning with the settings already on disk. The interview is not shown
again: config, peers, hosts, certificates, and panel accounts stay as they are.

Override the source if needed:

```bash
sudo EDGEKIT_REPO=https://github.com/you/edgekit.git edgekit update
sudo EDGEKIT_SOURCE=/home/you/edgekit edgekit update   # local checkout, no git fetch
sudo edgekit update --ref main
sudo edgekit update --skip-provision                   # package + restart only
```

`edgekit provision` remains the repair tool. It is safe to run repeatedly and will re-do
only the steps that are not already in the desired state.

---

### From the panel

**Settings → Maintenance → Update edgekit** (or **Update edgekit** on the overview) runs the same
`edgekit update` without SSH. It runs as a transient systemd unit, `edgekit-update`, rather
than inside the panel: the update restarts the panel, and would otherwise be killed along
with it. The page follows the log live and reports whether the run succeeded.

---

## Removing edgekit

```bash
sudo edgekit uninstall            # asks you to type "remove"
sudo edgekit uninstall --keep-dns # leave the DNS records edgekit created in Cloudflare
```

Or **Settings → Maintenance → Remove edgekit** in the panel. Removal deletes everything edgekit
created on this server:

- the panel service and every panel account
- Nginx Proxy Manager — containers, image, and `/opt/nginx-proxy-manager` with every proxy
  host, certificate and login in it
- the WireGuard interface, its `wg0.conf` and keys (every peer is disconnected)
- edgekit's iptables rules, ufw openings, systemd units and sysctl drop-in
- `/etc/edgekit`, `/var/lib/edgekit`, `/var/log/edgekit`, `/root/origin.pem` and
  `/root/origin.key` — settings, credentials and records
- the DNS records edgekit created in Cloudflare (those tagged *Managed by edgekit*; records
  you added yourself are kept), unless `--keep-dns`
- edgekit itself: `/opt/edgekit` and `/usr/local/bin/edgekit`

It keeps the Docker and WireGuard packages, which other software may use, and ufw with its SSH
rule, so removal cannot lock you out. Every step is attempted even if an earlier one fails,
and the output lists what, if anything, was left behind.

---

## How it is put together

```
install.sh                  bootstrap: deps → virtualenv → `edgekit setup`
src/edgekit/
  cli.py                    Typer CLI; `setup` is what the installer calls, `update` refreshes
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

*SSL changes are verified, and undone if nginx refuses them.* NPM's API answers 200 for a
proxy host nginx will not serve — a certificate id that is no longer on disk being the usual
way in. After every host change edgekit runs `nginx -t` inside the container and, if it
fails, restores what was there before rather than leaving a vhost that cannot complete a
handshake. When `nginx -t` cannot be run at all, that is reported as unknown, never as a
failure.

*Firewall rules are a script, not `iptables -A`.* The guide's commands are neither idempotent
nor reboot-safe. edgekit writes `/usr/local/lib/edgekit/firewall.sh` — each rule added only if
an identical one is absent — plus a systemd unit that replays it after `docker.service`. The
subnet and interface in that script are read from the network Nginx Proxy Manager is actually
attached to: Compose gives it a project network of its own, so rules naming `docker0` and
`172.17.0.0/16` would compile fine and match nothing.

*The NPM admin UI stays on loopback.* The management panel binds to the WireGuard hub IP and
is published at `edgekit.<zone>` via NPM — never on `0.0.0.0`. Keep the panel port closed on
the cloud firewall.

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

Version lives in `src/edgekit/__init__.py` (`__version__`). After a behavior change,
bump it (SemVer) and add a `CHANGELOG.md` entry — see `.cursor/rules/versioning.mdc`.

Tests set `EDGEKIT_ROOT` to a temporary directory, so nothing touches `/etc` or `/var`. The
`wg` binary and Docker are stubbed; the API clients are tested against mocked HTTP.

## Requirements

Debian or Ubuntu (or a derivative), kernel 5.6+ preferred for in-tree WireGuard, Python 3.10+,
root access. Docker and WireGuard are installed for you.

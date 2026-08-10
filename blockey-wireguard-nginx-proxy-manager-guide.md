# Blockey.ir — WireGuard + Nginx Proxy Manager Setup Guide

## Final architecture

```text
Internet
   |
   v
Cloudflare (Full strict)
   |
   | HTTPS
   v
AWS Ubuntu — 52.56.216.78
   |
   +-- Nginx Proxy Manager
   |      :80
   |      :443
   |      :8181 (admin UI)
   |
   +-- WireGuard wg0
          10.50.0.1/24
             |
             | encrypted tunnel
             v
       Raspberry Pi
       10.50.0.2
             |
             +-- :3001 Retro
             +-- :3000 App
             +-- :8080 API
             +-- other services
```

Goal:

```text
retro.blockey.ir -> Cloudflare -> NPM -> WireGuard -> 10.50.0.2:3001
```

---

# 1. Network details

## AWS Ubuntu server

```text
Public IP:       52.56.216.78
WireGuard:       wg0
WireGuard IP:    10.50.0.1/24
Listen port:     51820/UDP
Server public key:
vQ8c+XmHJWHtiOAkmiX+zHZAOxyC7W+LgijwGmo14yU=
```

Never publish the server private key.

## Raspberry Pi

```text
WireGuard IP:    10.50.0.2/24
Pi public key:
MycqDpa23wNgeG4ROMaW2pZ0rjyFqSV3KYWTKf3U+ms=
```

The Pi connects outward to the AWS server, so the Pi does not need a publicly exposed WireGuard port.

---

# 2. Install WireGuard

Ubuntu:

```bash
sudo apt update
sudo apt install wireguard -y
```

Raspberry Pi:

```bash
sudo apt update
sudo apt install wireguard -y
```

Verify:

```bash
wg --version
```

---

# 3. WireGuard server

File:

```text
/etc/wireguard/wg0.conf
```

Example:

```ini
[Interface]
Address = 10.50.0.1/24
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY

[Peer]
PublicKey = MycqDpa23wNgeG4ROMaW2pZ0rjyFqSV3KYWTKf3U+ms=
AllowedIPs = 10.50.0.2/32
```

Start:

```bash
sudo wg-quick up wg0
```

Enable at boot:

```bash
sudo systemctl enable wg-quick@wg0
```

Check:

```bash
sudo systemctl status wg-quick@wg0 --no-pager
sudo wg show
```

`active (exited)` is normal for `wg-quick`.

---

# 4. AWS Security Group

Allow:

```text
UDP 51820
TCP 80
TCP 443
```

Ideally restrict NPM admin port `8181` to your own IP/VPN instead of exposing it publicly.

---

# 5. Raspberry Pi WireGuard

File:

```text
/etc/wireguard/wg0.conf
```

Example:

```ini
[Interface]
PrivateKey = PI_PRIVATE_KEY
Address = 10.50.0.2/24

[Peer]
PublicKey = vQ8c+XmHJWHtiOAkmiX+zHZAOxyC7W+LgijwGmo14yU=
Endpoint = 52.56.216.78:51820
AllowedIPs = 10.50.0.1/32
PersistentKeepalive = 25
```

Protect it:

```bash
sudo chmod 600 /etc/wireguard/wg0.conf
```

Start and enable:

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

Check:

```bash
sudo wg show
sudo systemctl status wg-quick@wg0 --no-pager
```

A healthy connection should show:

```text
latest handshake: ...
```

---

# 6. Test WireGuard

From Pi:

```bash
ping -c 4 10.50.0.1
```

From Ubuntu:

```bash
ping -c 4 10.50.0.2
```

Both should work.

---

# 7. Verify the Pi application

Retro service:

```text
10.50.0.2:3001
```

From Ubuntu:

```bash
curl -v --connect-timeout 5 http://10.50.0.2:3001
```

Expected:

```text
HTTP/1.1 200 OK
```

This proves Ubuntu -> WireGuard -> Pi -> application works.

---

# 8. Install Docker

Install Docker using the appropriate official/current method for the Ubuntu release.

Verify:

```bash
docker --version
docker compose version
```

---

# 9. Install Nginx Proxy Manager

Create directory:

```bash
sudo mkdir -p /opt/nginx-proxy-manager
cd /opt/nginx-proxy-manager
```

Create `docker-compose.yml`:

```yaml
services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: nginx-proxy-manager
    restart: unless-stopped

    ports:
      - "80:80"
      - "8181:81"
      - "443:443"

    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
```

Validate:

```bash
sudo docker compose config
```

Start:

```bash
sudo docker compose up -d
```

Check:

```bash
sudo docker ps
sudo docker logs nginx-proxy-manager --tail 50
```

Expected ports:

```text
0.0.0.0:80->80/tcp
0.0.0.0:443->443/tcp
0.0.0.0:8181->81/tcp
```

---

# 10. Stop the old host Nginx

NPM needs ports 80 and 443.

```bash
sudo systemctl stop nginx
sudo systemctl disable nginx
```

Verify:

```bash
sudo ss -ltnp | grep -E ':80|:443'
```

Then:

```bash
cd /opt/nginx-proxy-manager
sudo docker compose up -d
```

Verify:

```bash
sudo ss -ltnp | grep -E ':80|:443|:8181'
```

Docker should own the ports.

---

# 11. NPM admin UI

Open:

```text
http://52.56.216.78:8181
```

Log in and immediately change the default password.

Prefer restricting port `8181` with the AWS Security Group/firewall.

---

# 12. Cloudflare DNS

Create records pointing to:

```text
52.56.216.78
```

Example:

```text
blockey.ir       A    52.56.216.78    Proxied
*.blockey.ir     A    52.56.216.78    Proxied
retro.blockey.ir A    52.56.216.78    Proxied
```

Check:

```bash
dig +short blockey.ir
dig +short retro.blockey.ir
```

When proxied, Cloudflare IPs are returned by DNS. That is expected.

---

# 13. Cloudflare SSL

Cloudflare:

```text
SSL/TLS -> Overview
```

Use:

```text
Full (strict)
```

Do not use Flexible.

Final flow:

```text
Browser
   |
 HTTPS
   v
Cloudflare
   |
 HTTPS
   v
Nginx Proxy Manager
```

---

# 14. Create Cloudflare Origin Certificate

Cloudflare:

```text
SSL/TLS
  -> Origin Server
  -> Create Certificate
```

Cover:

```text
*.blockey.ir
blockey.ir
```

The certificate can be reused by all matching subdomains.

Cloudflare provides:

```text
Origin Certificate
Private Key
```

Never publish the private key.

---

# 15. Add certificate to NPM

NPM:

```text
SSL Certificates
  -> Add SSL Certificate
  -> Custom
```

Example name:

```text
Cloudflare Origin - blockey.ir
```

Add:

```text
Certificate
Certificate Key
```

Save.

---

# 16. Create the Retro proxy host

NPM:

```text
Hosts
  -> Proxy Hosts
  -> Add Proxy Host
```

Use:

```text
Domain Names:
retro.blockey.ir

Scheme:
http

Forward Hostname / IP:
10.50.0.2

Forward Port:
3001
```

SSL:

```text
SSL Certificate:
Cloudflare Origin - blockey.ir

Force SSL:
Enabled

HTTP/2 Support:
Enabled
```

Save.

Final route:

```text
retro.blockey.ir
      |
      v
Cloudflare
      |
      v
AWS :443
      |
      v
NPM
      |
      v
10.50.0.2:3001
```

---

# 17. Docker -> WireGuard networking

Initially the NPM container could not reach:

```text
10.50.0.2:3001
```

Docker bridge subnet:

```text
172.17.0.0/16
```

Enable forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Verify:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```text
net.ipv4.ip_forward = 1
```

Add forwarding:

```bash
sudo iptables -A FORWARD   -i docker0   -o wg0   -d 10.50.0.0/24   -j ACCEPT
```

Return traffic:

```bash
sudo iptables -A FORWARD   -i wg0   -o docker0   -s 10.50.0.0/24   -m conntrack   --ctstate ESTABLISHED,RELATED   -j ACCEPT
```

NAT:

```bash
sudo iptables -t nat -A POSTROUTING   -s 172.17.0.0/16   -d 10.50.0.0/24   -o wg0   -j MASQUERADE
```

Test from NPM container:

```bash
sudo docker exec nginx-proxy-manager   curl -I --connect-timeout 5   http://10.50.0.2:3001
```

Expected:

```text
HTTP/1.1 200 OK
```

This was the important Docker-to-WireGuard fix.

---

# 18. Local proxy tests

HTTP:

```bash
curl -I   -H "Host: retro.blockey.ir"   http://127.0.0.1
```

Expected:

```text
HTTP/1.1 200 OK
```

HTTPS:

```bash
curl -vkI   https://127.0.0.1   -H "Host: retro.blockey.ir"
```

After the origin certificate is configured, TLS should succeed.

---

# 19. Public test

```bash
curl -I https://retro.blockey.ir
```

Expected:

```text
HTTP/2 200
server: cloudflare
```

If Cloudflare returns:

```text
HTTP/2 525
```

check the NPM SSL certificate first.

A 525 means Cloudflare could not complete the TLS handshake with the origin.

---

# 20. Adding future services

Once the infrastructure is working, new services normally require no manual Nginx editing.

Example:

```text
app.blockey.ir    -> 10.50.0.2:3000
api.blockey.ir    -> 10.50.0.2:8080
admin.blockey.ir  -> 10.50.0.2:9000
game.blockey.ir   -> 10.50.0.2:5000
```

For each:

1. Run the service on the Pi.
2. Verify the port works.
3. Add DNS in Cloudflare if necessary.
4. NPM -> Hosts -> Proxy Hosts -> Add Proxy Host.
5. Set the Pi IP and port.
6. Select the existing `*.blockey.ir` certificate.
7. Enable Force SSL.
8. Save.

No new WireGuard peer is needed.

No new per-port Docker rule is normally needed.

---

# 21. Troubleshooting

## WireGuard has no handshake

Pi:

```bash
sudo wg show
sudo systemctl status wg-quick@wg0 --no-pager
```

Check:

```text
Endpoint = 52.56.216.78:51820
```

and AWS Security Group:

```text
UDP 51820 allowed
```

---

## Ubuntu can reach Pi, but NPM cannot

Host test:

```bash
curl -I http://10.50.0.2:3001
```

Container test:

```bash
sudo docker exec nginx-proxy-manager   curl -I --connect-timeout 5   http://10.50.0.2:3001
```

Check:

```bash
sysctl net.ipv4.ip_forward
```

Should be:

```text
net.ipv4.ip_forward = 1
```

Check Docker subnet:

```bash
sudo docker network inspect bridge   --format '{{(index .IPAM.Config 0).Subnet}}'
```

Make sure forwarding/NAT rules cover that subnet.

---

## NPM is not reachable

```bash
sudo docker ps
sudo docker logs nginx-proxy-manager --tail 100
sudo ss -ltnp | grep -E ':80|:443|:8181'
```

---

## Cloudflare returns 525

Test:

```bash
curl -vkI   https://127.0.0.1   -H "Host: retro.blockey.ir"
```

Check certificate:

```bash
openssl s_client   -connect 127.0.0.1:443   -servername retro.blockey.ir   </dev/null 2>/dev/null |
  openssl x509 -noout -subject -issuer -dates
```

Verify NPM has a certificate matching the hostname.

Keep Cloudflare on:

```text
Full (strict)
```

---

# 22. Useful commands

WireGuard:

```bash
sudo wg show
sudo wg-quick up wg0
sudo wg-quick down wg0
sudo systemctl status wg-quick@wg0 --no-pager
sudo systemctl enable wg-quick@wg0
```

Docker:

```bash
sudo docker ps
sudo docker compose ps
sudo docker compose logs -f
sudo docker logs nginx-proxy-manager --tail 100
sudo docker compose restart
```

Ports:

```bash
sudo ss -ltnp | grep -E ':80|:443|:8181'
```

WireGuard interface:

```bash
ip addr show wg0
```

Pi service:

```bash
curl -I http://10.50.0.2:3001
```

DNS:

```bash
dig +short blockey.ir
dig +short retro.blockey.ir
```

NPM -> Pi:

```bash
sudo docker exec nginx-proxy-manager   curl -I --connect-timeout 5   http://10.50.0.2:3001
```

Local proxy:

```bash
curl -I   -H "Host: retro.blockey.ir"   http://127.0.0.1
```

Public proxy:

```bash
curl -I https://retro.blockey.ir
```

---

# 23. Final verified state

```text
WireGuard handshake             OK
Pi -> AWS ping                  OK
AWS -> Pi ping                  OK
AWS -> Pi:3001                  OK
NPM -> Pi:3001                  OK
NPM :80                         OK
NPM :443                        OK
Cloudflare DNS                  OK
Cloudflare Full (strict)        OK
Origin SSL                      OK
retro.blockey.ir                OK
NPM admin UI                    OK
```

## The normal future workflow

```text
1. Run service on Pi
2. Verify Pi port
3. Add DNS/subdomain if necessary
4. Add Proxy Host in NPM
5. Select existing *.blockey.ir certificate
6. Enable Force SSL
7. Done
```

The main benefit of this architecture is that Nginx Proxy Manager becomes the administration layer. You do not need to manually edit Nginx configuration for every new subdomain.

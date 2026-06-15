# RADIUS / TACACS+ unreachable behind a hardened Docker host

**Symptom:** Check Point Gaia (or any NAS) reports the RADIUS server timed out —

```
pam_radius_auth: RADIUS server <host>:1812 failed to respond (time out 3 sec)
pam_radius_auth: All RADIUS servers failed to respond.
```

— and the simulator's **RADIUS → Live log** shows **nothing**. TACACS+ behaves the
same way (connection just hangs).

> **Key diagnostic:** an empty Live log means the packet *never reached the app*.
> A wrong shared secret would still produce a `reject` row (the app receives the
> packet, fails to decrypt the password, and logs it). **Silence = a network/
> firewall problem, not an app problem.** The app is almost certainly fine.

---

## Why this happens

RADIUS (UDP 1812/1813) and TACACS+ (TCP 49) are **not HTTP**, so Traefik/Dokploy
**cannot route them by hostname**. They are published directly on the **host's
public IP** (see `docker-compose.yml` `ports:`) and must be reached at that IP —
**not** at the `IDP_DOMAIN` web address. The portal's **"How to reach this
server"** card (RADIUS/TACACS+ pages) shows the auto-detected host IP to use.

That gets the packet to the host. The second gate is the **host firewall**. A
security-hardened Docker host often closes the well-known "Docker bypasses UFW"
hole by filtering published container ports in the **`DOCKER-USER`** iptables
chain — typically allowing only `80`/`443` inbound and dropping everything else:

```
Chain DOCKER-USER
  RETURN  ctstate RELATED,ESTABLISHED
  RETURN  tcp dpt:80   in <wan-if>
  RETURN  tcp dpt:443  in <wan-if>
  DROP    in <wan-if>          <-- RADIUS/TACACS+ die here
```

So the packet is DNAT'd toward the container and then **dropped in `FORWARD`/
`DOCKER-USER` before it reaches the container**. `docker ps` shows the port
published and `ss -lun` shows the host listening, yet nothing arrives — which is
exactly what makes this confusing.

---

## Diagnose (read-only)

Run on the Docker host. Replace the container name / interface as needed.

```bash
# 1. Is the port actually published by the container?
docker ps --format '{{.Names}}  {{.Ports}}' | grep -i simulator
#   want: 0.0.0.0:1812-1813->1812-1813/udp, 0.0.0.0:49->4949/tcp

# 2. Is the host listening?
ss -lun | grep -E ':1812|:1813'      # UDP (RADIUS)
ss -ltn | grep -E ':49 '             # TCP (TACACS+, host side)

# 3. Does the app answer LOCALLY? (proves it's a firewall issue, not the app)
python3 - <<'PY'
import socket, struct, os
attr = bytes([1, 2 + len(b'probe')]) + b'probe'              # User-Name = probe
pkt  = bytes([1, 7]) + struct.pack('!H', 20 + len(attr)) + os.urandom(16) + attr
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(pkt, ('127.0.0.1', 1812))
try: print('LOCAL REPLY code', s.recvfrom(4096)[0][0], '-> app is fine')
except Exception as e: print('LOCAL NO REPLY:', e)
PY

# 4. Find the WAN interface + confirm the public IP is on this box (not NAT)
ip -br a | grep -v '^lo'

# 5. Inspect the firewall: is DOCKER-USER dropping our ports?
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

If step 3 replies (`code 3`) but the port is unreachable from outside, the
firewall in step 5 is the cause.

---

## Fix

Allow the three AAA ports **inbound on the WAN interface**, mirroring how `80`/`443`
are allowed, **above** the `DROP`.

> **TACACS+ port note:** `DOCKER-USER` runs *after* DNAT, so it matches the
> **container** port. The compose maps host `49 → 4949`, so allow **`tcp 4949`**
> (not `49`). RADIUS is `1812:1812`/`1813:1813` (unchanged).

### 1. Apply at runtime (effective immediately)

```bash
WAN=vlan.9        # your WAN interface from `ip -br a`
sudo iptables -I DOCKER-USER 4 -i "$WAN" -p udp --dport 1812 -j RETURN
sudo iptables -I DOCKER-USER 4 -i "$WAN" -p udp --dport 1813 -j RETURN
sudo iptables -I DOCKER-USER 4 -i "$WAN" -p tcp --dport 4949 -j RETURN
```

(`4` inserts above the existing `DROP`; adjust if your chain differs.)

### 2. Persist across reboots

On UFW hosts the `DOCKER-USER` chain is rebuilt from `/etc/ufw/after.rules`.
Back it up, then add the same three lines **before** the `DROP` in the
`DOCKER-USER` block:

```bash
sudo cp /etc/ufw/after.rules /etc/ufw/after.rules.bak
```
```diff
  -A DOCKER-USER -i vlan.9 -p tcp --dport 443 -j RETURN
+ -A DOCKER-USER -i vlan.9 -p udp --dport 1812 -j RETURN
+ -A DOCKER-USER -i vlan.9 -p udp --dport 1813 -j RETURN
+ -A DOCKER-USER -i vlan.9 -p tcp --dport 4949 -j RETURN
  -A DOCKER-USER -i vlan.9 -j DROP
```

The runtime rules in step 1 are already active, so a `ufw reload` is **not**
required immediately — and on a busy multi-container host it's worth avoiding
until a maintenance window (a reload re-applies all rules and can briefly perturb
Docker's own chains). The edit ensures the rules return after the next reboot.

### 3. Verify from outside

```bash
# From a machine that is NOT the host:
python3 - <<'PY'
import socket, struct, os
attr = bytes([1, 2 + len(b'probe')]) + b'probe'              # User-Name = probe
pkt  = bytes([1, 11]) + struct.pack('!H', 20 + len(attr)) + os.urandom(16) + attr
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
s.sendto(pkt, ('YOUR_HOST_IP', 1812))
try: print('EXTERNAL REPLY code', s.recvfrom(4096)[0][0], '-> reachable')
except Exception as e: print('EXTERNAL NO REPLY:', e)
PY
```

A reply (`code 3`) means RADIUS is now reachable — retry the Gaia login and watch
the row appear in the Live log.

---

## Revert

```bash
# Runtime:
sudo iptables -D DOCKER-USER -i vlan.9 -p udp --dport 1812 -j RETURN
sudo iptables -D DOCKER-USER -i vlan.9 -p udp --dport 1813 -j RETURN
sudo iptables -D DOCKER-USER -i vlan.9 -p tcp --dport 4949 -j RETURN
# Persistent: restore the backup, then reload
sudo cp /etc/ufw/after.rules.bak /etc/ufw/after.rules && sudo ufw reload
```

---

## Other things that block it

- **Cloud security group** — if the host is a cloud VM, the provider's network
  firewall is a separate layer from the OS firewall. Allow inbound `udp/1812`,
  `udp/1813`, `tcp/49`.
- **Wrong address in Gaia** — must be the host **IP** (from the portal card), not
  the web domain, and **UDP 1812** for auth (1813 is accounting).
- **Shared secret mismatch** — this shows as a `reject` row in the Live log, not
  silence. If you see rejects, fix the secret on the RADIUS/TACACS+ page.

# 🐳 Docker Security Problem #3 — Exposed Docker Daemon Socket

> **Severity:** 🔴 Critical  
> **Category:** Configuration / Runtime  
> **MITRE ATT&CK:** [T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)  
> **CWE:** [CWE-732 – Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Remove the socket mount](#option-1-remove-the-socket-mount)
  - [Option 2: Use a socket proxy](#option-2-use-a-socket-proxy)
  - [Option 3: Use rootless Docker](#option-3-use-rootless-docker)
  - [Option 4: Use Podman instead of Docker](#option-4-use-podman-instead-of-docker)
  - [Option 5: Kubernetes — avoid hostPath mounts](#option-5-kubernetes--avoid-hostpath-mounts)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

The Docker daemon socket (`/var/run/docker.sock`) is the Unix socket that the Docker CLI communicates with to control Docker. Mounting it inside a container gives that container **complete control over the Docker host** — it can:

- Spin up new privileged containers
- Mount the host filesystem
- Kill or inspect all other containers
- Extract secrets from running containers
- Achieve full root-level host access

This is equivalent to giving a container the keys to the entire server.

---

## Why It Happens

The socket mount is commonly used for:

- CI/CD agents (Jenkins, GitLab Runner) that need to build Docker images
- Monitoring tools (Portainer, cAdvisor) that inspect containers
- Reverse proxies (Traefik, Nginx Proxy Manager) that auto-discover containers
- Development tools that rebuild on code changes

It's a quick and easy pattern that developers reach for without understanding the blast radius.

```yaml
# This is extremely common and extremely dangerous
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| App container compromised | Attacker accesses Docker socket, launches privileged container, mounts host `/` |
| CI agent with socket mount | Malicious build step escapes to host, steals secrets |
| Monitoring tool exposed | Lateral movement across all containers |
| Read-only socket still risky | Attacker reads secrets, env vars, configs from other containers |
| Automated exploit tools | Tools like `deepce` can fully escape using the socket in seconds |

**Instant host escape via Docker socket:**

```bash
# If an attacker gets shell in a container with docker.sock mounted:
docker run -v /:/host --rm -it alpine chroot /host
# They now have a root shell on the host OS
```

---

## How to Detect It

### Find all containers with the socket mounted

```bash
# Check all running containers for docker.sock mount
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: {{range .Mounts}}{{.Source}} {{end}}' \
  | grep docker.sock
```

### Check a specific container

```bash
docker inspect <container_name> | grep -A5 "docker.sock"
```

### Check docker-compose files in your repo

```bash
grep -r "docker.sock" . --include="*.yml" --include="*.yaml" --include="*.json"
```

### Scan with Trivy (misconfiguration mode)

```bash
trivy config .
# Reports: "docker.sock is mounted"
```

### Check Docker daemon TCP exposure

```bash
# Is the Docker daemon exposed over TCP (even worse than socket)?
ss -tlnp | grep 2375
ss -tlnp | grep 2376
curl http://localhost:2375/version   # Should fail/timeout
```

---

## The Fix

### Option 1: Remove the socket mount

The simplest fix — remove it and find an alternative approach for whatever use case required it.

```yaml
# ❌ Before
services:
  myapp:
    image: myapp:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

# ✅ After — no socket mount
services:
  myapp:
    image: myapp:latest
```

**For CI/CD — use Docker-in-Docker (DinD) instead:**

```yaml
# GitLab CI — use dind service, not socket mount
services:
  - docker:24-dind

variables:
  DOCKER_HOST: tcp://docker:2376
  DOCKER_TLS_CERTDIR: "/certs"

build:
  image: docker:24
  script:
    - docker build -t myapp .
```

### Option 2: Use a socket proxy

If you genuinely need container access (e.g., Traefik, Portainer), use a read-limited proxy that exposes only the specific API endpoints needed.

```yaml
# docker-compose.yml — Tecnativa socket proxy
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1     # allow read containers
      SERVICES: 1       # allow read services
      NETWORKS: 1       # allow read networks
      TASKS: 1          # allow read tasks
      # POST: 0 by default — no create/delete/exec
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - proxy-net

  traefik:
    image: traefik:v3
    environment:
      - DOCKER_HOST=tcp://socket-proxy:2375
    networks:
      - proxy-net
    # No direct socket mount on traefik container
```

> The proxy only exposes read-only GET endpoints — an attacker who compromises Traefik cannot launch new containers or escape the host.

### Option 3: Use rootless Docker

Rootless Docker runs the daemon itself as a non-root user. Even if the socket is exposed, the blast radius is limited to the unprivileged user's permissions.

```bash
# Install rootless Docker
dockerd-rootless-setuptool.sh install

# Start the rootless daemon
systemctl --user start docker

# Verify
docker context ls
# Should show a rootless context
docker info | grep rootless
```

```bash
# The socket path changes for rootless
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
```

### Option 4: Use Podman instead of Docker

Podman is daemonless and rootless by design — there's no central socket to expose.

```bash
# Drop-in Docker replacement
alias docker=podman

# Podman has no daemon, no socket by default
# Build and run work the same way
podman build -t myapp .
podman run myapp
```

### Option 5: Kubernetes — avoid hostPath mounts

```yaml
# ❌ Bad — mounting docker socket in Kubernetes
volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock

# ✅ Better — use containerd socket with read-only and only if strictly needed
volumes:
  - name: containerd-socket
    hostPath:
      path: /run/containerd/containerd.sock
      type: Socket

# ✅ Best — use a purpose-built tool that doesn't need the socket
# e.g. Kaniko for image builds, no socket required
containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
      - "--context=git://github.com/myorg/myrepo"
      - "--destination=myrepo/myimage:latest"
```

---

## Verification

```bash
# 1. Confirm no running containers have the socket mounted
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: {{range .Mounts}}{{.Source}}{{end}}' \
  | grep -v docker.sock
# Should print names with no docker.sock entries

# 2. Confirm Docker daemon is not exposed over TCP
curl -s --max-time 2 http://localhost:2375/version
# Should fail: Connection refused

# 3. If using socket proxy, verify only allowed endpoints work
curl http://localhost:2375/containers/json   # should work (if CONTAINERS=1)
curl -X POST http://localhost:2375/containers/create  # should fail (403)

# 4. Trivy config scan
trivy config --severity HIGH,CRITICAL docker-compose.yml
```

---

## Hardening Checklist

- [ ] No containers mount `/var/run/docker.sock` in production
- [ ] CI/CD builds use DinD or Kaniko instead of socket mount
- [ ] Monitoring/proxy tools use `tecnativa/docker-socket-proxy` with minimal permissions
- [ ] Docker daemon TCP port (2375/2376) is not exposed
- [ ] Rootless Docker or Podman used where possible
- [ ] `grep -r docker.sock` run across all compose files in repo
- [ ] Kubernetes admission policy blocking `hostPath: /var/run/docker.sock`
- [ ] Regular audits: `docker ps -q | xargs docker inspect`

---

## Real-World CVEs & Incidents

| Incident / CVE | Year | Summary |
|---|---|---|
| Tesla Kubernetes cryptojacking | 2018 | Exposed Docker API (no auth) allowed attackers to run cryptominer containers on Tesla's AWS infrastructure |
| Graboid cryptoworm | 2019 | Spread via exposed Docker daemon TCP ports — first Docker container worm |
| CVE-2019-14271 | 2019 | Docker cp command exploit — combined with socket access for host escape |
| CVE-2021-21285 | 2021 | Docker daemon DoS via malformed image — exploitable via exposed socket |
| Jenkins agent socket escapes | 2022+ | Repeated incidents where Jenkins agents with socket mounts were used to pivot to host in CI/CD attacks |

---

## References

- [Docker socket security — official docs](https://docs.docker.com/engine/security/#docker-daemon-attack-surface)
- [Tecnativa Docker Socket Proxy](https://github.com/Tecnativa/docker-socket-proxy)
- [Rootless Docker setup](https://docs.docker.com/engine/security/rootless/)
- [Kaniko — build images without Docker daemon](https://github.com/GoogleContainerTools/kaniko)
- [deepce — Docker enumeration and escape tool (research)](https://github.com/stealthcopter/deepce)
- [MITRE T1611 — Escape to Host](https://attack.mitre.org/techniques/T1611/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

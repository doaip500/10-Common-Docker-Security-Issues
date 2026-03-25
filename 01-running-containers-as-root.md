# 🐳 Docker Security Problem #1 — Running Containers as Root

> **Severity:** 🔴 Critical  
> **Category:** Runtime / Configuration  
> **MITRE ATT&CK:** [T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)  
> **CWE:** [CWE-250 – Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Dockerfile (recommended)](#option-1-dockerfile-recommended)
  - [Option 2: docker run flag](#option-2-docker-run-flag)
  - [Option 3: Docker Compose](#option-3-docker-compose)
  - [Option 4: Kubernetes Security Context](#option-4-kubernetes-security-context)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

By default, processes inside a Docker container run as **root (UID 0)**. While containers provide namespace-level isolation, running as root still poses a significant risk:

- If an attacker exploits a vulnerability in your application, they operate as root *inside* the container.
- If a container escape vulnerability exists in the kernel or Docker runtime (e.g., `runc`), root-inside becomes **root-on-the-host** — a full system compromise.

This is one of the most common and most dangerous misconfigurations found in production container environments.

---

## Why It Happens

Docker does not enforce a non-root user by default. Most official base images (Ubuntu, Debian, Alpine, etc.) also default to root unless explicitly configured otherwise. Teams often skip this step during rapid development and never revisit it.

```bash
# Proof: run any standard image and check who you are
docker run --rm ubuntu whoami
# Output: root
```

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| RCE vulnerability in app code | Attacker has root inside container |
| Kernel exploit (e.g., Dirty COW, runc CVE) | Attacker escapes to host as root |
| Misconfigured volume mount | Root in container reads/writes host files |
| Container breakout via `/proc` or capabilities | Full host takeover |
| Lateral movement via shared network | Root process can bind to privileged ports, sniff traffic |

---

## How to Detect It

### Check a running container

```bash
# See the user a container is running as
docker inspect <container_id> --format '{{.Config.User}}'
# Empty output = running as root (default)

# Or exec into it directly
docker exec -it <container_id> whoami
```

### Audit all running containers at once

```bash
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}} — User: {{.Config.User}}' \
  | grep -E 'User: $|User: root'
```

### Scan with Trivy

```bash
trivy image --severity HIGH,CRITICAL <your-image>
# Look for: "Running as root user"
```

### Check with Docker Bench for Security

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
# Check: [WARN] 4.1 Ensure that a user for the container has been created
```

---

## The Fix

### Option 1: Dockerfile (recommended)

Add a dedicated non-root user directly in your image. This is the most portable and reproducible approach.

```dockerfile
FROM node:20-alpine

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory and ownership
WORKDIR /app
COPY --chown=appuser:appgroup . .

RUN npm ci --only=production

# Switch to non-root user before CMD
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]
```

> ✅ The `USER` instruction applies to all subsequent `RUN`, `CMD`, and `ENTRYPOINT` instructions.

**For Python:**

```dockerfile
FROM python:3.12-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup . .

USER appuser
CMD ["python", "app.py"]
```

---

### Option 2: docker run flag

Override at runtime without changing the image. Useful for third-party images you don't control.

```bash
docker run --user 1000:1000 nginx
```

To find a non-root UID available on the host:

```bash
id  # shows your current UID/GID
# uid=1000(youruser) gid=1000(yourgroup)
```

---

### Option 3: Docker Compose

```yaml
# docker-compose.yml
services:
  web:
    image: myapp:latest
    user: "1000:1000"   # UID:GID
    # or use a named user if defined in the image:
    # user: "appuser"
```

---

### Option 4: Kubernetes Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true       # Kubernetes will reject the pod if UID is 0
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000            # Files created in volumes get this GID
      containers:
        - name: myapp
          image: myapp:latest
          securityContext:
            allowPrivilegeEscalation: false   # Prevents sudo/setuid escalation
            readOnlyRootFilesystem: true       # Combine with non-root for full hardening
            capabilities:
              drop:
                - ALL             # Drop all Linux capabilities
```

---

## Verification

After applying the fix, verify your container is no longer running as root:

```bash
# 1. Build and run your updated image
docker build -t myapp:secure .
docker run --rm myapp:secure whoami
# Expected output: appuser (NOT root)

# 2. Check the UID
docker run --rm myapp:secure id
# Expected: uid=1000(appuser) gid=1000(appgroup)

# 3. Confirm Docker inspect shows the user
docker inspect myapp:secure --format '{{.Config.User}}'
# Expected: appuser (not empty)

# 4. Try to write to a system path — should fail
docker run --rm myapp:secure touch /etc/test
# Expected: touch: /etc/test: Permission denied
```

---

## Hardening Checklist

Use this alongside the non-root user fix for defense-in-depth:

- [ ] `USER <non-root>` set in Dockerfile
- [ ] Files `COPY`-ed with `--chown=appuser:appgroup`
- [ ] `--read-only` filesystem enabled at runtime
- [ ] `--cap-drop ALL` with only required capabilities added back
- [ ] `--no-new-privileges` flag set
- [ ] `allowPrivilegeEscalation: false` in Kubernetes
- [ ] `runAsNonRoot: true` enforced in Kubernetes or OPA/Gatekeeper policy
- [ ] Image scanned with Trivy or Grype in CI pipeline

**Full hardened docker run example:**

```bash
docker run \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  myapp:secure
```

---

## Real-World CVEs & Incidents

| CVE | Year | Summary |
|---|---|---|
| CVE-2019-5736 | 2019 | `runc` container escape — root in container led to host root compromise |
| CVE-2020-15257 | 2020 | `containerd` API exposure — root processes could access host socket |
| CVE-2022-0492 | 2022 | Linux `cgroups` escape — root in container could escape to host |
| CVE-2024-21626 | 2024 | `runc` process.cwd escape — root container process leaked into host filesystem |

> In all cases above, running as a non-root user with dropped capabilities would have significantly reduced or fully prevented the impact.

---

## References

- [Docker official docs — Run as non-root user](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Trivy — Container vulnerability scanner](https://github.com/aquasecurity/trivy)
- [MITRE ATT&CK T1611 — Escape to Host](https://attack.mitre.org/techniques/T1611/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

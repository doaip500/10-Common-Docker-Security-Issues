# 🐳 Docker Security Problem #9 — Writable Container Filesystems

> **Severity:** 🔵 Medium  
> **Category:** Runtime / Configuration  
> **MITRE ATT&CK:** [T1565 – Data Manipulation](https://attack.mitre.org/techniques/T1565/) / [T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  
> **CWE:** [CWE-732 – Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: docker run --read-only](#option-1-docker-run---read-only)
  - [Option 2: Docker Compose](#option-2-docker-compose)
  - [Option 3: Kubernetes readOnlyRootFilesystem](#option-3-kubernetes-readonlyrootfilesystem)
  - [Option 4: tmpfs for writable paths](#option-4-tmpfs-for-writable-paths)
  - [Option 5: Combine with seccomp and AppArmor](#option-5-combine-with-seccomp-and-apparmor)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

By default, Docker containers have a writable filesystem layer. Any process running inside the container can create, modify, or delete files anywhere in the container's filesystem — including binary directories, configuration files, and temporary work areas.

If an attacker gains code execution inside a container, a writable filesystem lets them:

- Install attack tools (curl, ncat, python, reverse shells)
- Modify application binaries or startup scripts
- Drop persistence mechanisms
- Write exploit code and execute it

A read-only filesystem makes post-exploitation dramatically harder — attackers can execute code but can't change anything.

---

## Why It Happens

Writable filesystem is the Docker default, and many applications genuinely need to write files (logs, temp files, uploads, caches). Making the filesystem read-only requires knowing exactly where your app writes and explicitly allowing those paths — effort that teams skip.

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| RCE vulnerability exploited | Attacker installs reverse shell tools directly in container |
| Supply chain compromise | Malicious code modifies app binaries after deployment |
| Compromised process writes to /tmp | Staging ground for further exploitation |
| Log4Shell-style exploit | Attacker writes malicious class files to filesystem |
| Container escape attempt | Writable fs used to stage exploit binaries |
| Config tampering | App configs modified to exfiltrate data |

---

## How to Detect It

### Check if a container has a read-only filesystem

```bash
# Inspect root filesystem read-only setting
docker inspect <container_name> --format '{{.HostConfig.ReadonlyRootfs}}'
# false = writable (default), true = read-only

# Check all running containers
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: ReadOnly={{.HostConfig.ReadonlyRootfs}}' \
  | grep "ReadOnly=false"
```

### Test writability inside a container

```bash
# Try to write to a system directory
docker exec <container> touch /tmp/test
docker exec <container> touch /usr/bin/test
docker exec <container> echo "evil" > /etc/passwd
# If these succeed, filesystem is writable
```

### Kubernetes — check security context

```bash
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.readOnlyRootFilesystem != true) | .metadata.name'
```

### Trivy misconfiguration scan

```bash
trivy config --severity MEDIUM,HIGH,CRITICAL .
# Reports: "readOnlyRootFilesystem is not set to true"
```

---

## The Fix

### Option 1: docker run --read-only

```bash
# ❌ Before — writable filesystem (default)
docker run myapp

# ✅ After — read-only root filesystem
docker run --read-only myapp

# Many apps need to write to /tmp — mount it as tmpfs
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  myapp

# Full hardened example
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /var/run:rw,noexec,nosuid,size=16m \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  myapp
```

**tmpfs mount options explained:**

| Option | Effect |
|---|---|
| `rw` | Read-write (tmpfs is in RAM) |
| `noexec` | Cannot execute binaries from this mount |
| `nosuid` | SUID bits ignored |
| `size=Xm` | Cap the tmpfs size to prevent RAM exhaustion |

### Option 2: Docker Compose

```yaml
# docker-compose.yml
services:
  web:
    image: myapp:latest
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
      - /var/run:rw,noexec,nosuid,size=16m
    volumes:
      # For persistent writable paths, use named volumes instead of tmpfs
      - uploads:/app/uploads
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true

  # If your app writes logs to files, redirect to stdout instead
  # Or mount a specific log volume
  worker:
    image: myworker:latest
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - worker-logs:/app/logs

volumes:
  uploads:
  worker-logs:
```

### Option 3: Kubernetes readOnlyRootFilesystem

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: myapp
          image: myapp:latest
          securityContext:
            readOnlyRootFilesystem: true     # Key setting
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL
          volumeMounts:
            # Mount writable paths explicitly
            - name: tmp
              mountPath: /tmp
            - name: var-run
              mountPath: /var/run
            - name: app-cache
              mountPath: /app/cache

      volumes:
        - name: tmp
          emptyDir:
            medium: Memory     # RAM-backed like tmpfs
            sizeLimit: 64Mi
        - name: var-run
          emptyDir:
            medium: Memory
            sizeLimit: 16Mi
        - name: app-cache
          emptyDir:
            sizeLimit: 256Mi
```

### Option 4: tmpfs for writable paths

Not all writable paths should be treated the same. Use different strategies:

```bash
# In-memory tmpfs — data gone on restart (good for temp files)
--tmpfs /tmp:rw,noexec,nosuid,size=64m

# Named volume — data persisted across restarts (good for uploads, databases)
docker run --read-only \
  -v myapp-uploads:/app/uploads \
  -v myapp-cache:/app/cache \
  --tmpfs /tmp \
  myapp
```

**Decision guide for writable paths:**

| Path type | Strategy | Reasoning |
|---|---|---|
| `/tmp`, `/var/tmp` | `tmpfs` | Ephemeral, no persistence needed |
| `/var/run`, `/run` | `tmpfs` | PID files, sockets — ephemeral |
| App logs | Named volume or stdout | Persist or stream |
| File uploads | Named volume | Persist across restarts |
| App cache | `emptyDir` or named volume | Depends on cache lifetime |
| DB data | Named volume | Must persist |

### Option 5: Combine with seccomp and AppArmor

Read-only filesystem + seccomp + AppArmor creates a strong defence-in-depth stack.

```bash
# Use Docker's default seccomp profile (already applied by default)
docker run --read-only --security-opt seccomp=default myapp

# Use a custom seccomp profile to restrict syscalls
docker run --read-only \
  --security-opt seccomp=/path/to/seccomp-profile.json \
  myapp
```

```json
// Minimal seccomp profile — allow only needed syscalls
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": ["read", "write", "open", "close", "stat", "fstat",
                "mmap", "mprotect", "exit_group", "brk", "arch_prctl",
                "execve", "access", "openat", "getpid", "sendto"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# Enable AppArmor profile
docker run --read-only \
  --security-opt apparmor=docker-default \
  myapp
```

---

## Common App Write Paths Reference

Before enabling `--read-only`, identify where your app writes:

```bash
# Find what files a container creates/modifies at runtime
docker run --name test-run myapp &
sleep 30
# Check what was written
docker diff test-run
docker stop test-run
docker rm test-run
```

**Common framework write paths:**

| Framework | Typical write paths |
|---|---|
| Node.js | `/tmp`, `/app/.npm`, log files |
| Python | `/tmp`, `__pycache__`, `.pyc` files |
| Java | `/tmp`, `/var/tmp`, log files |
| Nginx | `/var/run/nginx.pid`, `/var/cache/nginx`, `/var/log/nginx` |
| PHP-FPM | `/var/run/php-fpm.pid`, `/tmp` |
| Rails | `/tmp`, `/app/tmp`, `/app/log` |

---

## Verification

```bash
# 1. Confirm read-only flag is set
docker inspect myapp --format '{{.HostConfig.ReadonlyRootfs}}'
# Expected: true

# 2. Attempt to write to system path — should fail
docker exec myapp touch /usr/bin/evil
# Expected: touch: /usr/bin/evil: Read-only file system

# 3. tmpfs paths should still be writable
docker exec myapp touch /tmp/ok
# Expected: success

# 4. tmpfs cannot execute binaries
docker exec myapp sh -c "echo 'test' > /tmp/test.sh && chmod +x /tmp/test.sh && /tmp/test.sh"
# Expected: Permission denied (noexec)

# 5. Kubernetes verification
kubectl exec myapp-pod -- touch /usr/local/bin/evil
# Expected: Read-only file system
```

---

## Hardening Checklist

- [ ] `--read-only` or `read_only: true` set on all production containers
- [ ] `/tmp` mounted as `tmpfs` with `noexec,nosuid` options
- [ ] All required writable paths identified with `docker diff`
- [ ] Application logs redirected to stdout/stderr (not files)
- [ ] `readOnlyRootFilesystem: true` set in all Kubernetes security contexts
- [ ] `emptyDir` or named volumes used for necessary write paths in Kubernetes
- [ ] seccomp profile applied (Docker default or custom)
- [ ] AppArmor or SELinux profile applied where available
- [ ] `tmpfs` size limits set to prevent RAM exhaustion
- [ ] Combined with non-root user and dropped capabilities

---

## Real-World CVEs & Incidents

| CVE / Incident | Year | Summary |
|---|---|---|
| CVE-2019-5736 (runc) | 2019 | Attacker used writable container filesystem to overwrite runc binary via `/proc/self/exe` |
| Log4Shell exploitation | 2021 | Writable filesystems allowed attackers to drop malicious `.class` files and achieve persistence |
| CVE-2021-21284 | 2021 | Docker volume mount race condition — writable fs enabled exploitation path |
| Kubernetes cryptominer (various) | 2020–2023 | Writable container fs used to install and persist cryptominer binaries after initial RCE |

---

## References

- [Docker --read-only documentation](https://docs.docker.com/engine/reference/commandline/run/#read-only)
- [Kubernetes readOnlyRootFilesystem](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Docker seccomp security profiles](https://docs.docker.com/engine/security/seccomp/)
- [AppArmor with Docker](https://docs.docker.com/engine/security/apparmor/)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [MITRE T1565 — Data Manipulation](https://attack.mitre.org/techniques/T1565/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

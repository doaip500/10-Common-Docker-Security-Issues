# 🐳 Docker Security Problem #4 — Privileged Container Mode

> **Severity:** 🔴 Critical  
> **Category:** Runtime / Configuration  
> **MITRE ATT&CK:** [T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)  
> **CWE:** [CWE-269 – Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Remove --privileged and use --cap-add](#option-1-remove---privileged-and-use---cap-add)
  - [Option 2: Docker Compose](#option-2-docker-compose)
  - [Option 3: Kubernetes Security Context](#option-3-kubernetes-security-context)
  - [Option 4: Enforce via Policy (OPA/Gatekeeper)](#option-4-enforce-via-policy-opagatekeeper)
- [Linux Capabilities Reference](#linux-capabilities-reference)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

The `--privileged` flag disables virtually all of Docker's security isolation mechanisms in a single switch. A privileged container:

- Has access to **all Linux capabilities**
- Can see and interact with **all host devices** (`/dev`)
- Can modify **kernel parameters** via `sysctl`
- Can load and unload **kernel modules**
- Can **mount host filesystems** including the root filesystem
- Bypasses **AppArmor and seccomp** profiles

Running `--privileged` is essentially running a process directly on the host — with container labeling but without container security.

---

## Why It Happens

Teams reach for `--privileged` when something doesn't work in a standard container — network issues, device access, kernel feature requirements. It's a quick fix that bypasses all security checks immediately, so it stays in production long after the original need is gone.

Common reasons it gets added (and almost always kept):

- Nested Docker/Kubernetes (CI agents)
- VPN or network tools needing `NET_ADMIN`
- GPU access
- Low-level system monitoring
- "It works now" — nobody removes it

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Any RCE in privileged container | Instant, trivial host escape |
| Access to `/dev` | Read/write raw disk, intercept input devices |
| `sysctl` write access | Modify kernel network stack, disable security features |
| `CAP_SYS_MODULE` available | Load rootkit kernel module |
| Mount host filesystem | Read /etc/shadow, SSH keys, secrets |
| Escape via cgroup release_agent | Classic container breakout technique |

**Classic privileged container escape:**

```bash
# Inside a privileged container — full host escape in seconds
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output   # runs on the HOST as root
```

---

## How to Detect It

### Find all privileged running containers

```bash
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' \
  | grep "Privileged=true"
```

### Check a specific container

```bash
docker inspect <container_name> | grep -i privileged
```

### Check capabilities granted

```bash
docker inspect <container_name> | grep -A10 CapAdd
```

### Scan compose files

```bash
grep -r "privileged: true" . --include="*.yml" --include="*.yaml"
grep -r "\-\-privileged" . --include="*.sh" --include="Makefile"
```

### Trivy misconfiguration scan

```bash
trivy config --severity HIGH,CRITICAL .
# Reports: "Container is running with privileged access"
```

### Kubernetes — find privileged pods

```bash
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
```

---

## The Fix

### Option 1: Remove --privileged and use --cap-add

Grant only the specific Linux capability your app actually needs.

```bash
# ❌ Before — full privilege
docker run --privileged myapp

# ✅ After — only grant what's needed
# For network tools:
docker run --cap-add NET_ADMIN --cap-add NET_RAW myapp

# For system time adjustment:
docker run --cap-add SYS_TIME myapp

# For binding privileged ports:
docker run --cap-add NET_BIND_SERVICE myapp

# Hardened baseline — drop all, add only what's needed:
docker run \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  myapp
```

### Option 2: Docker Compose

```yaml
# ❌ Before
services:
  myapp:
    privileged: true

# ✅ After — cap-drop all, add only required
services:
  myapp:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # only add what the app actually needs
    security_opt:
      - no-new-privileges:true
```

### Option 3: Kubernetes Security Context

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
            privileged: false                   # explicit denial
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE              # only what's needed
            seccompProfile:
              type: RuntimeDefault              # apply default seccomp filter
```

### Option 4: Enforce via Policy (OPA/Gatekeeper)

Block privileged containers cluster-wide so no one can accidentally deploy them.

```yaml
# Gatekeeper ConstraintTemplate — deny privileged containers
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivilegedcontainer
        violation[{"msg": msg}] {
          c := input_containers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged container is not allowed: %v", [c.name])
        }
        input_containers[c] {
          c := input.review.object.spec.containers[_]
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: psp-privileged-container
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

---

## Linux Capabilities Reference

Use this to replace `--privileged` with the minimal capability needed:

| Use Case | Capability | Notes |
|---|---|---|
| Bind to ports < 1024 | `NET_BIND_SERVICE` | Most web servers |
| Raw socket / packet capture | `NET_RAW` | tcpdump, ping |
| Network interface config | `NET_ADMIN` | VPN, iptables |
| Change system time | `SYS_TIME` | NTP daemons |
| Load kernel modules | `SYS_MODULE` | ⚠️ Still very dangerous — avoid |
| Access raw block devices | `SYS_RAWIO` | ⚠️ Very dangerous — avoid |
| Change file ownership | `CHOWN` | Often avoidable |
| Kill any process | `KILL` | Supervisors |
| Set process priorities | `SYS_NICE` | Real-time workloads |
| Audit logging | `AUDIT_WRITE` | Security daemons |

> **Rule of thumb:** If you're adding `SYS_ADMIN`, rethink the architecture. It grants a huge surface and is often used as a shortcut for things that have safer alternatives.

---

## Verification

```bash
# 1. Confirm no privileged containers running
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' \
  | grep "true"
# Should return nothing

# 2. Check capabilities on a container
docker inspect myapp --format '{{.HostConfig.CapAdd}}'
# Should show only the specific caps you added, not a massive list

# 3. Try a privileged operation inside the container — it should fail
docker exec myapp mount -t proc proc /proc/test
# Expected: mount: permission denied

# 4. Kubernetes — verify no privileged pods
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.securityContext.privileged}{"\n"}{end}{end}' | grep true
# Should return nothing
```

---

## Hardening Checklist

- [ ] `--privileged` removed from all `docker run` commands
- [ ] `privileged: true` removed from all docker-compose files
- [ ] `cap_drop: ALL` set as default, with only required caps in `cap_add`
- [ ] `--security-opt no-new-privileges` applied
- [ ] `privileged: false` explicit in all Kubernetes security contexts
- [ ] `allowPrivilegeEscalation: false` in all Kubernetes containers
- [ ] `capabilities.drop: [ALL]` in all Kubernetes security contexts
- [ ] OPA/Gatekeeper or Kyverno policy blocking privileged pods
- [ ] CI pipeline lints compose/manifests for `privileged: true`
- [ ] `SYS_ADMIN` and `SYS_MODULE` on blocklist — require security review to use

---

## Real-World CVEs & Incidents

| Incident / CVE | Year | Summary |
|---|---|---|
| CVE-2022-0492 | 2022 | Linux cgroup v1 escape — trivially exploitable from privileged containers |
| CVE-2019-5736 | 2019 | runc overwrite via `/proc/self/exe` — privileged containers made this a one-step host escape |
| CVE-2020-14386 | 2020 | Linux kernel net/af_packet exploit — required privileged container to exploit |
| Azurescape | 2021 | Cross-tenant container escape on Azure — involved privileged containers in ACI |
| CVE-2021-30465 | 2021 | runc symlink-exchange race — privileged mode bypassed all mitigations |

---

## References

- [Docker security — Linux capabilities](https://docs.docker.com/engine/security/#linux-kernel-capabilities)
- [Linux capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Kubernetes Pod Security Standards — Restricted](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [OPA Gatekeeper library](https://github.com/open-policy-agent/gatekeeper-library)
- [Kyverno policies for privileged containers](https://kyverno.io/policies/pod-security/)
- [MITRE T1611 — Escape to Host](https://attack.mitre.org/techniques/T1611/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

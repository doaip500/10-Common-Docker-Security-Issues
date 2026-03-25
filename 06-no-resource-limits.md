# 🐳 Docker Security Problem #6 — No Resource Limits (CPU/Memory)

> **Severity:** 🟠 High  
> **Category:** Runtime / Configuration  
> **MITRE ATT&CK:** [T1499 – Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)  
> **CWE:** [CWE-400 – Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: docker run flags](#option-1-docker-run-flags)
  - [Option 2: Docker Compose](#option-2-docker-compose)
  - [Option 3: Kubernetes Resource Requests and Limits](#option-3-kubernetes-resource-requests-and-limits)
  - [Option 4: Enforce Defaults with LimitRange](#option-4-enforce-defaults-with-limitrange)
  - [Option 5: Monitor with Prometheus and cAdvisor](#option-5-monitor-with-prometheus-and-cadvisor)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World Incidents](#real-world-incidents)
- [References](#references)

---

## Overview

Without resource limits, every container on a host competes for the same pool of CPU and memory. A single container — whether compromised, buggy, or deliberately malicious — can consume all available resources and starve every other workload on the host.

This is both a **security concern** (denial-of-service, container breakout enabler) and an **operational concern** (cascading failures, SLA breaches, unpredictable latency).

Docker does not set resource limits by default. Every container gets unlimited access to host resources unless you explicitly constrain it.

---

## Why It Happens

Resource limits require upfront capacity planning, which teams skip during development. The configuration moves to production unchanged. Common reasons:

- "We'll add limits after launch" — never happens
- Dev environments rarely hit resource pressure, so the issue isn't noticed
- Limits feel risky — teams fear OOMKills more than they fear noisy neighbours
- Kubernetes resource requests require knowing your app's actual footprint

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Memory leak in app | Container grows until host OOM kills random processes |
| Fork bomb or runaway process | All CPUs saturated, host unresponsive |
| Cryptominer deployed post-compromise | 100% CPU consumed, other services degraded |
| DDoS traffic spike | Single container absorbs all host resources |
| Runaway log writing | Disk I/O starvation kills other containers |
| Multiple tenants on shared host | One tenant's workload degrades all others |

---

## How to Detect It

### Find containers with no resource limits

```bash
# Check memory limit — 0 means unlimited
docker inspect $(docker ps -q) \
  --format '{{.Name}}: Memory={{.HostConfig.Memory}} CPU={{.HostConfig.NanoCpus}}'

# Find all containers with no memory limit
docker ps -q | xargs -I {} docker inspect {} \
  --format '{{.Name}}: Memory={{.HostConfig.Memory}}' \
  | grep "Memory=0"
```

### Check current resource usage

```bash
# Live stats for all running containers
docker stats

# Single snapshot (no stream)
docker stats --no-stream

# Check a specific container
docker stats --no-stream <container_name>
```

### Kubernetes — find pods without resource limits

```bash
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].resources.limits == null) | .metadata.name'

# Or use kubectl-resource-capacity plugin
kubectl resource-capacity --pods --util
```

### Trivy misconfiguration scan

```bash
trivy config --severity MEDIUM,HIGH,CRITICAL .
# Reports: "CPU and memory limits should be set"
```

---

## The Fix

### Option 1: docker run flags

```bash
# Memory limit — container gets OOMKilled instead of taking down the host
docker run \
  --memory="512m" \           # Hard memory limit
  --memory-swap="512m" \      # Disable swap (same value = no swap)
  --memory-reservation="256m" \ # Soft limit / request
  --cpus="0.5" \              # Max 0.5 CPU cores
  --cpu-shares=512 \          # Relative CPU weight (default 1024)
  --pids-limit=100 \          # Limit number of processes (prevents fork bombs)
  myapp:latest
```

**Flag reference:**

| Flag | Effect |
|---|---|
| `--memory` | Hard memory ceiling — OOMKill at this value |
| `--memory-swap` | Set equal to `--memory` to disable swap |
| `--memory-reservation` | Soft limit — used for scheduling |
| `--cpus` | Max CPU cores (fractional allowed) |
| `--cpu-shares` | Relative weight when CPU is contested |
| `--pids-limit` | Max processes — blocks fork bombs |
| `--blkio-weight` | Relative disk I/O weight (default 500) |
| `--ulimit nofile` | Max open file descriptors |

### Option 2: Docker Compose

```yaml
# docker-compose.yml
services:
  web:
    image: myapp:latest
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 256M
    ulimits:
      nproc: 65535
      nofile:
        soft: 1024
        hard: 2048

  worker:
    image: myworker:latest
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 1G
        reservations:
          cpus: "0.5"
          memory: 512M
```

> **Note:** `deploy.resources` works in both Swarm and non-Swarm Compose (v3.x with `docker compose up`).

### Option 3: Kubernetes Resource Requests and Limits

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
          resources:
            requests:              # Scheduling floor — guaranteed allocation
              memory: "256Mi"
              cpu: "250m"          # 250 millicores = 0.25 CPU
            limits:                # Hard ceiling — OOMKill or throttle at this
              memory: "512Mi"
              cpu: "500m"
```

**CPU and memory sizing guide:**

| Unit | Value |
|---|---|
| `1000m` | 1 full CPU core |
| `500m` | 0.5 CPU core |
| `256Mi` | 256 mebibytes RAM |
| `1Gi` | 1 gibibyte RAM |

> Start with Requests ≈ 50% of observed peak usage. Set Limits ≈ 2× Requests. Tune from real metrics.

### Option 4: Enforce Defaults with LimitRange

Apply automatic defaults to all pods in a namespace — so new deployments without explicit limits still get constrained.

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
    - type: Container
      default:                    # Applied if no limits set
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:             # Applied if no requests set
        cpu: "250m"
        memory: "256Mi"
      max:                        # Hard max — requests above this are rejected
        cpu: "4"
        memory: "4Gi"
      min:
        cpu: "50m"
        memory: "64Mi"
```

```yaml
# Also enforce namespace-level quotas
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: production
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
    pods: "50"
```

### Option 5: Monitor with Prometheus and cAdvisor

```yaml
# docker-compose.yml — monitoring stack
services:
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    ports:
      - "8080:8080"

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

**Key Prometheus alerts:**

```yaml
# prometheus-alerts.yml
groups:
  - name: container_resources
    rules:
      - alert: ContainerHighMemory
        expr: (container_memory_usage_bytes / container_spec_memory_limit_bytes) > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Container using >85% of memory limit"

      - alert: ContainerCPUThrottling
        expr: rate(container_cpu_cfs_throttled_seconds_total[5m]) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Container CPU is being throttled >50%"

      - alert: ContainerNoMemoryLimit
        expr: container_spec_memory_limit_bytes == 0
        labels:
          severity: high
        annotations:
          summary: "Container has no memory limit set"
```

---

## Verification

```bash
# 1. Confirm limits are set on a container
docker inspect myapp --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}'
# Should NOT show 0 0

# 2. Confirm stats show bounded usage
docker stats --no-stream myapp
# MEM USAGE / LIMIT should show a limit, not "unlimited" / "0B"

# 3. Test OOMKill works (memory limit enforcement)
docker run --memory="10m" --rm alpine sh -c 'cat /dev/zero | head -c 100m'
# Should be OOMKilled

# 4. Kubernetes — verify limits applied
kubectl describe pod <pod-name> | grep -A6 "Limits:"

# 5. Check no container shows unlimited in Kubernetes
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.name}{"\t"}{.resources.limits}{"\n"}{end}' | grep "null"
# Should return nothing
```

---

## Hardening Checklist

- [ ] `--memory` and `--cpus` set on all `docker run` commands
- [ ] `--pids-limit` set to prevent fork bombs
- [ ] `deploy.resources.limits` set in all docker-compose services
- [ ] Kubernetes `resources.requests` and `resources.limits` set on all containers
- [ ] `LimitRange` applied to all production namespaces as default backstop
- [ ] `ResourceQuota` applied to limit total namespace consumption
- [ ] cAdvisor + Prometheus monitoring container resource usage
- [ ] Alerts firing for containers exceeding 85% memory or CPU throttling
- [ ] Regular `docker stats` review or dashboard in Grafana
- [ ] Load testing done to establish realistic request/limit baselines

---

## Real-World Incidents

| Incident | Year | Summary |
|---|---|---|
| Monzo production incident | 2019 | Linkerd proxy containers without memory limits caused cascading OOMKills across the cluster |
| Tesla cryptojacking | 2018 | Attacker containers ran unconstrained cryptominer — no CPU limits meant 100% resource drain |
| GitHub Actions runner saturation | 2021 | Runaway build jobs without limits exhausted shared runner pools, blocking other teams |
| Shopify Kubernetes noisy neighbour | 2020 | Single tenant pod without limits caused P99 latency spikes for other pods on the same node |

---

## References

- [Docker resource constraints docs](https://docs.docker.com/config/containers/resource_constraints/)
- [Kubernetes resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes LimitRange](https://kubernetes.io/docs/concepts/policy/limit-range/)
- [cAdvisor — container metrics](https://github.com/google/cadvisor)
- [Goldilocks — right-sizing Kubernetes resources](https://github.com/FairwindsOps/goldilocks)
- [MITRE T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

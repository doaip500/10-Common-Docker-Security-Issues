# 🐳 Docker Security Problem #8 — Unrestricted Container-to-Container Networking

> **Severity:** 🟠 High  
> **Category:** Network  
> **MITRE ATT&CK:** [T1021 – Remote Services](https://attack.mitre.org/techniques/T1021/) / [T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)  
> **CWE:** [CWE-923 – Improper Restriction of Communication Channel](https://cwe.mitre.org/data/definitions/923.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Use separate user-defined bridge networks](#option-1-use-separate-user-defined-bridge-networks)
  - [Option 2: Disable ICC on the default bridge](#option-2-disable-icc-on-the-default-bridge)
  - [Option 3: Docker Compose network segmentation](#option-3-docker-compose-network-segmentation)
  - [Option 4: Kubernetes Network Policies](#option-4-kubernetes-network-policies)
  - [Option 5: Service mesh mTLS (Istio/Linkerd)](#option-5-service-mesh-mtls-istiolinkerd)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World Incidents](#real-world-incidents)
- [References](#references)

---

## Overview

By default, all containers on the same Docker network can communicate freely with each other on any port. There is no firewall between a compromised frontend container and your internal database, Redis cache, or admin service.

This means a single compromised container becomes a pivot point for lateral movement across your entire application stack — all without ever touching the host.

---

## Why It Happens

Docker's default networking model prioritises ease of use over least-privilege. All containers on the default bridge network (`docker0`) can reach each other. User-defined networks are better but still unrestricted by default. Network segmentation requires deliberate design, and most teams don't think about it until something goes wrong.

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Frontend container compromised | Attacker directly connects to internal DB on port 5432 |
| XSS leading to SSRF | Attacker pivots to internal services via compromised container |
| Compromised sidecar | Scans and attacks other containers on same network |
| Shared network across services | Dev/staging service talks to prod DB on same network |
| Container scanning internal network | nmap finds all running services and ports |

**Instant lateral movement from a compromised container:**

```bash
# From inside a compromised container — all these may be reachable by default
curl http://database:5432        # Postgres
curl http://redis:6379           # Redis
curl http://rabbitmq:15672       # RabbitMQ management UI
curl http://admin-service:8080   # Internal admin API
nmap -sn 172.17.0.0/16           # Scan entire Docker subnet
```

---

## How to Detect It

### Inspect container network membership

```bash
# See what networks a container is on
docker inspect <container> --format '{{json .NetworkSettings.Networks}}' | jq keys

# List all Docker networks and their containers
docker network ls
docker network inspect bridge | jq '.[0].Containers'
```

### Check if ICC is enabled (default bridge)

```bash
# Check Docker daemon config
cat /etc/docker/daemon.json | grep icc
# If absent or true, ICC is enabled

# Check directly on the bridge interface
docker network inspect bridge | jq '.[0].Options'
# Look for: "com.docker.network.bridge.enable_icc": "true"
```

### Test inter-container connectivity

```bash
# From container A, can you reach container B?
docker exec containerA ping -c1 containerB
docker exec containerA curl -s --max-time 2 http://containerB:5432
# If this succeeds, network is unrestricted
```

### Kubernetes — check for missing NetworkPolicy

```bash
# Namespaces with no NetworkPolicy are fully open
kubectl get networkpolicy --all-namespaces
# Namespaces not listed have NO policies = unrestricted

# Check a specific namespace
kubectl get networkpolicy -n production
```

---

## The Fix

### Option 1: Use separate user-defined bridge networks

Containers on different user-defined networks cannot communicate by default. Only attach containers to networks they need to talk on.

```bash
# Create isolated networks
docker network create frontend-net
docker network create backend-net
docker network create db-net

# Frontend: only on frontend-net
docker run --network frontend-net --name web nginx

# API: on both frontend-net and backend-net (bridges the two)
docker run --network frontend-net --name api myapi
docker network connect backend-net api

# Database: only on db-net (isolated from frontend)
docker run --network db-net --name db postgres

# Worker: only on backend-net
docker run --network backend-net --name worker myworker
```

Now `web` cannot reach `db` — it has no route to `db-net`.

### Option 2: Disable ICC on the default bridge

```json
// /etc/docker/daemon.json
{
  "icc": false,
  "iptables": true
}
```

```bash
# Apply and restart Docker
sudo systemctl restart docker

# Verify ICC is disabled
docker network inspect bridge | jq '.[0].Options["com.docker.network.bridge.enable_icc"]'
# Should return "false"
```

> **Note:** With `icc=false`, containers can only communicate through explicitly published ports (`-p`). This is a blunt instrument — user-defined networks with deliberate connectivity is the more flexible approach.

### Option 3: Docker Compose network segmentation

```yaml
# docker-compose.yml — three-tier network isolation
services:

  # Frontend — only on public-facing network
  nginx:
    image: nginx:alpine
    networks:
      - frontend
    ports:
      - "443:443"

  # API — bridges frontend and backend
  api:
    image: myapi:latest
    networks:
      - frontend   # can receive from nginx
      - backend    # can reach db and cache

  # Database — only on backend network, unreachable from nginx
  postgres:
    image: postgres:16-alpine
    networks:
      - backend    # only api can reach this
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password

  # Cache — only on backend network
  redis:
    image: redis:7-alpine
    networks:
      - backend

  # Admin tool — separate isolated network
  pgadmin:
    image: dpage/pgadmin4
    networks:
      - admin      # completely isolated from frontend/backend
    ports:
      - "127.0.0.1:5050:80"   # bind to localhost only

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true   # no external internet access from backend
  admin:
    driver: bridge
    internal: true
```

The `internal: true` flag means containers on that network have no outbound internet access — only intra-network traffic.

### Option 4: Kubernetes Network Policies

By default, Kubernetes allows all pod-to-pod traffic. Network Policies work like firewall rules at the pod level.

**Default deny all — then explicitly allow:**

```yaml
# Step 1: Default deny all ingress and egress in the namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}     # applies to all pods in namespace
  policyTypes:
    - Ingress
    - Egress
```

```yaml
# Step 2: Allow frontend to reach API only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
```

```yaml
# Step 3: Allow API to reach database only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - protocol: TCP
          port: 5432
```

```yaml
# Step 4: Allow DNS resolution (required for all pods)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

> **Important:** NetworkPolicy requires a CNI plugin that supports it — Calico, Cilium, Weave, or Antrea. Flannel alone does NOT enforce NetworkPolicy.

### Option 5: Service mesh mTLS (Istio/Linkerd)

For microservices, a service mesh enforces mutual TLS between all services — even if a container is compromised and attempts to impersonate another service, it can't without the valid mTLS certificate.

```yaml
# Istio — enforce strict mTLS across the namespace
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT    # All traffic must use mTLS — plaintext rejected
```

```yaml
# Istio AuthorizationPolicy — only allow api → database
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  selector:
    matchLabels:
      app: postgres
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/api-service-account"
      to:
        - operation:
            ports: ["5432"]
```

---

## Verification

```bash
# 1. Verify network segmentation — container on frontend cannot reach db
docker exec web curl -s --max-time 2 http://postgres:5432
# Should timeout or refuse

# 2. Container on backend CAN reach db
docker exec api curl -s --max-time 2 http://postgres:5432
# Should respond (even with an error, not a timeout)

# 3. Check networks are separate
docker network inspect frontend | jq '.[0].Containers | keys'
docker network inspect backend | jq '.[0].Containers | keys'
# web should ONLY appear in frontend, db should ONLY appear in backend

# 4. Kubernetes — test that default-deny works
kubectl exec -it frontend-pod -- curl -s --max-time 2 http://postgres:5432
# Should timeout (blocked by NetworkPolicy)

# 5. Kubernetes — check CNI enforces policies
kubectl get networkpolicy -A
kubectl describe networkpolicy default-deny-all -n production
```

---

## Hardening Checklist

- [ ] Containers placed on separate user-defined networks by tier (frontend/backend/db)
- [ ] No containers on the default `bridge` network in production
- [ ] `internal: true` set on backend and database networks in Compose
- [ ] `icc=false` set in daemon.json as an additional backstop
- [ ] Kubernetes default-deny NetworkPolicy applied to all production namespaces
- [ ] Explicit allow policies created for each required service-to-service path
- [ ] CNI plugin verified to support NetworkPolicy (Calico, Cilium, etc.)
- [ ] DNS egress policy allowing port 53
- [ ] Service mesh mTLS enforced in STRICT mode (if using Istio/Linkerd)
- [ ] Regular network connectivity tests in CI to verify isolation holds

---

## Real-World Incidents

| Incident | Year | Summary |
|---|---|---|
| Capital One breach | 2019 | SSRF from EC2 metadata; flat network allowed attacker to pivot to S3 buckets from a single compromised service |
| SolarWinds | 2020 | Flat internal network enabled lateral movement from compromised build server across entire environment |
| Shopify internal pivot | 2020 | Rogue contractors used flat container network to access services beyond their authorised scope |
| Tesla Kubernetes breach | 2018 | Unsecured Kubernetes dashboard — flat pod network gave immediate access to workloads and secrets |

---

## References

- [Docker networking overview](https://docs.docker.com/network/)
- [Docker network security — ICC flag](https://docs.docker.com/network/bridge/#enable-forwarding-from-docker-containers-to-the-outside-world)
- [Kubernetes Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Calico network policy tutorial](https://docs.tigera.io/calico/latest/network-policy/)
- [Cilium network policy](https://docs.cilium.io/en/stable/security/policy/)
- [Istio PeerAuthentication — mTLS](https://istio.io/latest/docs/reference/config/security/peer_authentication/)
- [MITRE T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

# 🐳 Docker Security Problem #5 — Secrets in Environment Variables or Image Layers

> **Severity:** 🟠 High  
> **Category:** Configuration / Image  
> **MITRE ATT&CK:** [T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)  
> **CWE:** [CWE-312 – Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Docker Secrets (Swarm)](#option-1-docker-secrets-swarm)
  - [Option 2: Build-time secrets with --secret](#option-2-build-time-secrets-with---secret)
  - [Option 3: External Secret Manager](#option-3-external-secret-manager)
  - [Option 4: Kubernetes Secrets + External Secrets Operator](#option-4-kubernetes-secrets--external-secrets-operator)
  - [Option 5: .dockerignore and environment hygiene](#option-5-dockerignore-and-environment-hygiene)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

Secrets — API keys, database passwords, tokens, certificates — frequently end up embedded inside Docker images or exposed via environment variables in ways that make them readable to anyone with access to the image or container.

The two most common mistakes:

1. **In image layers** — using `ENV`, `ARG`, or `RUN` to handle secrets during build embeds them permanently in the layer history, even if a later `RUN` step deletes them.
2. **In environment variables** — passing secrets via `-e` or `env_file` exposes them to all processes in the container, via `/proc/<pid>/environ`, and through `docker inspect`.

---

## Why It Happens

It's the path of least resistance. Environment variables are the 12-factor app way to configure services, and developers reasonably assume they're "not in the code". What they miss is:

- `docker inspect` exposes all env vars to anyone with Docker access
- `/proc/1/environ` inside the container exposes them to any process
- `docker history` and `--no-trunc` reveal layer commands including secrets
- Images pushed to registries carry secrets in their layers forever
- `.env` files accidentally get `COPY`-ed into images

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Image pushed to Docker Hub | All secrets in layers are publicly readable |
| `docker inspect` by low-privilege user | All env vars exposed — DB password, API keys |
| `docker history` of image | Build-time secrets visible in RUN commands |
| .env file in COPY context | All secrets baked into image |
| Logs printing env on startup | Secrets leaked to log aggregation systems |
| Compromised container | `cat /proc/1/environ` dumps all secrets instantly |

---

## How to Detect It

### Check env vars in running containers

```bash
# Inspect all env vars — visible to any Docker user
docker inspect <container_name> | jq '.[0].Config.Env'

# Or directly from inside the container
docker exec <container_name> cat /proc/1/environ | tr '\0' '\n'
```

### Check image layer history for secrets

```bash
# Full layer history — look for passwords, tokens, keys
docker history --no-trunc <image_name> | grep -iE "password|secret|token|key|api|auth"

# Check all ENV and ARG instructions
docker inspect <image_name> | jq '.[0].Config.Env'
```

### Scan with Trivy for secret detection

```bash
trivy image --scanners secret myimage:latest
trivy fs --scanners secret .
```

### Scan with truffleHog

```bash
# Scan Docker image layers for secrets
trufflehog docker --image myimage:latest

# Scan git history
trufflehog git file://. --since-commit HEAD~20
```

### Find .env files accidentally included

```bash
# Check if .env is in the Docker build context
docker build --no-cache . 2>&1 | grep ".env"

# Better: unpack image and check
docker save myimage | tar -xO --wildcards "*/layer.tar" | tar -t | grep ".env"
```

---

## The Fix

### Option 1: Docker Secrets (Swarm)

Docker Swarm has a native secrets management system. Secrets are stored encrypted and only mounted into containers that explicitly request them — not visible in `docker inspect`.

```bash
# Create a secret
echo "supersecretpassword" | docker secret create db_password -

# List secrets
docker secret ls

# Use in a service (Swarm)
docker service create \
  --name myapp \
  --secret db_password \
  myimage:latest
```

```yaml
# docker-compose.yml (Swarm mode)
services:
  myapp:
    image: myapp:latest
    secrets:
      - db_password
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password   # point app to file, not env var

secrets:
  db_password:
    external: true
```

The secret is mounted at `/run/secrets/db_password` inside the container — not in env vars, not in `docker inspect`.

### Option 2: Build-time secrets with --secret

Never use `ARG` or `ENV` for secrets during build. Use BuildKit's `--secret` flag, which mounts secrets temporarily during build without writing them to any layer.

```bash
# ❌ Before — secret baked into layer history forever
FROM node:20-alpine
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
RUN npm install
```

```bash
# ✅ After — secret never written to any layer
# syntax=docker/dockerfile:1
FROM node:20-alpine
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) \
    npm install
```

```bash
# Build with the secret — not stored in image
DOCKER_BUILDKIT=1 docker build \
  --secret id=npmtoken,src=~/.npmtoken \
  -t myapp .
```

```bash
# Verify the secret is NOT in the image history
docker history --no-trunc myapp | grep npmtoken
# Should return nothing
```

### Option 3: External Secret Manager

For production, use a dedicated secrets manager. Your app fetches secrets at startup — nothing is stored in the image or environment.

**HashiCorp Vault:**

```bash
# App fetches DB password from Vault at runtime
vault kv put secret/myapp db_password="supersecret"
```

```python
# app.py — fetch secret at startup
import hvac
import os

client = hvac.Client(url=os.environ['VAULT_ADDR'], token=os.environ['VAULT_TOKEN'])
secret = client.secrets.kv.read_secret_version(path='myapp')
db_password = secret['data']['data']['db_password']
```

**AWS Secrets Manager:**

```python
import boto3
import json

client = boto3.client('secretsmanager', region_name='us-east-1')
secret = json.loads(client.get_secret_value(SecretId='myapp/db')['SecretString'])
db_password = secret['password']
```

**Vault Agent Sidecar (Kubernetes):**

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/agent-inject-secret-db-password: "secret/myapp"
  vault.hashicorp.com/role: "myapp"
```

### Option 4: Kubernetes Secrets + External Secrets Operator

```bash
# Create a Kubernetes secret
kubectl create secret generic db-credentials \
  --from-literal=password=supersecret
```

```yaml
# Reference in deployment — mounted as file, not env var
containers:
  - name: myapp
    volumeMounts:
      - name: db-secret
        mountPath: /run/secrets
        readOnly: true
volumes:
  - name: db-secret
    secret:
      secretName: db-credentials
```

> **Note:** Kubernetes Secrets are base64-encoded, not encrypted, by default. Use the External Secrets Operator to sync from Vault, AWS Secrets Manager, or GCP Secret Manager.

```yaml
# External Secrets Operator — sync from AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-credentials
  data:
    - secretKey: password
      remoteRef:
        key: myapp/db
        property: password
```

### Option 5: .dockerignore and environment hygiene

```bash
# .dockerignore — always exclude these
.env
.env.*
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
.aws/
.ssh/
secrets/
vault-token
```

```dockerfile
# ❌ Never do this
ENV DB_PASSWORD=supersecret
ARG API_KEY=sk-abc123
RUN curl -H "Authorization: Bearer $API_KEY" https://api.example.com

# ✅ App reads from file at runtime, not from build args or env
ENV SECRET_FILE=/run/secrets/db_password
CMD ["sh", "-c", "DB_PASSWORD=$(cat $SECRET_FILE) node server.js"]
```

---

## Verification

```bash
# 1. Confirm no secrets in env vars
docker inspect <container> | jq '.[0].Config.Env' | grep -iE "password|token|secret|key"
# Should return nothing sensitive

# 2. Confirm no secrets in image layers
docker history --no-trunc myimage | grep -iE "password|token|secret|key|api"
# Should return nothing

# 3. Trivy secret scan
trivy image --scanners secret myimage:latest
# Should show: No secrets found

# 4. Confirm .env is not in image
docker run --rm myimage ls -la | grep ".env"
# Should return nothing

# 5. Test build-time secret was not persisted
DOCKER_BUILDKIT=1 docker build --secret id=mytoken,src=./token -t test .
docker history --no-trunc test | grep mytoken
# Should return nothing
```

---

## Hardening Checklist

- [ ] No `ENV`, `ARG` or `RUN` commands contain secret values in Dockerfile
- [ ] Build-time secrets use `RUN --mount=type=secret` (BuildKit)
- [ ] `.dockerignore` excludes `.env`, `*.key`, `*.pem`, `.ssh/`, `.aws/`
- [ ] Runtime secrets passed via Docker secrets or external manager, not `-e`
- [ ] Apps read secrets from files (`/run/secrets/`) not environment variables
- [ ] Trivy secret scanning integrated into CI pipeline
- [ ] truffleHog or gitleaks scanning git history in CI
- [ ] No images containing secrets pushed to any registry
- [ ] Kubernetes secrets backed by External Secrets Operator + Vault/ASM/GSM
- [ ] Secret rotation policy defined and automated

---

## Real-World CVEs & Incidents

| Incident | Year | Summary |
|---|---|---|
| Uber AWS key exposure | 2016 | AWS keys in GitHub repo used to access S3 — 57M records breached |
| Docker Hub credential scraping | 2019 | Researchers found thousands of valid cloud credentials in public Docker Hub images |
| Toyota GitHub token leak | 2022 | Access token in public GitHub repo exposed T-Connect data of 296,000 customers |
| CircleCI breach | 2023 | Secrets stored in env vars exfiltrated — customers advised to rotate all secrets |
| Codecov supply chain | 2021 | Attacker modified Docker image — collected CI env vars (containing tokens) from thousands of orgs |

---

## References

- [Docker secrets documentation](https://docs.docker.com/engine/swarm/secrets/)
- [BuildKit secret mounts](https://docs.docker.com/build/building/secrets/)
- [Trivy secret scanning](https://aquasecurity.github.io/trivy/latest/docs/scanner/secret/)
- [truffleHog — secret detection](https://github.com/trufflesecurity/trufflehog)
- [External Secrets Operator](https://external-secrets.io/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [MITRE T1552.001 — Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

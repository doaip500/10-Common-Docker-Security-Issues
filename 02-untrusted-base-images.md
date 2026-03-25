# 🐳 Docker Security Problem #2 — Using Untrusted or Unverified Base Images

> **Severity:** 🔴 Critical  
> **Category:** Image  
> **MITRE ATT&CK:** [T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)  
> **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Use Official or Verified Images](#option-1-use-official-or-verified-images)
  - [Option 2: Enable Docker Content Trust](#option-2-enable-docker-content-trust)
  - [Option 3: Pin Images by Digest](#option-3-pin-images-by-digest)
  - [Option 4: Scan Images in CI/CD](#option-4-scan-images-in-cicd)
  - [Option 5: Use a Private Registry with Policies](#option-5-use-a-private-registry-with-policies)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

Every Docker image you pull is a potential attack surface. Pulling images from unverified sources — random Docker Hub accounts, unofficial repositories, or third-party registries — can silently introduce:

- Malware or backdoors baked into image layers
- Known CVEs in outdated packages
- Cryptominers, reverse shells, or data exfiltration tools
- Typosquatted images designed to mimic trusted ones (e.g., `ngimx` instead of `nginx`)

Even "legitimate" images on Docker Hub can be abandoned, unpatched, or unknowingly compromised by a maintainer account takeover.

---

## Why It Happens

Teams default to searching Docker Hub and pulling the first result that looks right. There's no built-in warning when an image hasn't been updated in 3 years, has 0 stars, or comes from an unknown publisher. Developers optimise for speed, not provenance.

```bash
# This is how most people pull images — no verification at all
docker pull node
docker pull python:3.9
docker pull some-random-user/myapp   # ← this is where it gets dangerous
```

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Typosquatted image pulled by mistake | Malware runs inside your infrastructure |
| Abandoned image with unpatched CVEs | Known exploits used against your app |
| Compromised maintainer account | Backdoored image pushed to a trusted-looking name |
| `:latest` tag re-pointed to malicious image | Silent supply chain attack on every new deployment |
| Image from unknown registry in CI/CD | Entire build pipeline and secrets exposed |

---

## How to Detect It

### Check image provenance

```bash
# Inspect where an image came from
docker inspect <image> --format '{{.RepoDigests}}'

# Check image history for suspicious layers
docker history <image> --no-trunc

# Look for unexpected scripts or downloads in layers
docker history <image> --no-trunc | grep -iE "curl|wget|bash -c|eval|base64"
```

### Scan for vulnerabilities with Trivy

```bash
# Scan a local or remote image
trivy image node:18
trivy image python:3.9-slim

# Output only critical/high CVEs
trivy image --severity CRITICAL,HIGH myimage:latest

# Generate a report
trivy image --format json --output report.json myimage:latest
```

### Scan with Grype

```bash
grype docker:myimage:latest
grype dir:/path/to/project
```

### Check Docker Hub image metadata

```bash
# Use the Docker Hub API to check publisher and last pushed date
curl -s https://hub.docker.com/v2/repositories/library/node/ | jq '.last_updated, .pull_count'

# For non-official images
curl -s https://hub.docker.com/v2/repositories/<user>/<image>/ | jq '.last_updated'
```

---

## The Fix

### Option 1: Use Official or Verified Images

Always prefer in this order:

1. **Official images** — maintained by Docker under `library/` (e.g., `nginx`, `node`, `python`)
2. **Verified Publisher images** — companies like Microsoft, AWS, Bitnami with the blue checkmark
3. **Docker-Sponsored Open Source** — community projects with formal oversight

```dockerfile
# ✅ Good — official image, pinned minor version, minimal variant
FROM node:20-alpine

# ✅ Good — official slim variant
FROM python:3.12-slim

# ❌ Bad — unknown publisher, no tag pin
FROM some-guy/node-app

# ❌ Bad — latest tag, no digest
FROM ubuntu:latest
```

### Option 2: Enable Docker Content Trust

Docker Content Trust (DCT) uses Notary to cryptographically verify image signatures on push and pull. When enabled, unsigned images are rejected.

```bash
# Enable for the current session
export DOCKER_CONTENT_TRUST=1

# Now pulls will fail if the image isn't signed
docker pull unsigned-image:latest
# Error: No valid trust data for unsigned-image

# Enable globally (add to ~/.bashrc or /etc/environment)
echo 'export DOCKER_CONTENT_TRUST=1' >> ~/.bashrc
```

**Sign your own images:**

```bash
# Generate delegation keys
docker trust key generate mykey

# Sign and push
docker trust sign myrepo/myimage:v1.0
docker push myrepo/myimage:v1.0
```

### Option 3: Pin Images by Digest

Tags like `:latest` or `:20` are mutable — they can be silently repointed to a new (potentially malicious) image. Digests are immutable SHA256 hashes.

```bash
# Get the digest of an image
docker pull node:20-alpine
docker inspect node:20-alpine --format '{{index .RepoDigests 0}}'
# sha256:abc123...

# Or pull by digest directly
docker pull node:20-alpine@sha256:abc123def456...
```

```dockerfile
# ✅ Pin by digest in Dockerfile for reproducible, tamper-proof builds
FROM node:20-alpine@sha256:a1b2c3d4e5f6...
```

> Use tools like [Renovate](https://github.com/renovatebot/renovate) or [Dependabot](https://github.com/dependabot) to automate digest updates when upstream releases security patches.

### Option 4: Scan Images in CI/CD

Integrate scanning into your pipeline so vulnerable images never reach production.

**GitHub Actions with Trivy:**

```yaml
# .github/workflows/scan.yml
name: Image Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1   # Fail the build on findings

      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```

**GitLab CI:**

```yaml
container_scan:
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL,HIGH $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

### Option 5: Use a Private Registry with Policies

Mirror approved images into your own registry and block direct pulls from Docker Hub.

```bash
# Example: set up a pull-through cache with Harbor or ECR

# AWS ECR — create a pull-through cache rule for Docker Hub
aws ecr create-pull-through-cache-rule \
  --ecr-repository-prefix dockerhub \
  --upstream-registry-url registry-1.docker.io

# Pull via your private mirror instead of Docker Hub directly
docker pull <your-account>.dkr.ecr.<region>.amazonaws.com/dockerhub/library/node:20-alpine
```

**Enforce with admission controller (Kubernetes):**

```yaml
# OPA/Gatekeeper policy — only allow images from approved registries
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: allowed-repos
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    repos:
      - "gcr.io/my-org/"
      - "012345678901.dkr.ecr.us-east-1.amazonaws.com/"
```

---

## Verification

```bash
# 1. Confirm image digest matches expected value
docker inspect myimage:v1.0 --format '{{index .RepoDigests 0}}'

# 2. Confirm DCT is active
export DOCKER_CONTENT_TRUST=1
docker pull alpine   # should succeed (signed)
docker pull some-unsigned-image   # should fail

# 3. Run Trivy and confirm zero criticals
trivy image --exit-code 1 --severity CRITICAL myimage:v1.0
echo $?   # 0 = clean, 1 = vulnerabilities found

# 4. Check no images are using :latest in production
docker inspect $(docker ps -q) --format '{{.Name}}: {{.Config.Image}}' | grep ':latest'
# Should return nothing
```

---

## Hardening Checklist

- [ ] Only pull from official or verified publisher images
- [ ] Images pinned by digest, not by mutable tag
- [ ] `DOCKER_CONTENT_TRUST=1` set in CI/CD environment
- [ ] Trivy or Grype scanning integrated into CI pipeline with `exit-code 1`
- [ ] No `:latest` tags used in Dockerfiles or deployment manifests
- [ ] Private registry mirror configured (Harbor, ECR, GCR, Artifactory)
- [ ] Admission controller enforcing allowed registry list
- [ ] Automated image update PRs via Renovate or Dependabot
- [ ] `docker history` reviewed for all third-party images

---

## Real-World CVEs & Incidents

| Incident / CVE | Year | Summary |
|---|---|---|
| Docker Hub malicious images (cryptominers) | 2018 | 17 images on Docker Hub contained hidden cryptomining malware — downloaded 5M+ times |
| `node-ipc` supply chain attack | 2022 | Maintainer sabotaged their own npm package; affected Docker images downstream |
| CVE-2021-41091 | 2021 | Docker Engine file permission flaw — unprivileged users could access container files |
| Codecov breach | 2021 | Attackers modified a Docker image in CI — stole secrets from thousands of orgs |
| `azuredevstorage` typosquatting | 2023 | Fake Azure-named images on Docker Hub captured cloud credentials |

---

## References

- [Docker Hub Official Images](https://hub.docker.com/search?image_filter=official)
- [Docker Content Trust docs](https://docs.docker.com/engine/security/trust/)
- [Trivy — container vulnerability scanner](https://github.com/aquasecurity/trivy)
- [Grype — vulnerability scanner for containers](https://github.com/anchore/grype)
- [SLSA Supply Chain Security Framework](https://slsa.dev/)
- [Sigstore / Cosign image signing](https://github.com/sigstore/cosign)
- [MITRE T1195.002 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

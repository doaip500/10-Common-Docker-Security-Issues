# 🐳 Docker Security Problem #7 — Outdated or Unpatched Base Images

> **Severity:** 🟠 High  
> **Category:** Image  
> **MITRE ATT&CK:** [T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)  
> **CWE:** [CWE-1104 – Use of Unmaintained Third-Party Components](https://cwe.mitre.org/data/definitions/1104.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Pin to current minor versions with minimal variants](#option-1-pin-to-current-minor-versions-with-minimal-variants)
  - [Option 2: Automate image rebuilds in CI/CD](#option-2-automate-image-rebuilds-in-cicd)
  - [Option 3: Automate dependency updates with Renovate or Dependabot](#option-3-automate-dependency-updates-with-renovate-or-dependabot)
  - [Option 4: Use distroless images](#option-4-use-distroless-images)
  - [Option 5: Scan on schedule in production](#option-5-scan-on-schedule-in-production)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

Base images age quickly. A `node:14` image that was fine at project launch may be carrying dozens of critical CVEs a year later — in OpenSSL, glibc, curl, or the runtime itself. Using `:latest` doesn't help either, because `latest` can go months without rebuilds.

The problem compounds across three layers:

1. **OS layer** — outdated Alpine, Debian, or Ubuntu packages
2. **Runtime layer** — EOL Node.js, Python, Java, or Go versions
3. **Application layer** — unpatched npm/pip/maven/gradle dependencies

Each layer is a separate attack surface that needs separate tracking and patching.

---

## Why It Happens

- Images are built once and treated as immutable artifacts
- No automated process to rebuild when upstream base image updates
- Teams pin to `:latest` thinking it's always current — it's not
- Old versions feel "stable" — developers are reluctant to upgrade
- CI scans at build time but images aren't re-scanned once deployed

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| EOL Node 12 / Python 3.6 in production | Known exploits in runtime, no upstream patches |
| Old OpenSSL in base image | TLS vulnerabilities expose encrypted traffic |
| Outdated curl/wget | Server-side request forgery, code execution |
| glibc vulnerabilities | Privilege escalation from within the container |
| Unpatched log4j in Java app image | Remote code execution (as demonstrated at scale in 2021) |
| `:latest` not recently built | Appears current but carries months of unpatched CVEs |

---

## How to Detect It

### Check image age

```bash
# When was the image last built?
docker inspect myimage:latest --format '{{.Created}}'

# Check the base image age on Docker Hub via API
curl -s "https://hub.docker.com/v2/repositories/library/node/tags/18-alpine" \
  | jq '.last_updated'
```

### Scan with Trivy

```bash
# Full vulnerability scan
trivy image node:14
trivy image python:3.8-slim

# Focus on OS-level CVEs
trivy image --vuln-type os myimage:latest

# Check what OS/packages are in the image
trivy image --list-all-pkgs myimage:latest

# Scan with SBOM output for tracking
trivy image --format cyclonedx --output sbom.json myimage:latest
```

### Scan with Grype

```bash
grype docker:myimage:latest
grype docker:node:14 --fail-on critical
```

### Check runtime EOL status

```bash
# Node.js EOL dates
node --version   # inside container
# Check against https://endoflife.date/nodejs

# Python EOL
python --version
# Check against https://endoflife.date/python
```

### Find old images in your registry (ECR example)

```bash
aws ecr describe-images \
  --repository-name myapp \
  --query 'sort_by(imageDetails, &imagePushedAt)[*].{Tag:imageTags[0],Pushed:imagePushedAt}' \
  --output table
```

---

## The Fix

### Option 1: Pin to current minor versions with minimal variants

```dockerfile
# ❌ Bad — EOL runtime
FROM node:14

# ❌ Bad — mutable tag, unknown actual version
FROM node:latest

# ❌ Bad — fat image, larger attack surface
FROM ubuntu:20.04

# ✅ Good — current LTS, pinned minor, minimal Alpine variant
FROM node:20-alpine

# ✅ Good — pinned patch version for reproducibility
FROM node:20.11-alpine3.19

# ✅ Good — slim Debian for better compatibility than Alpine
FROM python:3.12-slim-bookworm
```

**Image size and attack surface comparison:**

| Image | Size | Packages | CVEs (approx) |
|---|---|---|---|
| `ubuntu:latest` | ~77MB | 400+ | Many |
| `node:20` | ~1.1GB | 800+ | Many |
| `node:20-slim` | ~240MB | ~200 | Fewer |
| `node:20-alpine` | ~170MB | ~50 | Very few |
| `gcr.io/distroless/nodejs20` | ~120MB | ~10 | Minimal |

### Option 2: Automate image rebuilds in CI/CD

Rebuild your images on a schedule even if your code hasn't changed, so upstream OS patches are picked up.

**GitHub Actions — weekly rebuild:**

```yaml
# .github/workflows/weekly-rebuild.yml
name: Weekly Image Rebuild

on:
  schedule:
    - cron: '0 2 * * 1'   # Every Monday at 2am
  workflow_dispatch:

jobs:
  rebuild:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build with no cache (force fresh base image pull)
        run: docker build --no-cache --pull -t myapp:latest .

      - name: Scan rebuilt image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:latest
          exit-code: 1
          severity: CRITICAL

      - name: Push to registry
        run: |
          docker tag myapp:latest ghcr.io/myorg/myapp:latest
          docker push ghcr.io/myorg/myapp:latest
```

> `--pull` forces Docker to check for a newer base image even if it's cached locally. `--no-cache` ensures all layers are rebuilt fresh.

### Option 3: Automate dependency updates with Renovate or Dependabot

**Renovate — auto-update Dockerfile base images:**

```json
// renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "dockerfile": {
    "enabled": true
  },
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "automerge": true,
      "automergeType": "pr",
      "matchUpdateTypes": ["patch"]
    },
    {
      "matchDatasources": ["docker"],
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "labels": ["needs-review"]
    }
  ]
}
```

**Dependabot — GitHub native:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: docker
    directory: "/"
    schedule:
      interval: weekly
    labels:
      - "dependencies"
      - "docker"
```

### Option 4: Use distroless images

Distroless images contain only the application and its runtime — no shell, no package manager, no OS utilities. This dramatically reduces the attack surface and CVE count.

```dockerfile
# Multi-stage build — build in full image, run in distroless
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json .
RUN npm ci --only=production
COPY . .
RUN npm run build

# Final image — distroless has no shell, no package manager
FROM gcr.io/distroless/nodejs20-debian12
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER nonroot
CMD ["dist/server.js"]
```

```dockerfile
# Go — fully static binary in scratch (zero OS layer)
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server .

FROM scratch
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
```

### Option 5: Scan on schedule in production

Images in production get stale even if they were clean at deploy time. Schedule regular scans against your registry.

```yaml
# GitHub Actions — nightly scan of production image in registry
name: Nightly Registry Scan

on:
  schedule:
    - cron: '0 3 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan production image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/myorg/myapp:production
          format: sarif
          output: scan-results.sarif
          severity: CRITICAL,HIGH

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-results.sarif

      - name: Alert on critical CVEs
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: '{"text":"🚨 Critical CVEs found in production image — review needed"}'
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Verification

```bash
# 1. Check base image is current
docker run --rm myimage cat /etc/os-release
docker run --rm myimage node --version   # or python, java, etc.

# 2. Run Trivy — zero criticals expected
trivy image --exit-code 1 --severity CRITICAL myimage:latest
echo "Exit code: $?"   # 0 = clean

# 3. Confirm image was built recently (within 7 days ideally)
docker inspect myimage:latest --format '{{.Created}}'

# 4. Confirm --no-cache and --pull were used in latest build
# Check CI logs for: "docker build --no-cache --pull"

# 5. Verify Renovate/Dependabot PRs are being opened and merged
# Check repo for open PRs with label "dependencies" and "docker"
```

---

## Hardening Checklist

- [ ] No EOL runtimes — Node <18, Python <3.9, Java <11, etc.
- [ ] No `:latest` tags in Dockerfiles — use pinned minor versions
- [ ] Alpine or slim variants used to minimise package count
- [ ] Multi-stage builds used — build tools excluded from final image
- [ ] `--no-cache --pull` used in CI builds
- [ ] Weekly scheduled rebuild pipeline configured
- [ ] Renovate or Dependabot auto-PRs Dockerfile base image updates
- [ ] Trivy scanning in CI with `exit-code 1` on CRITICAL
- [ ] Nightly scan of production registry images
- [ ] Alerts configured for new critical CVEs in production images
- [ ] Distroless or scratch images used for statically-compiled apps

---

## Real-World CVEs & Incidents

| CVE / Incident | Year | Summary |
|---|---|---|
| Log4Shell (CVE-2021-44228) | 2021 | Unpatched log4j in Java container images — mass RCE across thousands of organisations |
| CVE-2021-3156 (sudo heap overflow) | 2021 | Old sudo in Ubuntu/Debian base images — local privilege escalation to root |
| CVE-2022-0778 (OpenSSL infinite loop) | 2022 | DoS via crafted certificate — affected all images with outdated OpenSSL |
| CVE-2023-38408 (OpenSSH RCE) | 2023 | Remote code execution in old OpenSSH — present in many base images |
| Spring4Shell (CVE-2022-22965) | 2022 | Unpatched Spring Framework in Java images — RCE on Tomcat deployments |

---

## References

- [End of Life dates for all runtimes](https://endoflife.date/)
- [Trivy vulnerability scanner](https://github.com/aquasecurity/trivy)
- [Google Distroless images](https://github.com/GoogleContainerTools/distroless)
- [Renovate bot](https://github.com/renovatebot/renovate)
- [Docker official image update policy](https://github.com/docker-library/official-images)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

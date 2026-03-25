# 🐳 Docker Security Problem #10 — No Image Signing or Provenance Verification

> **Severity:** 🔵 Medium  
> **Category:** Image / Configuration  
> **MITRE ATT&CK:** [T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)  
> **CWE:** [CWE-345 – Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

---

## Table of Contents

- [Overview](#overview)
- [Why It Happens](#why-it-happens)
- [What Can Go Wrong](#what-can-go-wrong)
- [How to Detect It](#how-to-detect-it)
- [The Fix](#the-fix)
  - [Option 1: Sign images with Cosign (Sigstore)](#option-1-sign-images-with-cosign-sigstore)
  - [Option 2: Docker Content Trust (Notary)](#option-2-docker-content-trust-notary)
  - [Option 3: Generate and verify SBOMs](#option-3-generate-and-verify-sboms)
  - [Option 4: Enforce signatures in Kubernetes with Kyverno](#option-4-enforce-signatures-in-kubernetes-with-kyverno)
  - [Option 5: SLSA provenance attestations](#option-5-slsa-provenance-attestations)
- [Verification](#verification)
- [Hardening Checklist](#hardening-checklist)
- [Real-World CVEs & Incidents](#real-world-cves--incidents)
- [References](#references)

---

## Overview

Without image signing, there is no way to verify that the container image running in production is the same image that was built and scanned in your CI pipeline. An attacker who gains access to your registry, CDN, or deployment pipeline can silently substitute a malicious image — and nothing in your standard workflow will detect it.

Image signing creates a cryptographic link between the image you built and the image you deployed. Any tampering invalidates the signature.

---

## Why It Happens

Image signing requires tooling (Cosign, Notary), key management, and integration into both the CI pipeline (signing) and the deployment gate (verification). This is more friction than most teams add upfront. The risk feels abstract until a supply chain attack hits.

---

## What Can Go Wrong

| Scenario | Impact |
|---|---|
| Registry compromised | Attacker pushes backdoored image under same tag |
| CI/CD pipeline hijacked | Malicious image built and pushed without detection |
| Man-in-the-middle on image pull | Image swapped in transit (especially HTTP registries) |
| `:latest` tag repointed | Deployment pulls different image than expected |
| Insider threat | Rogue developer pushes unapproved image to production tag |
| Dependency confusion attack | Attacker publishes higher-versioned image to public registry |

---

## How to Detect It

### Check if your images are signed (Cosign)

```bash
# Install cosign
brew install cosign   # or: go install github.com/sigstore/cosign/cmd/cosign@latest

# Verify a signature
cosign verify \
  --certificate-identity="https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp:v1.0.0

# If unsigned:
# Error: no signatures found
```

### Check Docker Content Trust status

```bash
# Is DCT enabled?
echo $DOCKER_CONTENT_TRUST
# Empty or 0 = disabled

# Try pulling with DCT enabled
DOCKER_CONTENT_TRUST=1 docker pull myimage:latest
# If unsigned: "No valid trust data for myimage"
```

### Check if your CI pipeline signs images

```bash
# Look for cosign or docker trust commands in CI config
grep -r "cosign sign\|docker trust sign" .github/ .gitlab-ci.yml Jenkinsfile
# Empty output = no signing
```

### Check SBOM presence

```bash
# Check if an image has an attached SBOM
cosign download sbom ghcr.io/myorg/myapp:v1.0.0
# Error: no SBOM attachments found
```

---

## The Fix

### Option 1: Sign images with Cosign (Sigstore)

Cosign is the modern standard for container image signing, backed by the Linux Foundation's Sigstore project. It supports keyless signing via OIDC (no key management required).

**Keyless signing in GitHub Actions (recommended):**

```yaml
# .github/workflows/build-and-sign.yml
name: Build, Push, and Sign

on:
  push:
    branches: [main]

permissions:
  id-token: write      # Required for keyless OIDC signing
  contents: read
  packages: write

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign the image (keyless)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
        # No keys needed — OIDC token from GitHub Actions is the identity
```

**Verify the signed image:**

```bash
cosign verify \
  --certificate-identity="https://github.com/myorg/myrepo/.github/workflows/build-and-sign.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp@sha256:abc123...
```

**With explicit keys (for air-gapped or self-hosted environments):**

```bash
# Generate a signing key pair
cosign generate-key-pair
# Creates cosign.key (private) and cosign.pub (public)
# Store cosign.key in GitHub Secrets as COSIGN_PRIVATE_KEY

# Sign with key
cosign sign --key cosign.key ghcr.io/myorg/myapp:v1.0.0

# Verify with public key
cosign verify --key cosign.pub ghcr.io/myorg/myapp:v1.0.0
```

### Option 2: Docker Content Trust (Notary)

Docker Content Trust (DCT) is Docker's built-in signing system based on The Update Framework (TUF).

```bash
# Enable DCT globally
export DOCKER_CONTENT_TRUST=1

# Initialize trust for your repository (first time only)
docker trust key generate mykey
docker trust signer add --key mykey.pub mykey myrepo/myimage

# Sign and push
docker trust sign myrepo/myimage:v1.0.0

# Verify
docker trust inspect --pretty myrepo/myimage:v1.0.0
```

```bash
# Enforce DCT in CI/CD
# Set in CI environment variables:
DOCKER_CONTENT_TRUST=1
DOCKER_CONTENT_TRUST_SERVER=https://notary.docker.io
```

```json
// /etc/docker/daemon.json — enforce content trust at daemon level
{
  "content-trust": {
    "mode": "enforced"
  }
}
```

### Option 3: Generate and verify SBOMs

A Software Bill of Materials (SBOM) lists every package and dependency in your image. Attach it to the image and verify it at deploy time.

```bash
# Generate SBOM with Syft
syft ghcr.io/myorg/myapp:v1.0.0 -o cyclonedx-json > sbom.json

# Attach SBOM to image with Cosign
cosign attach sbom --sbom sbom.json ghcr.io/myorg/myapp:v1.0.0

# Sign the SBOM attachment
cosign sign --attachment sbom ghcr.io/myorg/myapp:v1.0.0

# Verify and download SBOM
cosign download sbom ghcr.io/myorg/myapp:v1.0.0

# Scan SBOM for vulnerabilities
grype sbom:./sbom.json
```

**In GitHub Actions:**

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: ghcr.io/${{ github.repository }}:${{ github.sha }}
    format: cyclonedx-json
    output-file: sbom.cyclonedx.json

- name: Attach and sign SBOM
  run: |
    cosign attach sbom --sbom sbom.cyclonedx.json \
      ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
    cosign sign --attachment sbom --yes \
      ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

### Option 4: Enforce signatures in Kubernetes with Kyverno

Block unsigned images from ever running in your cluster.

```yaml
# Install Kyverno first:
# kubectl apply -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml

# Policy: only allow images signed by your CI pipeline
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce    # Reject unsigned images
  background: false
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/*.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

**Test the policy:**

```bash
# Try to deploy unsigned image — should be rejected
kubectl run test --image=ghcr.io/myorg/myapp:unsigned
# Error: image signature verification failed

# Signed image should be allowed
kubectl run prod --image=ghcr.io/myorg/myapp:v1.0.0@sha256:abc123
# pod/prod created
```

### Option 5: SLSA provenance attestations

SLSA (Supply-chain Levels for Software Artifacts) provenance records exactly how and where an image was built — build inputs, environment, source commit, builder identity.

```yaml
# GitHub Actions with SLSA provenance generation
- name: Build and push with provenance
  uses: docker/build-push-action@v5
  with:
    context: .
    push: true
    tags: ghcr.io/myorg/myapp:v1.0.0
    provenance: true    # Generates and attaches SLSA provenance
    sbom: true          # Also generates SBOM

- name: Sign provenance with Cosign
  run: |
    cosign sign --yes \
      --attachment provenance \
      ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

```bash
# Verify provenance
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity="https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp:v1.0.0

# Download and inspect provenance
cosign download attestation ghcr.io/myorg/myapp:v1.0.0 | \
  jq -r '.payload' | base64 -d | jq '.predicate'
```

---

## Full Pipeline Example

```yaml
# Complete signed, attested, SBOM-attached pipeline
name: Secure Build Pipeline

on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write

jobs:
  build-sign-attest:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}

    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: sigstore/cosign-installer@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # Scan BEFORE pushing
      - name: Build for scanning (no push)
        uses: docker/build-push-action@v5
        with:
          context: .
          load: true
          tags: myapp:scan

      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:scan
          exit-code: 1
          severity: CRITICAL

      # Build, push, sign, attest
      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          provenance: true
          sbom: true

      - name: Sign image
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

      - name: Generate and attach SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
          output-file: sbom.cyclonedx.json

      - name: Sign SBOM
        run: |
          cosign attach sbom --sbom sbom.cyclonedx.json \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
          cosign sign --attachment sbom --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

---

## Verification

```bash
# 1. Verify image signature
cosign verify \
  --certificate-identity="https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp:v1.0.0
# Expected: Verification for ghcr.io/myorg/myapp:v1.0.0 -- The following checks were performed...

# 2. Verify SBOM is attached and signed
cosign verify --attachment sbom \
  --certificate-identity="..." \
  --certificate-oidc-issuer="..." \
  ghcr.io/myorg/myapp:v1.0.0

# 3. Download and check SBOM contents
cosign download sbom ghcr.io/myorg/myapp:v1.0.0 | jq '.components | length'

# 4. Kubernetes — confirm Kyverno policy is active
kubectl get clusterpolicy verify-image-signatures
kubectl describe clusterpolicy verify-image-signatures | grep "Validation Failure Action"
# Expected: Enforce

# 5. Test Kyverno blocks unsigned image
kubectl run reject-test --image=nginx:latest --dry-run=server
# Expected: admission webhook rejection
```

---

## Hardening Checklist

- [ ] Cosign installed and integrated into CI pipeline
- [ ] All production images signed on push (keyless or key-based)
- [ ] Images deployed by digest, not mutable tag
- [ ] SBOM generated, attached, and signed for each release
- [ ] Provenance attestations generated with SLSA level >= 2
- [ ] Kyverno or Connaisseur policy enforcing signature verification in Kubernetes
- [ ] `DOCKER_CONTENT_TRUST=1` set in all CI/CD environments
- [ ] Public key / identity published and documented for external consumers
- [ ] Signed image verification step in deployment pipeline before rollout
- [ ] Rekor transparency log used (default with keyless Cosign)

---

## Real-World CVEs & Incidents

| Incident | Year | Summary |
|---|---|---|
| SolarWinds Orion | 2020 | Unsigned build artifacts allowed compromised build system to inject malicious code undetected |
| Codecov bash uploader | 2021 | Attacker modified a script served over HTTPS — no signing meant tampered version was silently used |
| PyPI/npm dependency confusion | 2021–2023 | Unsigned packages from wrong registries pulled into Docker images — no provenance to detect substitution |
| Docker Hub malicious images | 2018–2023 | Typosquatted images used for cryptomining — signing would have blocked non-registry images |
| 3CX supply chain attack | 2023 | Signed malware (certificate compromise) — highlights need for transparency logs like Rekor alongside signing |

---

## References

- [Sigstore / Cosign](https://github.com/sigstore/cosign)
- [Sigstore keyless signing explained](https://docs.sigstore.dev/cosign/signing/overview/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [Kyverno image verification policies](https://kyverno.io/policies/other/verify-image/)
- [SLSA framework](https://slsa.dev/)
- [Syft — SBOM generator](https://github.com/anchore/syft)
- [Rekor — transparency log](https://github.com/sigstore/rekor)
- [MITRE T1195.002 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)

---

*Part of the [cloud-security-problems](../) series — practical write-ups on real-world security issues companies face in containerized environments.*

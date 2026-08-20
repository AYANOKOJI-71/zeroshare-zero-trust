# ZeroShare — Zero-Trust Secure File-Sharing Platform

> A full local OAuth2/OIDC security lab that makes every file request prove its identity, scope, policy, and time-bound authorization before the API releases decrypted content.

ZeroShare is a secure architecture rather than a consumer file drive. It pairs a React workspace with a Node.js/TypeScript API, PostgreSQL schema, S3-compatible object storage, a local OAuth2/OIDC provider, AES-256-GCM envelope encryption, one-time download grants, and HMAC-linked audit evidence.

## What this project demonstrates

| Security concern | ZeroShare implementation |
|---|---|
| Authentication | OAuth2 authorization-code flow with PKCE, signed short-lived JWTs, a JWKS endpoint, and refresh-token rotation in the local identity lab. |
| Authorization | Token scopes plus server-side owner/recipient/expiry policy checks; the browser never decides access. |
| Storage | An S3-compatible MinIO service holds ciphertext only; the API holds encrypted per-file data keys and opaque object keys. |
| Encryption | Each upload is encrypted with a fresh AES-256-GCM data key. That key is wrapped by a master key before metadata persistence. |
| Downloads | The API mints recipient-bound, one-time grants that expire after 60 seconds. Direct object-store reads are not exposed. |
| Auditability | Security events form an HMAC-linked hash chain. The dashboard verifies its integrity before displaying evidence. |

## Architecture

```text
React SPA ── PKCE ──> Local OIDC provider ── signed JWT/JWKS ──┐
     │                                                         │
     └────────── Bearer token ──> ZeroShare API ── policy ────┘
                                      │              │
                                 PostgreSQL      AES-256-GCM
                                      │              │
                                  audit chain ──> MinIO ciphertext store
```

Read the detailed threat boundaries and local-versus-production separation in [`docs/security-architecture.md`](docs/security-architecture.md).

## Run locally

Docker Compose supplies PostgreSQL, MinIO, the local OIDC provider, API, and React workspace. The bundled values are **local-demo-only** and must be replaced with runtime secrets before any nonlocal deployment.

```bash
docker compose up --build
```

Open `http://localhost:5175`, choose **Sign in with OIDC**, and select Alice (security owner) or Bob (project member). Alice can upload and create recipient policies. Bob can download only after Alice shares an object with `bob`.

For a no-container developer loop, use three terminals:

```bash
ALLOW_INSECURE_DEMO=true pnpm dev:identity
ALLOW_INSECURE_DEMO=true pnpm dev:api
pnpm dev:web
```

The local provider is intentionally a demonstration-only provider. Its user-selection screen has no password verifier and must never be exposed publicly.

## Quality checks

```bash
npx --yes pnpm@10.6.3 install
npx --yes pnpm@10.6.3 lint
npx --yes pnpm@10.6.3 test
npx --yes pnpm@10.6.3 build
```

The API tests validate missing-token rejection, encrypted upload and denied access, recipient-bound single-use downloads, and audit-chain integrity. The frontend unit test validates RFC 7636 PKCE challenge derivation.

## Production hardening checklist

This repository is intentionally designed to make the production delta explicit:

1. Replace the local demo identity provider with a hardened OIDC provider and disable `ALLOW_INSECURE_DEMO`.
2. Store master keys and audit keys in a managed KMS/HSM, never in source code, Compose files, or browser variables.
3. Use TLS, secure cookies, strict CORS origins, CSP, rate limits, malware scanning, and content-type validation at the edge.
4. Apply the PostgreSQL schema through versioned migrations; use immutable, externally retained audit storage.
5. Use private S3 buckets with block-public-access controls, lifecycle retention, versioning, and server-side encryption.
6. Run dependency scans, secrets scans, DAST, and threat-model review before deployment.

## Repository layout

```text
apps/identity  Local OAuth2/OIDC provider with PKCE and refresh rotation
apps/api       File policy API, envelope encryption, audit chain, object-store adapters
apps/web       React security workspace
infra/         PostgreSQL schema and container deployment configuration
docs/          Security architecture and validation evidence
```

## References

[RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) · [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636) · [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)

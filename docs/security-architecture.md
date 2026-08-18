# ZeroShare security architecture

ZeroShare is an educational, **local-first zero-trust file-sharing lab**. It treats every request as untrusted until a short-lived OAuth2/OIDC access token, the required scope, the object owner’s policy, and the time-bound sharing rule have all been validated. The demonstration identity provider deliberately uses local demo-user selection rather than passwords; it must not be exposed as a production identity system.

## Trust boundaries

| Zone | Responsibility | What it must not trust |
|---|---|---|
| React workspace | Performs PKCE authorization-code login and displays only API-approved metadata. | Browser state, claimed roles, or file IDs supplied by a user. |
| Local OIDC provider | Issues signed short-lived access/ID tokens and rotating refresh tokens to the registered SPA client. | Arbitrary redirect URIs, expired authorization codes, reused refresh tokens, or a missing PKCE verifier. |
| ZeroShare API | Validates issuer, audience, expiry, signature, scopes, ownership, recipient policy, and grant expiry. | Frontend permission decisions or object-store keys sent by the client. |
| Encrypted object store | Persists ciphertext only. | Plaintext, user authorization, or file-level permissions. |
| Audit chain | Captures security-relevant actions with a hash linked to the preceding event. | Mutable user-provided audit fields or a broken chain. |

## Data flow

1. The user completes an authorization-code + PKCE flow with the local provider.
2. The browser sends the access token to the API; the API validates it against the provider JWKS.
3. A permitted upload is encrypted with a unique AES-256-GCM data key. The data key is encrypted by a local master key before metadata is recorded.
4. The object-store adapter receives ciphertext and an opaque object key only.
5. A download is possible only after the API issues a one-time, recipient-bound, short-lived download grant.
6. The API appends each upload, share, download, revocation, and policy decision to the HMAC-linked audit chain.

## Local lab versus production

The local provider, local encrypted filesystem adapter, in-memory demonstration repository, and container definitions make the application runnable without a paid account. A production deployment must replace the demo provider with a managed or self-hosted hardened OIDC provider, store master keys in a KMS/HSM, enforce TLS, use PostgreSQL migrations, place objects in an S3-compatible store with server-side encryption, and ship audit records to an append-only security log.

## References

[1]: https://datatracker.ietf.org/doc/html/rfc7636 "RFC 7636: Proof Key for Code Exchange by OAuth Public Clients"
[2]: https://datatracker.ietf.org/doc/html/rfc6749 "RFC 6749: The OAuth 2.0 Authorization Framework"
[3]: https://datatracker.ietf.org/doc/html/rfc7519 "RFC 7519: JSON Web Token (JWT)"

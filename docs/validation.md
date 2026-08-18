# Validation Record

## Local demonstration, initial review

The browser-accessible React workspace was opened successfully at the temporary preview URL. The landing screen rendered the expected ZeroShare branding, OIDC sign-in controls, policy-decision trace, AES-256-GCM storage statement, and local-demo safety notice.

An attempt to click the browser sign-in control from the connected browser automation channel could not establish a receiver connection. This was recorded as a browser-connector limitation rather than an application authorization failure. The identity and API services remained healthy, and the OAuth2/OIDC flow is additionally covered by local protocol tests. End-to-end HTTP validation of the redirect, code exchange, JWT verification, and encrypted upload/download policy path will be performed independently.

## End-to-end protocol validation

The workspace was isolated from an existing project that occupied port `4000`; ZeroShare now runs on local port `4100` for the demonstration and the React development proxy was updated accordingly. The browser preview continued to render the intended secure landing interface after this change.

The `pnpm verify:flow` verifier completed successfully against the running local OIDC provider and API. It performed a PKCE authorization-code login for Alice, uploaded an encrypted file, created a 15-minute policy for Bob, performed Bob's recipient-bound download, confirmed that reusing the download grant produced `403`, and verified the HMAC-linked audit chain. The recorded validation run captured five security events and confirmed that the decrypted output exactly matched the uploaded plaintext.

The browser automation channel again could not execute the sign-in click because its receiver connection was unavailable. This does not affect the independently executed protocol validation described above; manual review in the connected browser may use the visible **Sign in with OIDC** control.

## Final quality gate

The complete monorepo quality gate completed successfully: ESLint ran cleanly across the API, identity provider, and React workspace; all eight tests passed (four API authorization and encryption tests, three OIDC protocol tests, and one PKCE utility test); and all three production builds completed successfully.

The identity-provider tests verify discovery metadata, mandatory S256 PKCE, authorization-code exchange, and refresh-token rotation. The issuer assigns a unique JWT ID to each access token, so a token refreshed within the same second remains a distinct credential.

Docker Compose packaging is included for PostgreSQL, MinIO, the OIDC provider, API, and web application. Docker is not installed in this sandbox, so the Compose stack could not be executed here; this is an environment limitation, not a simulated Compose success.

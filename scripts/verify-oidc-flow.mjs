import crypto from 'node:crypto'

const identity = process.env.IDENTITY_ORIGIN ?? 'https://4001-iqzvoujaz6wicttdu1y4u-6cb4feab.us4.manus.computer'
const api = process.env.API_ORIGIN ?? 'http://127.0.0.1:4000'
const redirectUri = process.env.REDIRECT_URI ?? 'https://5175-iqzvoujaz6wicttdu1y4u-6cb4feab.us4.manus.computer'

const challengeFor = (verifier) => crypto.createHash('sha256').update(verifier).digest('base64url')
const formHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' }
const bearer = (token) => ({ Authorization: `Bearer ${token}` })

async function signIn(user) {
  const verifier = `zeroshare-${user}-pkce-verifier-2026`
  const authorize = new URL(`${identity}/authorize`)
  authorize.search = new URLSearchParams({ client_id: 'zeroshare-web', response_type: 'code', redirect_uri: redirectUri, code_challenge: challengeFor(verifier), code_challenge_method: 'S256', state: `state-${user}` }).toString()
  const authorizeResponse = await fetch(authorize, { redirect: 'manual' })
  if (authorizeResponse.status !== 302) throw new Error(`Authorization request for ${user} was rejected with ${authorizeResponse.status}`)
  const loginUrl = new URL(authorizeResponse.headers.get('location'), identity)
  const transaction = loginUrl.searchParams.get('transaction')
  if (!transaction) throw new Error('OIDC provider did not issue an authorization transaction')
  const loginResponse = await fetch(`${identity}/login`, { method: 'POST', redirect: 'manual', headers: formHeaders, body: new URLSearchParams({ transaction, user }) })
  if (loginResponse.status !== 302) throw new Error(`Demo identity selection for ${user} was rejected with ${loginResponse.status}`)
  const callback = new URL(loginResponse.headers.get('location'))
  const code = callback.searchParams.get('code')
  if (!code) throw new Error('OIDC provider did not issue an authorization code')
  const tokens = await fetch(`${identity}/token`, { method: 'POST', headers: formHeaders, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'zeroshare-web', code, redirect_uri: redirectUri, code_verifier: verifier }) })
  if (!tokens.ok) throw new Error(`Token exchange for ${user} failed with ${tokens.status}: ${await tokens.text()}`)
  return tokens.json()
}

async function checked(url, options) {
  const response = await fetch(url, options)
  if (!response.ok) throw new Error(`${options?.method ?? 'GET'} ${url} failed with ${response.status}: ${await response.text()}`)
  return response
}

const alice = await signIn('alice')
const uploaded = await checked(`${api}/api/v1/files`, { method: 'POST', headers: { ...bearer(alice.access_token), 'Content-Type': 'application/octet-stream', 'x-file-name': 'security-review.txt', 'x-file-type': 'text/plain', 'x-classification': 'confidential' }, body: 'ZeroShare end-to-end encrypted review evidence.' }).then((response) => response.json())
await checked(`${api}/api/v1/files/${uploaded.file.id}/shares`, { method: 'POST', headers: { ...bearer(alice.access_token), 'Content-Type': 'application/json' }, body: JSON.stringify({ recipientId: 'bob', expiresInMinutes: 15 }) })
const bob = await signIn('bob')
const grant = await checked(`${api}/api/v1/files/${uploaded.file.id}/download-grants`, { method: 'POST', headers: bearer(bob.access_token) }).then((response) => response.json())
const firstDownload = await checked(`${api}${grant.grant.url}`, { headers: bearer(bob.access_token) }).then((response) => response.text())
const reusedGrant = await fetch(`${api}${grant.grant.url}`, { headers: bearer(bob.access_token) })
const audit = await checked(`${api}/api/v1/audit`, { headers: bearer(alice.access_token) }).then((response) => response.json())

if (firstDownload !== 'ZeroShare end-to-end encrypted review evidence.') throw new Error('Downloaded plaintext did not match the encrypted upload payload')
if (reusedGrant.status !== 403) throw new Error(`One-time download grant was unexpectedly reusable: ${reusedGrant.status}`)
if (!audit.chainValid) throw new Error('Audit evidence hash chain did not verify')

console.log(JSON.stringify({ result: 'passed', identityIssuer: identity, fileId: uploaded.file.id, decryptedPayloadVerified: true, reusedGrantRejected: true, auditChainVerified: audit.chainValid, recordedEvents: audit.events.length }, null, 2))

import crypto from 'node:crypto'
import { pathToFileURL } from 'node:url'
import express from 'express'
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose'

type DemoUser = { id: string; name: string; email: string; role: string; scopes: string[] }
type PendingAuthorization = { clientId: string; redirectUri: string; state?: string; challenge: string; expiresAt: number }
type AuthorizationCode = PendingAuthorization & { user: DemoUser; used: boolean }
type RefreshRecord = { user: DemoUser; used: boolean; expiresAt: number }

const b64url = (input: Buffer) => input.toString('base64url')
const sha256 = (input: string) => b64url(crypto.createHash('sha256').update(input).digest())
const tokenHash = (input: string) => crypto.createHash('sha256').update(input).digest('hex')
const random = () => crypto.randomBytes(32).toString('base64url')
const safeEqual = (left: string, right: string) => {
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}
const htmlEscape = (value: string) => value.replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char] ?? char)

export async function createIdentityApp() {
const port = Number(process.env.IDENTITY_PORT ?? 4001)
const issuer = process.env.IDENTITY_ISSUER ?? `http://127.0.0.1:${port}`
const allowedOrigins = new Set((process.env.ALLOWED_REDIRECT_ORIGINS ?? 'http://localhost:5175').split(','))
const clientId = 'zeroshare-web'
const demoUsers: DemoUser[] = [
  { id: 'alice', name: 'Alice Rahman', email: 'alice@zeroshare.demo', role: 'security-owner', scopes: ['openid', 'profile', 'files:read', 'files:write', 'shares:manage', 'audit:read'] },
  { id: 'bob', name: 'Bob Hasan', email: 'bob@zeroshare.demo', role: 'project-member', scopes: ['openid', 'profile', 'files:read'] }
]
const pending = new Map<string, PendingAuthorization>()
const authorizationCodes = new Map<string, AuthorizationCode>()
const refreshTokens = new Map<string, RefreshRecord>()
const keyPair = await generateKeyPair('RS256')
const publicJwk = await exportJWK(keyPair.publicKey)
Object.assign(publicJwk, { kid: 'zeroshare-demo-rs256', use: 'sig', alg: 'RS256' })

async function signAccessToken(user: DemoUser) {
  return new SignJWT({ email: user.email, name: user.name, role: user.role, scope: user.scopes.join(' ') })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid })
    .setIssuer(issuer).setAudience('zeroshare-api').setSubject(user.id).setJti(random()).setIssuedAt().setExpirationTime('10m').sign(keyPair.privateKey)
}

async function signIdToken(user: DemoUser) {
  return new SignJWT({ email: user.email, name: user.name, preferred_username: user.id, role: user.role })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid })
    .setIssuer(issuer).setAudience(clientId).setSubject(user.id).setIssuedAt().setExpirationTime('10m').sign(keyPair.privateKey)
}

function createRefreshToken(user: DemoUser) {
  const raw = random()
  refreshTokens.set(tokenHash(raw), { user, used: false, expiresAt: Date.now() + 1000 * 60 * 60 })
  return raw
}

function createTokenResponse(user: DemoUser) {
  return Promise.all([signAccessToken(user), signIdToken(user)]).then(([accessToken, idToken]) => ({
    access_token: accessToken, id_token: idToken, refresh_token: createRefreshToken(user), token_type: 'Bearer', expires_in: 600, scope: user.scopes.join(' ')
  }))
}

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

app.get('/health', (_request, response) => response.json({ status: 'ok', service: 'zeroshare-identity', demo_mode: true }))
app.get('/.well-known/openid-configuration', (_request, response) => response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, userinfo_endpoint: `${issuer}/userinfo`, jwks_uri: `${issuer}/jwks.json`, response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'] }))
app.get('/jwks.json', (_request, response) => response.json({ keys: [publicJwk] }))

app.get('/authorize', (request, response) => {
  const { client_id: requestedClient, redirect_uri: redirectUri, response_type: responseType, code_challenge: challenge, code_challenge_method: challengeMethod, state } = request.query
  if (requestedClient !== clientId || responseType !== 'code' || typeof redirectUri !== 'string' || typeof challenge !== 'string' || challengeMethod !== 'S256') return response.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 and a registered client are required.' })
  const origin = new URL(redirectUri).origin
  if (!allowedOrigins.has(origin)) return response.status(400).json({ error: 'invalid_redirect_uri' })
  const transaction = random()
  pending.set(transaction, { clientId, redirectUri, state: typeof state === 'string' ? state : undefined, challenge, expiresAt: Date.now() + 1000 * 60 * 5 })
  return response.redirect(`/login?transaction=${encodeURIComponent(transaction)}`)
})

app.get('/login', (request, response) => {
  const transaction = typeof request.query.transaction === 'string' ? request.query.transaction : ''
  if (!pending.has(transaction)) return response.status(400).send('The authorization request is missing or expired.')
  const choices = demoUsers.map((user) => `<button name="user" value="${htmlEscape(user.id)}"><strong>${htmlEscape(user.name)}</strong><span>${htmlEscape(user.role)}</span></button>`).join('')
  return response.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>ZeroShare Identity</title><style>body{font:16px system-ui;background:#07111f;color:#e7f0fb;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:500px;padding:36px;border:1px solid #26415c;border-radius:18px;background:#0d1c2d}button{display:block;width:100%;text-align:left;margin:12px 0;padding:16px;border:1px solid #34536e;border-radius:12px;background:#11263b;color:#fff;cursor:pointer}button:hover{border-color:#7ee8ca}span{display:block;color:#9cb3c9;font-size:13px;margin-top:4px}.tag{color:#7ee8ca;text-transform:uppercase;font-size:12px;letter-spacing:.12em}</style></head><body><main class="card"><p class="tag">Local OAuth2/OIDC lab</p><h1>Choose a demo identity</h1><p>This local screen intentionally has no password and must not be used as a production identity provider.</p><form method="post" action="/login"><input type="hidden" name="transaction" value="${htmlEscape(transaction)}">${choices}</form></main></body></html>`)
})

app.post('/login', (request, response) => {
  const transaction = typeof request.body.transaction === 'string' ? request.body.transaction : ''
  const user = demoUsers.find((candidate) => candidate.id === request.body.user)
  const authorization = pending.get(transaction)
  if (!authorization || authorization.expiresAt < Date.now() || !user) return response.status(400).send('The authorization request is invalid or expired.')
  pending.delete(transaction)
  const code = random()
  authorizationCodes.set(code, { ...authorization, user, used: false })
  const redirect = new URL(authorization.redirectUri)
  redirect.searchParams.set('code', code)
  if (authorization.state) redirect.searchParams.set('state', authorization.state)
  return response.redirect(redirect.toString())
})

app.post('/token', async (request, response) => {
  const grantType = request.body.grant_type
  if (grantType === 'authorization_code') {
    const code = typeof request.body.code === 'string' ? request.body.code : ''
    const verifier = typeof request.body.code_verifier === 'string' ? request.body.code_verifier : ''
    const redirectUri = typeof request.body.redirect_uri === 'string' ? request.body.redirect_uri : ''
    const record = authorizationCodes.get(code)
    if (!record || record.used || record.expiresAt < Date.now() || request.body.client_id !== clientId || !safeEqual(record.redirectUri, redirectUri) || !safeEqual(record.challenge, sha256(verifier))) return response.status(400).json({ error: 'invalid_grant' })
    record.used = true
    return response.json(await createTokenResponse(record.user))
  }
  if (grantType === 'refresh_token') {
    const raw = typeof request.body.refresh_token === 'string' ? request.body.refresh_token : ''
    const record = refreshTokens.get(tokenHash(raw))
    if (!record || record.used || record.expiresAt < Date.now()) return response.status(400).json({ error: 'invalid_grant' })
    record.used = true
    return response.json(await createTokenResponse(record.user))
  }
  return response.status(400).json({ error: 'unsupported_grant_type' })
})

app.get('/userinfo', async (request, response) => {
  const value = request.headers.authorization?.replace(/^Bearer\s+/i, '')
  if (!value) return response.status(401).json({ error: 'invalid_token' })
  try {
    const { payload } = await jwtVerify(value, keyPair.publicKey, { issuer, audience: 'zeroshare-api' })
    return response.json({ sub: payload.sub, email: payload.email, name: payload.name, role: payload.role })
  } catch { return response.status(401).json({ error: 'invalid_token' }) }
})

return { app, issuer, port }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { app, issuer, port } = await createIdentityApp()
  app.listen(port, '0.0.0.0', () => console.log(`ZeroShare local OIDC provider at ${issuer}`))
}

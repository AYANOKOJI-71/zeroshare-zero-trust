import type { Server } from 'node:http'
import crypto from 'node:crypto'
import { afterEach, describe, expect, it } from 'vitest'
import { createIdentityApp } from '../src/server.js'

let server: Server | undefined

afterEach(() => server?.close())

const challengeFor = (verifier: string) => crypto.createHash('sha256').update(verifier).digest('base64url')

async function startProvider() {
  const { app } = await createIdentityApp()
  server = app.listen(0)
  await new Promise<void>((resolve) => server?.once('listening', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Test server did not expose a TCP port')
  return `http://127.0.0.1:${address.port}`
}

describe('local OIDC provider', () => {
  it('advertises authorization code with S256 PKCE and an RS256 JWKS', async () => {
    const baseUrl = await startProvider()
    const discovery = await fetch(`${baseUrl}/.well-known/openid-configuration`).then((response) => response.json()) as { response_types_supported: string[]; code_challenge_methods_supported: string[] }
    const jwks = await fetch(`${baseUrl}/jwks.json`).then((response) => response.json()) as { keys: Array<{ alg: string; use: string }> }
    expect(discovery.response_types_supported).toEqual(['code'])
    expect(discovery.code_challenge_methods_supported).toEqual(['S256'])
    expect(jwks.keys[0]).toMatchObject({ alg: 'RS256', use: 'sig' })
  })

  it('rejects authorization requests that omit the required PKCE S256 challenge', async () => {
    const baseUrl = await startProvider()
    const response = await fetch(`${baseUrl}/authorize?client_id=zeroshare-web&response_type=code&redirect_uri=http://localhost:5175`)
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_request' })
  })

  it('rotates a refresh token after a PKCE authorization-code exchange', async () => {
    const baseUrl = await startProvider()
    const verifier = 'identity-test-verifier-2026'
    const authorize = new URL(`${baseUrl}/authorize`)
    authorize.search = new URLSearchParams({ client_id: 'zeroshare-web', response_type: 'code', redirect_uri: 'http://localhost:5175', code_challenge: challengeFor(verifier), code_challenge_method: 'S256', state: 'test-state' }).toString()
    const pending = await fetch(authorize, { redirect: 'manual' })
    const transaction = new URL(pending.headers.get('location')!, baseUrl).searchParams.get('transaction')!
    const login = await fetch(`${baseUrl}/login`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ transaction, user: 'alice' }) })
    const code = new URL(login.headers.get('location')!).searchParams.get('code')!
    const token = await fetch(`${baseUrl}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'zeroshare-web', code, redirect_uri: 'http://localhost:5175', code_verifier: verifier }) })
    expect(token.status).toBe(200)
    const initial = await token.json() as { access_token: string; refresh_token: string; token_type: string }
    const refreshed = await fetch(`${baseUrl}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'zeroshare-web', refresh_token: initial.refresh_token }) })
    expect(refreshed.status).toBe(200)
    const next = await refreshed.json() as { access_token: string; refresh_token: string; token_type: string }
    expect(initial).toMatchObject({ token_type: 'Bearer' })
    expect(next).toMatchObject({ token_type: 'Bearer' })
    expect(next.refresh_token).not.toBe(initial.refresh_token)
    expect(next.access_token).not.toBe(initial.access_token)
  })
})

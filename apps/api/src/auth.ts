import { createRemoteJWKSet, jwtVerify } from 'jose'
import type { Principal } from './types.js'

export type Authenticator = (header: string | undefined) => Promise<Principal>

export function createJwtAuthenticator(issuer = process.env.IDENTITY_ISSUER ?? 'http://127.0.0.1:4001'): Authenticator {
  const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks.json`))
  return async (header) => {
    const token = header?.replace(/^Bearer\s+/i, '')
    if (!token) throw new Error('missing_token')
    const { payload } = await jwtVerify(token, jwks, { issuer, audience: 'zeroshare-api' })
    if (!payload.sub || typeof payload.email !== 'string' || typeof payload.name !== 'string' || typeof payload.role !== 'string') throw new Error('invalid_token')
    return { id: payload.sub, email: payload.email, name: payload.name, role: payload.role, scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [] }
  }
}

export function hasScope(principal: Principal, scope: string) { return principal.scopes.includes(scope) }

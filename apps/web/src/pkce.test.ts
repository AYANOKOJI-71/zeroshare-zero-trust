import { describe, expect, it } from 'vitest'
import { createChallenge } from './pkce'

describe('PKCE challenge', () => {
  it('uses URL-safe SHA-256 output', async () => {
    expect(await createChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})

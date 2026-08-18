import crypto from 'node:crypto'
import request from 'supertest'
import { describe, expect, it } from 'vitest'
import { createApp } from '../src/app.js'
import { MemoryRepository } from '../src/repository.js'
import { MemoryObjectStore } from '../src/storage.js'
import type { Principal } from '../src/types.js'

const users: Record<string, Principal> = {
  alice: { id: 'alice', name: 'Alice Rahman', email: 'alice@zeroshare.demo', role: 'security-owner', scopes: ['files:read', 'files:write', 'shares:manage', 'audit:read'] },
  bob: { id: 'bob', name: 'Bob Hasan', email: 'bob@zeroshare.demo', role: 'project-member', scopes: ['files:read'] }
}

function fixture() {
  return createApp({ repository: new MemoryRepository(), objectStore: new MemoryObjectStore(), masterKey: crypto.randomBytes(32), auditKey: crypto.randomBytes(32), authenticator: async (header) => {
    const user = users[header?.replace('Bearer ', '') ?? '']
    if (!user) throw new Error('invalid token')
    return user
  } })
}

describe('zero-trust file API', () => {
  it('rejects requests without a valid access token', async () => { await request(fixture()).get('/api/v1/files').expect(401) })
  it('encrypts an upload and prevents a non-recipient from minting a download grant', async () => {
    const app = fixture()
    const upload = await request(app).post('/api/v1/files').set('Authorization', 'Bearer alice').set('Content-Type', 'application/octet-stream').set('x-file-name', 'roadmap.txt').send('confidential roadmap').expect(201)
    await request(app).post(`/api/v1/files/${upload.body.file.id}/download-grants`).set('Authorization', 'Bearer bob').expect(403)
  })
  it('enforces a recipient-bound single-use download grant and preserves plaintext integrity', async () => {
    const app = fixture()
    const upload = await request(app).post('/api/v1/files').set('Authorization', 'Bearer alice').set('Content-Type', 'application/octet-stream').set('x-file-name', 'design.txt').send('encrypted design').expect(201)
    await request(app).post(`/api/v1/files/${upload.body.file.id}/shares`).set('Authorization', 'Bearer alice').send({ recipientId: 'bob', expiresInMinutes: 5 }).expect(201)
    const grant = await request(app).post(`/api/v1/files/${upload.body.file.id}/download-grants`).set('Authorization', 'Bearer bob').expect(201)
    const download = await request(app).get(grant.body.grant.url).set('Authorization', 'Bearer bob').expect(200)
    expect(download.body.toString()).toBe('encrypted design')
    await request(app).get(grant.body.grant.url).set('Authorization', 'Bearer bob').expect(403)
  })
  it('builds a verifiable audit chain and prevents members from reading global audit evidence', async () => {
    const app = fixture()
    const upload = await request(app).post('/api/v1/files').set('Authorization', 'Bearer alice').set('Content-Type', 'application/octet-stream').set('x-file-name', 'audit.txt').send('audit me').expect(201)
    await request(app).post(`/api/v1/files/${upload.body.file.id}/shares`).set('Authorization', 'Bearer alice').send({ recipientId: 'bob', expiresInMinutes: 5 }).expect(201)
    const audit = await request(app).get('/api/v1/audit').set('Authorization', 'Bearer alice').expect(200)
    expect(audit.body.chainValid).toBe(true)
    await request(app).get('/api/v1/audit').set('Authorization', 'Bearer bob').expect(403)
  })
})

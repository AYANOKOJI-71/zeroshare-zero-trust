import { randomUUID } from 'node:crypto'
import cors from 'cors'
import express, { type RequestHandler } from 'express'
import { z } from 'zod'
import { createJwtAuthenticator, hasScope, type Authenticator } from './auth.js'
import { MemoryRepository } from './repository.js'
import { createAuditEvent, decryptPayload, encryptPayload, loadLocalKey, verifyAuditChain } from './security.js'
import type { Principal } from './types.js'
import { createObjectStoreFromEnvironment, type ObjectStore } from './storage.js'

type Dependencies = { authenticator?: Authenticator; repository?: MemoryRepository; objectStore?: ObjectStore; masterKey?: Buffer; auditKey?: Buffer; now?: () => number }
type RequestWithPrincipal = express.Request & { principal?: Principal }

const shareSchema = z.object({ recipientId: z.string().regex(/^[a-z0-9-]{2,64}$/), expiresInMinutes: z.number().int().min(1).max(7 * 24 * 60) })

export function createApp(dependencies: Dependencies = {}) {
  const repository = dependencies.repository ?? new MemoryRepository()
  const objectStore = dependencies.objectStore ?? createObjectStoreFromEnvironment()
  const authenticator = dependencies.authenticator ?? createJwtAuthenticator()
  const masterKey = dependencies.masterKey ?? loadLocalKey(process.env.ZEROSHARE_MASTER_KEY_BASE64, 'master key')
  const auditKey = dependencies.auditKey ?? loadLocalKey(process.env.ZEROSHARE_AUDIT_CHAIN_KEY, 'audit chain key')
  const now = dependencies.now ?? Date.now
  const app = express()
  app.use(cors({ origin: (process.env.ALLOWED_REDIRECT_ORIGINS ?? 'http://localhost:5175').split(','), methods: ['GET', 'POST'] }))
  app.use(express.json({ limit: '64kb' }))

  const authenticate: RequestHandler = async (request, response, next) => {
    try { (request as RequestWithPrincipal).principal = await authenticator(request.headers.authorization); return next() }
    catch { return response.status(401).json({ error: 'unauthorized', message: 'A valid access token is required.' }) }
  }
  const requireScope = (scope: string): RequestHandler => (request, response, next) => {
    const principal = (request as RequestWithPrincipal).principal
    if (!principal || !hasScope(principal, scope)) return response.status(403).json({ error: 'forbidden', message: `Required scope: ${scope}` })
    return next()
  }
  const audit = (principal: Principal, action: string, resourceType: 'file' | 'share' | 'download' | 'policy', resourceId: string, decision: 'allowed' | 'denied', details: Record<string, string | number | boolean>) => {
    const previousHash = repository.audit.at(-1)?.hash ?? 'GENESIS'
    repository.appendAudit(createAuditEvent({ actorId: principal.id, action, resourceType, resourceId, decision, details }, previousHash, auditKey))
  }
  const authorized = (principal: Principal, fileId: string) => {
    const file = repository.getFile(fileId)
    if (!file) return { file: undefined, allowed: false }
    return { file, allowed: file.ownerId === principal.id || Boolean(repository.findActiveShare(fileId, principal.id, now())) }
  }

  app.get('/health', (_request, response) => response.json({ status: 'ok', service: 'zeroshare-api', storage: objectStore.constructor.name, demo_mode: process.env.ALLOW_INSECURE_DEMO === 'true' }))
  app.get('/api/v1/me', authenticate, (request, response) => response.json({ user: (request as RequestWithPrincipal).principal }))
  app.get('/api/v1/files', authenticate, requireScope('files:read'), (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    response.json({ files: repository.listVisibleFiles(principal.id, now()).map((file) => ({ id: file.id, ownerId: file.ownerId, originalName: file.originalName, mimeType: file.mimeType, bytes: file.bytes, createdAt: file.createdAt, classification: file.classification, access: file.ownerId === principal.id ? 'owner' : 'shared' })) })
  })
  app.post('/api/v1/files', authenticate, requireScope('files:write'), express.raw({ type: 'application/octet-stream', limit: '10mb' }), async (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    const originalName = request.header('x-file-name')?.replace(/[^a-zA-Z0-9._ -]/g, '_').slice(0, 160)
    if (!originalName || !Buffer.isBuffer(request.body) || request.body.length === 0) return response.status(400).json({ error: 'invalid_upload', message: 'A file name and non-empty octet-stream body are required.' })
    const encrypted = encryptPayload(request.body, masterKey)
    const id = randomUUID()
    const record = repository.createFile({ id, ownerId: principal.id, originalName, mimeType: request.header('x-file-type') ?? 'application/octet-stream', bytes: request.body.length, objectKey: `ciphertext/${id}`, encryptedDataKey: encrypted.encryptedDataKey, iv: encrypted.iv, authTag: encrypted.authTag, createdAt: new Date(now()).toISOString(), classification: request.header('x-classification') === 'internal' ? 'internal' : 'confidential' })
    await objectStore.put(record.objectKey, encrypted.ciphertext)
    audit(principal, 'file.upload', 'file', id, 'allowed', { bytes: record.bytes, encryption: 'AES-256-GCM' })
    return response.status(201).json({ file: { id: record.id, originalName: record.originalName, bytes: record.bytes, classification: record.classification } })
  })
  app.post('/api/v1/files/:id/shares', authenticate, requireScope('shares:manage'), (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    const file = repository.getFile(request.params.id)
    if (!file || file.ownerId !== principal.id) { audit(principal, 'share.create', 'share', request.params.id, 'denied', { reason: 'owner_required' }); return response.status(403).json({ error: 'forbidden', message: 'Only the file owner can create a sharing policy.' }) }
    const parsed = shareSchema.safeParse(request.body)
    if (!parsed.success || parsed.data.recipientId === principal.id) return response.status(400).json({ error: 'invalid_share_policy' })
    const share = repository.createShare({ fileId: file.id, recipientId: parsed.data.recipientId, createdBy: principal.id, expiresAt: now() + parsed.data.expiresInMinutes * 60_000 })
    audit(principal, 'share.create', 'share', share.id, 'allowed', { recipientId: share.recipientId, expiresAt: share.expiresAt })
    return response.status(201).json({ share: { id: share.id, fileId: share.fileId, recipientId: share.recipientId, expiresAt: share.expiresAt } })
  })
  app.post('/api/v1/files/:id/download-grants', authenticate, requireScope('files:read'), (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    const { file, allowed } = authorized(principal, request.params.id)
    if (!file || !allowed) { audit(principal, 'download.grant', 'download', request.params.id, 'denied', { reason: 'policy_denied' }); return response.status(403).json({ error: 'forbidden', message: 'The sharing policy does not allow this download.' }) }
    const grant = repository.createGrant({ fileId: file.id, recipientId: principal.id, expiresAt: now() + 60_000 })
    audit(principal, 'download.grant', 'download', grant.id, 'allowed', { fileId: file.id, ttlSeconds: 60 })
    return response.status(201).json({ grant: { id: grant.id, expiresAt: grant.expiresAt, url: `/api/v1/downloads/${grant.id}` } })
  })
  app.get('/api/v1/downloads/:grantId', authenticate, requireScope('files:read'), async (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    const grant = repository.consumeGrant(request.params.grantId, principal.id, now())
    if (!grant) { audit(principal, 'download.consume', 'download', request.params.grantId, 'denied', { reason: 'expired_used_or_wrong_recipient' }); return response.status(403).json({ error: 'invalid_grant' }) }
    const file = repository.getFile(grant.fileId)
    if (!file) return response.status(404).json({ error: 'file_not_found' })
    const plaintext = decryptPayload(file, await objectStore.get(file.objectKey), masterKey)
    audit(principal, 'download.consume', 'download', grant.id, 'allowed', { fileId: file.id, oneTime: true })
    response.setHeader('Content-Type', file.mimeType)
    response.setHeader('Content-Disposition', `attachment; filename="${file.originalName.replace(/["\\]/g, '_')}"`)
    return response.send(plaintext)
  })
  app.get('/api/v1/audit', authenticate, requireScope('audit:read'), (request, response) => {
    const principal = (request as RequestWithPrincipal).principal!
    const visible = repository.audit.filter((event) => event.actorId === principal.id || principal.role === 'security-owner')
    return response.json({ events: visible, chainValid: verifyAuditChain(repository.audit, auditKey) })
  })
  return app
}

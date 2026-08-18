import { randomUUID } from 'node:crypto'
import type { AuditEvent, DownloadGrant, FileRecord, ShareRecord } from './types.js'

export class MemoryRepository {
  files = new Map<string, FileRecord>()
  shares = new Map<string, ShareRecord>()
  grants = new Map<string, DownloadGrant>()
  audit: AuditEvent[] = []

  createFile(file: FileRecord) { this.files.set(file.id, file); return file }
  getFile(id: string) { return this.files.get(id) }
  listVisibleFiles(principalId: string, now = Date.now()) {
    const shared = new Set([...this.shares.values()].filter((share) => share.recipientId === principalId && !share.revokedAt && share.expiresAt > now).map((share) => share.fileId))
    return [...this.files.values()].filter((file) => file.ownerId === principalId || shared.has(file.id))
  }
  createShare(input: Omit<ShareRecord, 'id'>) { const share = { id: randomUUID(), ...input }; this.shares.set(share.id, share); return share }
  findActiveShare(fileId: string, recipientId: string, now = Date.now()) { return [...this.shares.values()].find((share) => share.fileId === fileId && share.recipientId === recipientId && !share.revokedAt && share.expiresAt > now) }
  createGrant(input: Omit<DownloadGrant, 'id'>) { const grant = { id: randomUUID(), ...input }; this.grants.set(grant.id, grant); return grant }
  consumeGrant(id: string, recipientId: string, now = Date.now()) { const grant = this.grants.get(id); if (!grant || grant.recipientId !== recipientId || grant.usedAt || grant.expiresAt <= now) return undefined; grant.usedAt = now; return grant }
  appendAudit(event: AuditEvent) { this.audit.push(event); return event }
}

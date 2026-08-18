export type Principal = { id: string; email: string; name: string; role: string; scopes: string[] }
export type FileRecord = { id: string; ownerId: string; originalName: string; mimeType: string; bytes: number; objectKey: string; encryptedDataKey: string; iv: string; authTag: string; createdAt: string; classification: 'confidential' | 'internal' }
export type ShareRecord = { id: string; fileId: string; recipientId: string; createdBy: string; expiresAt: number; revokedAt?: number }
export type DownloadGrant = { id: string; fileId: string; recipientId: string; expiresAt: number; usedAt?: number }
export type AuditEvent = { id: string; at: string; actorId: string; action: string; resourceType: 'file' | 'share' | 'download' | 'policy'; resourceId: string; decision: 'allowed' | 'denied'; details: Record<string, string | number | boolean>; previousHash: string; hash: string }

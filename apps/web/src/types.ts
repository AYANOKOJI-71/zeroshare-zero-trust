export type User = { id: string; email: string; name: string; role: string; scopes: string[] }
export type FileItem = { id: string; ownerId: string; originalName: string; mimeType: string; bytes: number; createdAt: string; classification: 'confidential' | 'internal'; access: 'owner' | 'shared' }
export type AuditEvent = { id: string; at: string; actorId: string; action: string; resourceType: string; resourceId: string; decision: 'allowed' | 'denied'; details: Record<string, string | number | boolean>; hash: string; previousHash: string }
export type Session = { access_token: string; refresh_token: string; expires_at: number; user?: User }

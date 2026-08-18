import crypto, { randomUUID } from 'node:crypto'
import type { AuditEvent, FileRecord } from './types.js'

const secureKey = (input: Buffer | string) => crypto.createHash('sha256').update(input).digest()
const base64 = (value: Buffer) => value.toString('base64')
const fromBase64 = (value: string) => Buffer.from(value, 'base64')

export function loadLocalKey(value: string | undefined, purpose: string) {
  if (value) { const decoded = fromBase64(value); if (decoded.length !== 32) throw new Error(`${purpose} must decode to 32 bytes`); return decoded }
  if (process.env.ALLOW_INSECURE_DEMO !== 'true') throw new Error(`${purpose} is required outside the local demo mode`)
  return secureKey(`zeroshare-local-demo-${purpose}-never-use-in-production`)
}

export function encryptPayload(plaintext: Buffer, masterKey: Buffer) {
  const dataKey = crypto.randomBytes(32)
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const wrapIv = crypto.randomBytes(12)
  const wrapper = crypto.createCipheriv('aes-256-gcm', masterKey, wrapIv)
  const encryptedDataKey = Buffer.concat([wrapper.update(dataKey), wrapper.final()])
  return { ciphertext, iv: base64(iv), authTag: base64(cipher.getAuthTag()), encryptedDataKey: base64(Buffer.concat([wrapIv, wrapper.getAuthTag(), encryptedDataKey])) }
}

export function decryptPayload(file: FileRecord, ciphertext: Buffer, masterKey: Buffer) {
  const wrapped = fromBase64(file.encryptedDataKey)
  const unwrap = crypto.createDecipheriv('aes-256-gcm', masterKey, wrapped.subarray(0, 12))
  unwrap.setAuthTag(wrapped.subarray(12, 28))
  const dataKey = Buffer.concat([unwrap.update(wrapped.subarray(28)), unwrap.final()])
  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, fromBase64(file.iv))
  decipher.setAuthTag(fromBase64(file.authTag))
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export function createAuditEvent(input: Omit<AuditEvent, 'id' | 'at' | 'previousHash' | 'hash'>, previousHash: string, auditKey: Buffer): AuditEvent {
  const event = { id: randomUUID(), at: new Date().toISOString(), ...input, previousHash }
  const canonical = JSON.stringify(event)
  const hash = crypto.createHmac('sha256', auditKey).update(`${previousHash}.${canonical}`).digest('hex')
  return { ...event, hash }
}

export function verifyAuditChain(events: AuditEvent[], auditKey: Buffer) {
  let previousHash = 'GENESIS'
  return events.every((event) => {
    const { hash, ...unsigned } = event
    const expected = crypto.createHmac('sha256', auditKey).update(`${previousHash}.${JSON.stringify(unsigned)}`).digest('hex')
    previousHash = hash
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(hash, 'hex'))
  })
}

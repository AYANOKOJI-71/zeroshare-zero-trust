import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3'

export interface ObjectStore { put(key: string, value: Buffer): Promise<void>; get(key: string): Promise<Buffer> }

export class MemoryObjectStore implements ObjectStore {
  private objects = new Map<string, Buffer>()
  async put(key: string, value: Buffer) { this.objects.set(key, Buffer.from(value)) }
  async get(key: string) { const value = this.objects.get(key); if (!value) throw new Error('Object not found'); return Buffer.from(value) }
}

export class EncryptedFilesystemObjectStore implements ObjectStore {
  constructor(private readonly root: string) {}
  private path(key: string) { return join(this.root, key) }
  async put(key: string, value: Buffer) { const path = this.path(key); await mkdir(dirname(path), { recursive: true }); await writeFile(path, value, { mode: 0o600 }) }
  async get(key: string) { return readFile(this.path(key)) }
}

export class S3ObjectStore implements ObjectStore {
  private readonly client: S3Client
  constructor(private readonly bucket: string, config: { endpoint: string; region: string; accessKeyId: string; secretAccessKey: string }) {
    this.client = new S3Client({ endpoint: config.endpoint, region: config.region, forcePathStyle: true, credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey } })
  }
  async put(key: string, value: Buffer) { await this.client.send(new PutObjectCommand({ Bucket: this.bucket, Key: key, Body: value, ContentType: 'application/octet-stream' })) }
  async get(key: string) {
    const response = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }))
    if (!response.Body) throw new Error('Object not found')
    return Buffer.from(await (response.Body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray())
  }
}

export function createObjectStoreFromEnvironment() {
  if (process.env.OBJECT_STORAGE_DRIVER !== 's3') return new EncryptedFilesystemObjectStore(process.env.OBJECT_ROOT ?? './data/objects')
  const endpoint = process.env.S3_ENDPOINT
  const accessKeyId = process.env.S3_ACCESS_KEY
  const secretAccessKey = process.env.S3_SECRET_KEY
  const bucket = process.env.S3_BUCKET
  if (!endpoint || !accessKeyId || !secretAccessKey || !bucket) throw new Error('S3 endpoint, bucket, and server-side credentials are required for the S3 storage driver')
  return new S3ObjectStore(bucket, { endpoint, region: process.env.S3_REGION ?? 'us-east-1', accessKeyId, secretAccessKey })
}

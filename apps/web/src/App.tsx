import { useEffect, useMemo, useRef, useState } from 'react'
import { createChallenge, createVerifier } from './pkce'
import type { AuditEvent, FileItem, Session, User } from './types'
import './styles.css'

const identityIssuer = import.meta.env.VITE_IDENTITY_ISSUER ?? 'http://127.0.0.1:4001'
const clientId = 'zeroshare-web'
const sessionKey = 'zeroshare-session'
const formatBytes = (bytes: number) => bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`
const formatTime = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))

async function api(path: string, token: string, init: RequestInit = {}) {
  const response = await fetch(path, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token}` } })
  if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.message ?? body.error ?? 'The security gateway rejected the request.') }
  return response
}

export default function App() {
  const [session, setSession] = useState<Session | null>(() => { const saved = sessionStorage.getItem(sessionKey); return saved ? JSON.parse(saved) as Session : null })
  const [user, setUser] = useState<User | null>(null)
  const [files, setFiles] = useState<FileItem[]>([])
  const [audits, setAudits] = useState<AuditEvent[]>([])
  const [chainValid, setChainValid] = useState(false)
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const signedIn = Boolean(session?.access_token && user)
  const canUpload = user?.scopes.includes('files:write')
  const canShare = user?.scopes.includes('shares:manage')
  const canAudit = user?.scopes.includes('audit:read')
  const accessLabel = useMemo(() => user?.role === 'security-owner' ? 'Security owner' : 'Project member', [user])

  const storeSession = (next: Session | null) => { setSession(next); if (next) sessionStorage.setItem(sessionKey, JSON.stringify(next)); else sessionStorage.removeItem(sessionKey) }
  const loadWorkspace = async (token = session?.access_token) => {
    if (!token) return
    const [meResponse, filesResponse] = await Promise.all([api('/api/v1/me', token), api('/api/v1/files', token)])
    const me = await meResponse.json() as { user: User }
    const list = await filesResponse.json() as { files: FileItem[] }
    setUser(me.user); setFiles(list.files)
    if (me.user.scopes.includes('audit:read')) { const audit = await api('/api/v1/audit', token).then((response) => response.json()) as { events: AuditEvent[]; chainValid: boolean }; setAudits(audit.events); setChainValid(audit.chainValid) }
  }
  const exchangeCallback = async () => {
    const query = new URLSearchParams(window.location.search)
    const code = query.get('code'); const state = query.get('state')
    const savedState = sessionStorage.getItem('zeroshare-oauth-state'); const verifier = sessionStorage.getItem('zeroshare-pkce-verifier')
    if (!code || !state || !verifier || state !== savedState) return false
    const tokenResponse = await fetch(`${identityIssuer}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: window.location.origin, code_verifier: verifier }) })
    if (!tokenResponse.ok) throw new Error('Authorization-code exchange failed.')
    const tokens = await tokenResponse.json() as { access_token: string; refresh_token: string; expires_in: number }
    storeSession({ ...tokens, expires_at: Date.now() + tokens.expires_in * 1000 })
    sessionStorage.removeItem('zeroshare-oauth-state'); sessionStorage.removeItem('zeroshare-pkce-verifier'); window.history.replaceState({}, '', window.location.pathname)
    await loadWorkspace(tokens.access_token)
    return true
  }
  const refreshSession = async (current: Session) => {
    const response = await fetch(`${identityIssuer}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: current.refresh_token }) })
    if (!response.ok) throw new Error('Session renewal was rejected. Please sign in again.')
    const tokens = await response.json() as { access_token: string; refresh_token: string; expires_in: number }
    const next = { ...tokens, expires_at: Date.now() + tokens.expires_in * 1000 }
    storeSession(next)
    await loadWorkspace(next.access_token)
  }
  useEffect(() => { exchangeCallback().catch((error: Error) => setNotice(error.message)).then((handled) => { if (!handled && session?.access_token) loadWorkspace().catch((error: Error) => { storeSession(null); setNotice(error.message) }) }) }, [])
  useEffect(() => {
    if (!session) return
    const delay = Math.max(15_000, session.expires_at - Date.now() - 30_000)
    const timer = window.setTimeout(() => { refreshSession(session).catch((error: Error) => { storeSession(null); setUser(null); setNotice(error.message) }) }, delay)
    return () => window.clearTimeout(timer)
  }, [session])
  const startLogin = async () => {
    const verifier = createVerifier(); const state = createVerifier(); const challenge = await createChallenge(verifier)
    sessionStorage.setItem('zeroshare-pkce-verifier', verifier); sessionStorage.setItem('zeroshare-oauth-state', state)
    const query = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: window.location.origin, scope: 'openid profile files:read files:write shares:manage audit:read', code_challenge: challenge, code_challenge_method: 'S256', state })
    window.location.assign(`${identityIssuer}/authorize?${query}`)
  }
  const signOut = () => { storeSession(null); setUser(null); setFiles([]); setAudits([]); setNotice('Signed out. Local session tokens were cleared from this browser tab.') }
  const upload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (!file || !session) return
    setBusy(true); setNotice('')
    try { await api('/api/v1/files', session.access_token, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'x-file-name': file.name, 'x-file-type': file.type || 'application/octet-stream', 'x-classification': 'confidential' }, body: await file.arrayBuffer() }); await loadWorkspace(); setNotice(`${file.name} was encrypted before it entered the storage adapter.`) }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Upload failed.') } finally { setBusy(false); if (fileInput.current) fileInput.current.value = '' }
  }
  const share = async (fileId: string) => {
    if (!session) return; const recipientId = window.prompt('Demo recipient ID: use “bob” for the project member.'); if (!recipientId) return
    setBusy(true); try { await api(`/api/v1/files/${fileId}/shares`, session.access_token, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipientId, expiresInMinutes: 30 }) }); await loadWorkspace(); setNotice(`A 30-minute, recipient-bound sharing policy was created for ${recipientId}.`) } catch (error) { setNotice(error instanceof Error ? error.message : 'Sharing policy was rejected.') } finally { setBusy(false) }
  }
  const download = async (fileId: string, originalName: string) => {
    if (!session) return; setBusy(true)
    try { const grant = await api(`/api/v1/files/${fileId}/download-grants`, session.access_token, { method: 'POST' }).then((response) => response.json()) as { grant: { url: string } }; const file = await api(grant.grant.url, session.access_token).then((response) => response.blob()); const url = URL.createObjectURL(file); const anchor = document.createElement('a'); anchor.href = url; anchor.download = originalName; anchor.click(); URL.revokeObjectURL(url); await loadWorkspace(); setNotice('One-time download grant consumed. A second attempt would be rejected.') } catch (error) { setNotice(error instanceof Error ? error.message : 'Download was rejected.') } finally { setBusy(false) }
  }
  return <div className="shell">
    <header className="topbar"><a className="brand" href="#top"><span className="brand-mark">Z</span><span>Zero<span>Share</span></span></a><div className="header-actions">{signedIn ? <><span className="identity-chip"><i></i>{user?.name}</span><button className="quiet-button" onClick={signOut}>Sign out</button></> : <button className="login-button" onClick={startLogin}>Sign in with OIDC <span>→</span></button>}</div></header>
    <main id="top">{!signedIn ? <section className="hero"><div className="hero-copy"><p className="eyebrow">Zero-trust file sharing lab</p><h1>Every file request<br /><em>earns</em> its access.</h1><p className="lede">A local OAuth2/OIDC demonstration of encrypted storage, recipient-bound sharing policies, short-lived download grants, and tamper-evident audit evidence.</p><button className="login-button hero-button" onClick={startLogin}>Enter the secure workspace <span>→</span></button><p className="hero-footnote">PKCE required · Short-lived tokens · No cloud account needed</p></div><div className="trust-card"><div className="trust-card-top"><span className="live-dot"></span><span>Policy decision trace</span><span className="mono">LIVE</span></div><div className="trace"><div><b>01</b><span>Validate OIDC token</span><strong>PASS</strong></div><div><b>02</b><span>Check scope &amp; role</span><strong>PASS</strong></div><div><b>03</b><span>Enforce file policy</span><strong>PASS</strong></div><div><b>04</b><span>Issue one-time grant</span><strong>PASS</strong></div></div><div className="cipherline"><span>aes-256-gcm</span><code>ciphertext / opaque-object-key</code></div></div></section> : <>
      <section className="workspace-heading"><div><p className="eyebrow">Authenticated session</p><h1>Good to see you, {user?.name?.split(' ')[0]}.</h1><p>{accessLabel} · {user?.email}</p></div><div className="session-security"><span className="live-dot"></span><div><b>Identity verified</b><small>OIDC access token active</small></div><span className="lock">⌁</span></div></section>
      {notice && <div className="notice" role="status">{notice}<button onClick={() => setNotice('')}>×</button></div>}
      <section className="security-strip"><div><span className="strip-icon">⌾</span><div><b>Token-bound session</b><small>OIDC / JWT signature verified at the API</small></div></div><div><span className="strip-icon">◇</span><div><b>Encrypted at rest</b><small>Unique AES-256-GCM data key per upload</small></div></div><div><span className="strip-icon">↗</span><div><b>Least-privilege grants</b><small>Recipient-bound and single use</small></div></div><div><span className="strip-icon">⌇</span><div><b>Audit-chain evidence</b><small>HMAC-linked security events</small></div></div></section>
      <section className="workspace-grid"><div className="primary-panel"><div className="panel-heading"><div><p className="eyebrow">Protected objects</p><h2>Secure file vault</h2></div>{canUpload && <label className={`upload-button ${busy ? 'disabled' : ''}`}>+ Encrypt & upload<input ref={fileInput} type="file" onChange={upload} disabled={busy} /></label>}</div><div className="file-table"><div className="table-head"><span>Name</span><span>Access</span><span>Classification</span><span>Created</span><span>Actions</span></div>{files.length === 0 ? <div className="empty-state"><span>◈</span><h3>No protected files yet</h3><p>{canUpload ? 'Upload a small text file to exercise the encrypted storage path.' : 'This account will see documents when the owner creates a policy for it.'}</p></div> : files.map((file) => <div className="file-row" key={file.id}><div className="file-name"><span className="file-icon">▧</span><span><b>{file.originalName}</b><small>{formatBytes(file.bytes)} · {file.mimeType}</small></span></div><span><i className={file.access === 'owner' ? 'owner-dot' : 'shared-dot'}></i>{file.access === 'owner' ? 'Owner' : 'Shared'}</span><span className="class-badge">{file.classification}</span><time>{formatTime(file.createdAt)}</time><div className="row-actions"><button onClick={() => download(file.id, file.originalName)} disabled={busy}>Download</button>{canShare && file.access === 'owner' && <button className="share-action" onClick={() => share(file.id)} disabled={busy}>Share</button>}</div></div>)}</div></div>
      <aside className="side-panel"><div className="panel-heading"><div><p className="eyebrow">Control plane</p><h2>Security posture</h2></div></div><div className="posture-score"><div className="ring"><span>100</span><small>/100</small></div><div><b>Controls enforced</b><p>All active checks passing</p></div></div><div className="control-list"><div><span>Token issuer</span><b>Verified</b></div><div><span>PKCE flow</span><b>Required</b></div><div><span>Direct object access</span><b>Blocked</b></div><div><span>Grant TTL</span><b>60 sec</b></div></div><p className="side-note">This local lab does not mutate cloud storage, production identity, or external resources.</p></aside></section>
      {canAudit && <section className="audit-panel"><div className="panel-heading"><div><p className="eyebrow">Security evidence</p><h2>Audit chain <span className={chainValid ? 'verified' : 'invalid'}>{chainValid ? '● VERIFIED' : '● CHECKING'}</span></h2></div><span className="audit-count">{audits.length} events</span></div><div className="audit-list">{audits.length === 0 ? <p className="empty-audit">Security actions will appear here with a linked integrity hash.</p> : audits.slice().reverse().map((event) => <div className="audit-row" key={event.id}><span className={`audit-decision ${event.decision}`}>{event.decision === 'allowed' ? 'ALLOW' : 'DENY'}</span><b>{event.action}</b><span>{event.resourceType} · {event.resourceId.slice(0, 8)}</span><time>{formatTime(event.at)}</time><code>{event.hash.slice(0, 14)}…</code></div>)}</div></section>}
    </>}</main><footer><span>ZeroShare local security lab</span><span>Demo provider · Encrypted filesystem adapter · Audit evidence</span></footer></div>
}

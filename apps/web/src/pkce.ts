const toBase64Url = (buffer: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export function createVerifier() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return toBase64Url(bytes.buffer)
}

export async function createChallenge(verifier: string) {
  return toBase64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
}

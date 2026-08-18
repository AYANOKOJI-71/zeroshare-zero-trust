CREATE TABLE users (
  id UUID PRIMARY KEY,
  oidc_subject TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('security-owner', 'project-member', 'external-recipient')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE files (
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  object_key TEXT UNIQUE NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  bytes BIGINT NOT NULL CHECK (bytes > 0),
  classification TEXT NOT NULL CHECK (classification IN ('confidential', 'internal')),
  encrypted_data_key BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  auth_tag BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE shares (
  id UUID PRIMARY KEY,
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES users(id),
  created_by UUID NOT NULL REFERENCES users(id),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CHECK (recipient_id <> created_by)
);

CREATE TABLE audit_events (
  id UUID PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  actor_id UUID NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id UUID NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'denied')),
  details JSONB NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT UNIQUE NOT NULL
);

CREATE INDEX shares_active_policy ON shares (file_id, recipient_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX audit_events_resource ON audit_events (resource_type, resource_id, occurred_at DESC);

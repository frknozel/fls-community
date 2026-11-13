-- Public trust anchor, scoped to one backup destination. Existing secrets/jobs stay unchanged.
ALTER TABLE archive_destinations
 ADD COLUMN IF NOT EXISTS tls_trust_pem TEXT NOT NULL DEFAULT '';

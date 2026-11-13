-- Observations belong to a target revision. No credentials or archived data change.
ALTER TABLE archive_destinations
 ADD COLUMN IF NOT EXISTS tls_peer_pem TEXT NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS tls_peer_revision INT UNSIGNED NULL,
 ADD COLUMN IF NOT EXISTS tls_peer_checked_at DATETIME(6) NULL,
 ADD COLUMN IF NOT EXISTS tls_peer_verified_at DATETIME(6) NULL,
 ADD COLUMN IF NOT EXISTS tls_peer_check_code VARCHAR(64) NOT NULL DEFAULT '';

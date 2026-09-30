// Package schemahistory holds the relay's schema as each kept version
// wrote it, so that a test can build a database the way an older relay
// did. It is strings and nothing else: no code, no SQL call, no file.
//
// Each constant is pasted from git, never derived from the tree's
// constants, since a text derived from today's tables builds today's
// database and calls it an old one. A version the relay carries forward
// has a constant here, added in the same commit as its step; raising the
// floor removes the constants below it.
package schemahistory

// SchemaAt11 is the schema of version 11, the `schema` constant of
// internal/relay/store.go at 3ceea62 with its table constants inlined.
// It is what the production relay's v0.0.0-20260923032722-a5fdd9dd92fd
// wrote, whose tables are 3ceea62's.
const SchemaAt11 = `
CREATE TABLE IF NOT EXISTS mailboxes (
	fp              TEXT PRIMARY KEY,
	bundle          BLOB NOT NULL,
	name            TEXT NOT NULL,
	created         TEXT NOT NULL,
	queued_messages INTEGER NOT NULL DEFAULT 0,
	queued_bytes    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	size     INTEGER NOT NULL,
	kind     TEXT NOT NULL DEFAULT 'envelope',
	channel  TEXT NOT NULL DEFAULT 'default',
	knocker  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_fp, id);
CREATE INDEX IF NOT EXISTS messages_knocker ON messages(to_fp, kind, knocker);
CREATE TABLE IF NOT EXISTS nonces (
	nonce   TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires ON nonces(expires);
CREATE TABLE IF NOT EXISTS relay_stats (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	queued_messages INTEGER NOT NULL,
	queued_bytes    INTEGER NOT NULL
);
INSERT OR IGNORE INTO relay_stats (id, queued_messages, queued_bytes) VALUES (1, 0, 0);
CREATE TABLE IF NOT EXISTS tokens (
	id            TEXT PRIMARY KEY,
	issuer        TEXT NOT NULL,
	use           TEXT NOT NULL,
	relay         TEXT NOT NULL,
	subject       TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL,
	not_before    INTEGER NOT NULL,
	not_after     INTEGER NOT NULL,
	uses          INTEGER NOT NULL,
	uses_left     INTEGER NOT NULL,
	revoked       INTEGER NOT NULL DEFAULT 0,
	created       TEXT NOT NULL,
	last_redeemed TEXT
);
CREATE INDEX IF NOT EXISTS tokens_not_after ON tokens(not_after);
CREATE TABLE IF NOT EXISTS blocks (
	fp      TEXT PRIMARY KEY,
	reason  TEXT NOT NULL,
	created TEXT NOT NULL,
	by_fp   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS uploads (
	id       TEXT PRIMARY KEY,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	from_fp  TEXT NOT NULL,
	size     INTEGER NOT NULL,
	received INTEGER NOT NULL DEFAULT 0,
	created  TEXT NOT NULL,
	expires  INTEGER NOT NULL,
	channel  TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS uploads_expires ON uploads(expires);
CREATE INDEX IF NOT EXISTS uploads_from_fp ON uploads(from_fp);
CREATE TABLE IF NOT EXISTS certs (
	serial     TEXT PRIMARY KEY,
	fp         TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	spki       TEXT NOT NULL,
	label      TEXT NOT NULL,
	not_before INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	created    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS certs_fp ON certs(fp, not_after);
CREATE TABLE IF NOT EXISTS directories (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
	fp          TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	description TEXT NOT NULL,
	not_before  TEXT,
	not_after   TEXT,
	position    INTEGER NOT NULL,
	PRIMARY KEY (fp, name)
);
CREATE TABLE IF NOT EXISTS allowlists (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	count  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cards (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	listed INTEGER NOT NULL,
	knocks INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cards_listed ON cards(listed, fp);`

// SchemaAt12 is the schema of version 12 as it was first written, the
// `schema` constant of internal/relay/store.go at 23ef264 with its table
// constants inlined. Two later commits added an index each to outbound
// without a new version, outbound_purge at e8ca901 and outbound_share at
// 766a345, so a version 12 file has three, four or five indexes on that
// table by the build that made it; this is the three.
const SchemaAt12 = `
CREATE TABLE IF NOT EXISTS mailboxes (
	fp              TEXT PRIMARY KEY,
	bundle          BLOB NOT NULL,
	name            TEXT NOT NULL,
	created         TEXT NOT NULL,
	queued_messages INTEGER NOT NULL DEFAULT 0,
	queued_bytes    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	size     INTEGER NOT NULL,
	kind     TEXT NOT NULL DEFAULT 'envelope',
	channel  TEXT NOT NULL DEFAULT 'default',
	knocker  TEXT NOT NULL DEFAULT '',
	-- via is the relays a message came through, in the order it came, each
	-- name the one written by the relay that wrote it, joined by '!' as a
	-- name cannot hold one. Empty for mail posted straight into this
	-- mailbox, which is all of it until a relay delivers what it carried;
	-- the column is here because the schema is one text and one version,
	-- and what writes it is the delivery two commits from this one.
	via      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_fp, id);
CREATE INDEX IF NOT EXISTS messages_knocker ON messages(to_fp, kind, knocker);
CREATE TABLE IF NOT EXISTS nonces (
	nonce   TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires ON nonces(expires);
CREATE TABLE IF NOT EXISTS relay_stats (
	id                INTEGER PRIMARY KEY CHECK (id = 1),
	queued_messages   INTEGER NOT NULL,
	queued_bytes      INTEGER NOT NULL,
	outbound_messages INTEGER NOT NULL DEFAULT 0,
	outbound_bytes    INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO relay_stats (id, queued_messages, queued_bytes) VALUES (1, 0, 0);
CREATE TABLE IF NOT EXISTS tokens (
	id            TEXT PRIMARY KEY,
	issuer        TEXT NOT NULL,
	use           TEXT NOT NULL,
	relay         TEXT NOT NULL,
	subject       TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL,
	not_before    INTEGER NOT NULL,
	not_after     INTEGER NOT NULL,
	uses          INTEGER NOT NULL,
	uses_left     INTEGER NOT NULL,
	revoked       INTEGER NOT NULL DEFAULT 0,
	created       TEXT NOT NULL,
	last_redeemed TEXT
);
CREATE INDEX IF NOT EXISTS tokens_not_after ON tokens(not_after);
CREATE TABLE IF NOT EXISTS blocks (
	fp      TEXT PRIMARY KEY,
	reason  TEXT NOT NULL,
	created TEXT NOT NULL,
	by_fp   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS uploads (
	id       TEXT PRIMARY KEY,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	from_fp  TEXT NOT NULL,
	size     INTEGER NOT NULL,
	received INTEGER NOT NULL DEFAULT 0,
	created  TEXT NOT NULL,
	expires  INTEGER NOT NULL,
	channel  TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS uploads_expires ON uploads(expires);
CREATE INDEX IF NOT EXISTS uploads_from_fp ON uploads(from_fp);
CREATE TABLE IF NOT EXISTS certs (
	serial     TEXT PRIMARY KEY,
	fp         TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	spki       TEXT NOT NULL,
	label      TEXT NOT NULL,
	not_before INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0,
	revoked_by TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	created    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS certs_fp ON certs(fp, not_after);
CREATE TABLE IF NOT EXISTS directories (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
	fp          TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	description TEXT NOT NULL,
	not_before  TEXT,
	not_after   TEXT,
	position    INTEGER NOT NULL,
	PRIMARY KEY (fp, name)
);
CREATE TABLE IF NOT EXISTS allowlists (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	count  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cards (
	fp     TEXT PRIMARY KEY REFERENCES mailboxes(fp) ON DELETE CASCADE,
	doc    BLOB NOT NULL,
	sig    BLOB NOT NULL,
	issued TEXT NOT NULL,
	listed INTEGER NOT NULL,
	knocks INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cards_listed ON cards(listed, fp);
CREATE TABLE IF NOT EXISTS outbound (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	poster_fp TEXT NOT NULL,
	neighbour TEXT NOT NULL,
	path      TEXT NOT NULL DEFAULT '',
	via       TEXT NOT NULL DEFAULT '',
	to_fp     TEXT NOT NULL DEFAULT '',
	hash      TEXT NOT NULL,
	size      INTEGER NOT NULL,
	kind      TEXT NOT NULL DEFAULT 'envelope',
	received  INTEGER NOT NULL,
	state     TEXT NOT NULL DEFAULT 'waiting',
	tries     INTEGER NOT NULL DEFAULT 0,
	last_try  INTEGER NOT NULL DEFAULT 0,
	next_try  INTEGER NOT NULL DEFAULT 0,
	gives_up  INTEGER NOT NULL,
	their_id  INTEGER NOT NULL DEFAULT 0,
	code      TEXT NOT NULL DEFAULT '',
	said      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS outbound_work ON outbound(neighbour, state, next_try);
CREATE INDEX IF NOT EXISTS outbound_poster ON outbound(poster_fp, id);
CREATE INDEX IF NOT EXISTS outbound_handed ON outbound(neighbour, their_id);
CREATE TABLE IF NOT EXISTS carried (
	hash    TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS carried_expires ON carried(expires);`

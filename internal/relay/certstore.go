package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// Failures the certificate routes tell apart.
var (
	// ErrNoCert means the serial is not one this relay issued, or is one it
	// has since forgotten.
	ErrNoCert = errors.New("relay: certificate is not known to this relay")
	// ErrCertRevoked means an administrator, or a renewal, withdrew it.
	ErrCertRevoked = errors.New("relay: certificate is revoked")
	// ErrCertExpired means it is past its not_after.
	ErrCertExpired = errors.New("relay: certificate has expired")
)

// CertRow is one issued client certificate as the relay stores it. The
// certificate itself is not kept: the machine holds that, and the relay needs
// only enough to recognise and revoke it.
type CertRow struct {
	Serial    string
	FP        string
	SPKI      string
	Label     string
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
	RevokedBy string
	Reason    string
	Created   time.Time
}

// View renders a row for the wire.
func (c CertRow) View(current bool) relayapi.CertRecord {
	return relayapi.CertRecord{
		Serial:    c.Serial,
		FP:        c.FP,
		Label:     c.Label,
		SPKI:      c.SPKI,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Revoked:   c.Revoked,
		Reason:    c.Reason,
		Current:   current,
	}
}

// NewCertRow turns a freshly issued certificate into the row that records it.
func NewCertRow(issued *clientca.Issued, fp string, now time.Time) CertRow {
	return CertRow{
		Serial:    issued.Serial,
		FP:        fp,
		SPKI:      issued.SPKI,
		Label:     issued.Label,
		NotBefore: issued.NotBefore,
		NotAfter:  issued.NotAfter,
		Created:   now,
	}
}

// insertCert writes one certificate row inside the caller's transaction.
func insertCert(tx *sql.Tx, c CertRow) error {
	_, err := tx.Exec(`
		INSERT INTO certs (serial, fp, spki, label, not_before, not_after, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.Serial, c.FP, c.SPKI, c.Label,
		c.NotBefore.Unix(), c.NotAfter.Unix(), c.Created.UTC().Format(time.RFC3339))
	return err
}

// CertBySerial looks one certificate up. It is on the path of every
// authenticated request, so it is one indexed read by primary key and returns
// only what the check needs.
func (s *Store) CertBySerial(serial string) (*CertRow, error) {
	var c CertRow
	var notBefore, notAfter int64
	var revoked int
	var created string
	err := s.db.QueryRow(`
		SELECT serial, fp, spki, label, not_before, not_after, revoked, revoked_by, reason, created
		FROM certs WHERE serial = ?`, serial).
		Scan(&c.Serial, &c.FP, &c.SPKI, &c.Label, &notBefore, &notAfter,
			&revoked, &c.RevokedBy, &c.Reason, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoCert
	}
	if err != nil {
		return nil, err
	}
	c.NotBefore = time.Unix(notBefore, 0)
	c.NotAfter = time.Unix(notAfter, 0)
	c.Revoked = revoked != 0
	c.Created, _ = time.Parse(time.RFC3339, created)
	return &c, nil
}

// LiveCert resolves a serial and applies the two conditions that make a
// certificate usable: not revoked, and not expired.
//
// The clock is the caller's, and the caller passes the real one. A
// certificate's validity is an agreement with the machine holding it, not
// something the relay's tests may bend.
func (s *Store) LiveCert(serial string, now time.Time) (*CertRow, error) {
	c, err := s.CertBySerial(serial)
	if err != nil {
		return nil, err
	}
	if c.Revoked {
		return nil, ErrCertRevoked
	}
	if now.After(c.NotAfter) {
		return nil, ErrCertExpired
	}
	return c, nil
}

// Certs lists the certificates of one identity, newest first. With all false
// only live ones are returned.
func (s *Store) Certs(fp string, all bool, now time.Time) ([]CertRow, error) {
	query := `
		SELECT serial, fp, spki, label, not_before, not_after, revoked, revoked_by, reason, created
		FROM certs WHERE fp = ?`
	args := []any{fp}
	if !all {
		query += ` AND revoked = 0 AND not_after >= ?`
		args = append(args, now.Unix())
	}
	query += ` ORDER BY not_before DESC, serial DESC`
	return s.certRows(query, args...)
}

// AllCerts lists every certificate on the relay, for an administrator.
func (s *Store) AllCerts(all bool, now time.Time) ([]CertRow, error) {
	query := `
		SELECT serial, fp, spki, label, not_before, not_after, revoked, revoked_by, reason, created
		FROM certs`
	var args []any
	if !all {
		query += ` WHERE revoked = 0 AND not_after >= ?`
		args = append(args, now.Unix())
	}
	query += ` ORDER BY not_before DESC, serial DESC`
	return s.certRows(query, args...)
}

func (s *Store) certRows(query string, args ...any) ([]CertRow, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRow
	for rows.Next() {
		var c CertRow
		var notBefore, notAfter int64
		var revoked int
		var created string
		if err := rows.Scan(&c.Serial, &c.FP, &c.SPKI, &c.Label, &notBefore, &notAfter,
			&revoked, &c.RevokedBy, &c.Reason, &created); err != nil {
			return nil, err
		}
		c.NotBefore = time.Unix(notBefore, 0)
		c.NotAfter = time.Unix(notAfter, 0)
		c.Revoked = revoked != 0
		c.Created, _ = time.Parse(time.RFC3339, created)
		out = append(out, c)
	}
	return out, rows.Err()
}

// RenewCert records a new certificate and retires the one the request arrived
// with, in one transaction.
//
// Both halves together or neither: a machine that ended up with two live
// certificates, or with none, would be a support problem the relay cannot see.
func (s *Store) RenewCert(fp, oldSerial string, row CertRow, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE fp = ?`, fp).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNoMailbox
	}
	if err := insertCert(tx, row); err != nil {
		return err
	}
	if oldSerial != "" {
		if _, err := tx.Exec(
			`UPDATE certs SET revoked = 1, revoked_by = ?, reason = ? WHERE serial = ? AND revoked = 0`,
			fp, reasonRenewed, oldSerial); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// reasonRenewed is written on a certificate a renewal replaced, so an
// administrator reading the list can tell one from a revocation they ordered.
const reasonRenewed = "renewed"

// RevokeCert withdraws one certificate. It reports false when the serial is
// unknown or was already revoked, which the handler answers 404 to: revoking
// twice is not an error, but it is not a change either.
func (s *Store) RevokeCert(serial, byFP, reason string, now time.Time) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE certs SET revoked = 1, revoked_by = ?, reason = ? WHERE serial = ? AND revoked = 0`,
		byFP, reason, serial)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// PurgeCerts removes rows that have been dead, by revocation or expiry, for
// longer than the retention. It runs from the same housekeeping pass as the
// nonce and token purges.
func (s *Store) PurgeCerts(before time.Time) error {
	_, err := s.db.Exec(
		`DELETE FROM certs WHERE not_after < ? AND (revoked = 1 OR not_after < ?)`,
		before.Unix(), before.Unix())
	if err != nil {
		return fmt.Errorf("relay: purging certificates: %w", err)
	}
	return nil
}

// LiveCerts counts the certificates an administrator would call current.
func (s *Store) LiveCerts(now time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM certs WHERE revoked = 0 AND not_after >= ?`, now.Unix()).Scan(&n)
	return n, err
}

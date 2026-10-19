package main

import (
	"crypto/tls"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
)

// loadKeyPair reads a certificate and key from disk.
func loadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// clientCertParts is what a bundle gives the relay: the policy the server
// package needs, and the certificate source for its own listener.
type clientCertParts struct {
	policy *relay.ClientCertPolicy
	server *clientca.Server
	loaded *pki.Loaded
}

// openBundle reads an auu-ca bundle and builds everything derived from it.
//
// Everything is checked here, at startup, with the path in the message: a
// relay that cannot serve or cannot issue should say so now rather than at
// the first handshake.
func openBundle(cfg Config) (*clientCertParts, error) {
	path, ok, err := cfg.BundlePath()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	loaded, err := pki.LoadBundle(path)
	if err != nil {
		return nil, err
	}
	server, err := clientca.NewServer(loaded, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	parts := &clientCertParts{server: server, loaded: loaded}
	if cfg.ClientCerts.Required() {
		lifetime, err := cfg.ClientCerts.ParsedLifetime()
		if err != nil {
			return nil, err
		}
		parts.policy = &relay.ClientCertPolicy{
			Issuer:   clientca.NewIssuer(loaded),
			Verifier: clientca.NewVerifier(loaded),
			Lifetime: lifetime,
		}
	}
	return parts, nil
}

// buildTLS turns a validated configuration into the TLS config for the
// listener. It is nil in mode off, which is plain HTTP for a relay on a
// private network or a test.
//
// There is no ACME arm: a relay's certificate comes from its own authority,
// which is what frees it from ports 80 and 443.
func buildTLS(cfg Config, parts *clientCertParts) (*tls.Config, error) {
	switch cfg.TLS.Mode {
	case ModeOff:
		return nil, nil

	case ModeFiles:
		// TLS 1.3 and the hybrid post-quantum key exchange, on both
		// branches and with no way to relax it: every client is built from
		// this tree, and a recording of who talked to whom made today is
		// then protected by the same hybrid as the messages. A relay run in
		// mode off behind somebody else's terminator is that terminator's
		// business, and docs/relay.md says so.
		out := &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			// HTTP/1.1 alone by ALPN; newHTTPServer says why h2 is off.
			NextProtos: []string{"http/1.1"},
		}
		if parts != nil {
			// The relay mints its own leaf and renews it in process, so the
			// certificate comes from a function rather than a field.
			out.GetCertificate = parts.server.GetCertificate
		} else {
			cert, err := loadKeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading certificate and key: %w", err)
			}
			out.Certificates = []tls.Certificate{cert}
		}
		if parts != nil && parts.policy != nil {
			parts.policy.Verifier.TLSConfig(out)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unknown tls mode %q", cfg.TLS.Mode)
	}
}

// renewLeaf keeps the relay's own certificate fresh. It is short-lived by
// design — the relay mints it itself, so there is no reason for it not to be
// — and a renewal takes over between one handshake and the next.
//
// It is also where the relay repeats, once a day, the one warning that
// matters operationally: a signing intermediate is the thing an operator has
// to make a trip to the offline machine for, a relay runs for longer than
// anyone remembers its startup log, and the leaf renewal is the first thing
// that fails when it expires.
func renewLeaf(parts *clientCertParts, log logger, stop <-chan struct{}) {
	if parts == nil {
		return
	}
	t := time.NewTicker(leafCheckEvery)
	defer t.Stop()
	var lastWarned time.Time
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			leafCheck(parts, log, time.Now(), &lastWarned)
		}
	}
}

// leafCheck is one tick of renewLeaf, and a fault in it ends that check and
// not the relay (S59): the goroutine is outside every HTTP handler, so a
// panic here would end the process. It is said once, with its stack, and
// the next check runs at its time.
func leafCheck(parts *clientCertParts, log logger, now time.Time, lastWarned *time.Time) {
	defer func() {
		if v := recover(); v != nil {
			log.Error("a check of this relay's certificate ended with a fault; the next runs at its time",
				"fault", fmt.Sprint(v), "stack", string(debug.Stack()))
		}
	}()
	renewed, err := renewStep(parts, now)
	switch {
	case err != nil:
		log.Error("could not renew this relay's certificate", "err", err)
	case renewed:
		log.Info("renewed this relay's certificate",
			"expires", parts.server.NotAfter().Format(time.DateOnly))
	}
	if now.Sub(*lastWarned) >= intermediateWarnEvery {
		*lastWarned = now
		for _, w := range intermediateWarnings(parts, now) {
			log.Warn(w.msg, "expires", w.when.Format(time.DateOnly))
		}
	}
}

// leafCheckEvery and renewStep are renewLeaf's interval and its renewal,
// variables so a test can tick it quickly and plant a fault in it.
var (
	leafCheckEvery = leafCheckInterval
	renewStep      = func(parts *clientCertParts, now time.Time) (bool, error) {
		return parts.server.RenewIfDue(now, leafRenewBefore)
	}
)

// expiryWarning is one signing intermediate near the end of its life.
type expiryWarning struct {
	msg  string
	when time.Time
}

// intermediateWarnings is what an operator has to hear before a trip to the
// offline machine becomes urgent: each signing intermediate within
// intermediateWarnBefore of expiry, and each already past it.
func intermediateWarnings(parts *clientCertParts, now time.Time) []expiryWarning {
	var out []expiryWarning
	for _, w := range []struct {
		what string
		when time.Time
	}{
		{"server signing intermediate", parts.server.IntermediateNotAfter()},
		{"client signing intermediate", parts.loaded.ClientInt.Cert.NotAfter},
	} {
		switch {
		case now.After(w.when):
			out = append(out, expiryWarning{"this relay's " + w.what + " has expired; " +
				"run 'auu-ca relay' on the offline machine and replace the bundle", w.when})
		case w.when.Sub(now) < intermediateWarnBefore:
			out = append(out, expiryWarning{"this relay's " + w.what + " expires soon; " +
				"run 'auu-ca relay' on the offline machine and replace the bundle", w.when})
		}
	}
	return out
}

// logger is what renewLeaf needs, so a test can pass its own.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

const (
	// leafRenewBefore is how much of the relay's own certificate must remain
	// before it is replaced.
	leafRenewBefore = 10 * 24 * time.Hour
	// leafCheckInterval is how often that is looked at.
	leafCheckInterval = time.Hour
	// intermediateWarnBefore is how close to expiry a signing intermediate
	// is before the relay starts saying so.
	intermediateWarnBefore = 60 * 24 * time.Hour
	// intermediateWarnEvery is how often it repeats itself.
	intermediateWarnEvery = 24 * time.Hour
)

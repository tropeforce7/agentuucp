// Command auu-relay is the store-and-forward server for auu.
//
// It holds sealed envelopes it cannot read and enforces four things about
// them: who may create a mailbox, who may drop mail into whose, how fast, and
// how much. It mints its own short-lived TLS certificate from the signing
// bundle its authority issued it, and it is administered over its own API by
// the identities named in the file it was started with.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// flagValues holds every command-line flag. Merge reads these, but only for
// the flags the operator actually typed.
type flagValues struct {
	config      string
	printConfig bool
	version     bool

	listen      string
	db          string
	messagesDir string
	maxBytes    int64

	registration   string
	streams        bool
	maxStreamBytes int64
	publicURL      string
	adminFile      string
	tokenMaxAge    string

	clientCerts        string
	clientCertLifetime string

	tlsMode             string
	tlsCert             string
	tlsKey              string
	tlsBundle           string
	tlsBundleCredential string

	limitRequests        int64
	limitPosts           int64
	limitPostBytes       int64
	limitUnauthenticated int64
	limitRegistrations   int64
	maxMailboxes         int64
	mailboxMaxMessages   int64
	mailboxMaxBytes      int64
	relayMaxBytes        int64
	maxInflight          int64
	maxWaiting           int64
	accessLog            string
}

func registerFlags(fs *flag.FlagSet) *flagValues {
	f := &flagValues{}
	d := Defaults()

	fs.StringVar(&f.config, "config", "", "read settings from this JSON file before applying flags")
	fs.BoolVar(&f.printConfig, "print-config", false, "print the effective configuration and exit")
	fs.BoolVar(&f.version, "version", false, "print the version this binary was built from, and the schema it speaks")

	fs.StringVar(&f.listen, "listen", d.Listen, "address to listen on")
	fs.StringVar(&f.db, "db", d.DB, "path to the SQLite database")
	fs.StringVar(&f.messagesDir, "messages-dir", "",
		"directory holding one file per stored message (default: alongside the database)")
	fs.Int64Var(&f.maxBytes, "max-bytes", d.MaxBytes, "largest accepted envelope, in bytes")
	fs.StringVar(&f.registration, "registration", d.Registration,
		"who may create a mailbox: open, token, or closed")
	fs.BoolVar(&f.streams, "streams", d.Streams, "accept chunked stream uploads for large messages")
	fs.Int64Var(&f.maxStreamBytes, "max-stream-bytes", d.MaxStreamBytes,
		"largest stream this relay will accept (0: unlimited)")
	fs.StringVar(&f.publicURL, "public-url", "",
		"the URL users reach this relay at; enrolment tokens must name it")
	fs.StringVar(&f.adminFile, "admin-file", "",
		"file of export lines, one per administrator; without it this relay has no administrators")
	fs.StringVar(&f.tokenMaxAge, "token-max-age", d.Admin.TokenMaxAge,
		"longest lifetime an enrolment token may be registered with")

	fs.StringVar(&f.clientCerts, "client-certs", "",
		"off or required: issue a certificate to each machine and require one (default: off)")
	fs.StringVar(&f.clientCertLifetime, "client-cert-lifetime", "",
		"how long an issued client certificate lives")

	fs.StringVar(&f.tlsMode, "tls-mode", "", "off or files (default files)")
	fs.StringVar(&f.tlsCert, "tls-cert", "", "TLS certificate file (requires --tls-key)")
	fs.StringVar(&f.tlsKey, "tls-key", "", "TLS key file (requires --tls-cert)")
	fs.StringVar(&f.tlsBundle, "tls-bundle", "",
		"an auu-ca bundle: this relay's signing intermediates and its trust anchor")
	fs.StringVar(&f.tlsBundleCredential, "tls-bundle-credential", "",
		"the same bundle as a systemd credential of this name, read from $CREDENTIALS_DIRECTORY")

	// Zero switches a limit off, everywhere.
	fs.Int64Var(&f.limitRequests, "limit-requests", d.Limits.RequestsPerMinute,
		"authenticated requests a minute, per identity (0: unlimited)")
	fs.Int64Var(&f.limitPosts, "limit-posts", d.Limits.PostsPerMinute,
		"posts a minute, per identity (0: unlimited)")
	fs.Int64Var(&f.limitPostBytes, "limit-post-bytes", d.Limits.PostBytesPerHour,
		"posted bytes an hour, per identity (0: unlimited)")
	fs.Int64Var(&f.limitUnauthenticated, "limit-unauthenticated", d.Limits.UnauthenticatedPerMinute,
		"registrations, key lookups and failed authentications a minute, per source address (0: unlimited)")
	fs.Int64Var(&f.limitRegistrations, "limit-registrations", d.Limits.RegistrationsPerHour,
		"registrations an hour, per source address (0: unlimited)")
	fs.Int64Var(&f.maxMailboxes, "max-mailboxes", d.Limits.MaxMailboxes,
		"most mailboxes this relay will hold (0: unlimited)")
	fs.Int64Var(&f.mailboxMaxMessages, "mailbox-max-messages", d.Limits.MailboxMaxMessages,
		"most messages queued for one recipient (0: unlimited)")
	fs.Int64Var(&f.mailboxMaxBytes, "mailbox-max-bytes", d.Limits.MailboxMaxBytes,
		"most queued bytes for one recipient (0: unlimited)")
	fs.Int64Var(&f.relayMaxBytes, "relay-max-bytes", d.Limits.RelayMaxBytes,
		"most queued bytes across the whole relay (0: unlimited)")
	fs.Int64Var(&f.maxInflight, "max-inflight", d.Limits.MaxInflight,
		"requests handled at once before answering 503 (0: unlimited)")
	fs.Int64Var(&f.maxWaiting, "max-waiting", d.Limits.MaxWaiting,
		"listings held open at once before the next is answered without a hold (0: unlimited)")
	fs.StringVar(&f.accessLog, "access-log", d.AccessLog,
		"full, or minimal to log the route instead of the path and omit the caller")
	return f
}

// resolveConfig merges every source in precedence order and validates the
// result: defaults, then the config file, then the flags that were typed.
func resolveConfig(fs *flag.FlagSet, f *flagValues) (Config, string, error) {
	cfg, warning, err := Load(f.config)
	if err != nil {
		return cfg, warning, err
	}
	cfg.Merge(fs, f)
	cfg.Resolve()
	if err := cfg.Validate(); err != nil {
		return cfg, warning, err
	}
	return cfg, warning, nil
}

func main() {
	fs := flag.NewFlagSet("auu-relay", flag.ExitOnError)
	f := registerFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	// Before the settings are resolved: what a binary is, and what schema
	// it speaks, is a question an operator asks of a binary they have been
	// handed, with no configuration anywhere near it.
	if f.version {
		fmt.Printf("auu-relay %s (schema %d)\n", buildinfo.Version(), relay.SchemaVersion)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, warning, err := resolveConfig(fs, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auu-relay: "+err.Error())
		os.Exit(1)
	}

	if f.printConfig {
		if err := Encode(os.Stdout, cfg.Redacted()); err != nil {
			fmt.Fprintln(os.Stderr, "auu-relay: "+err.Error())
			os.Exit(1)
		}
		return
	}

	if warning != "" {
		log.Warn(warning)
	}
	if err := run(cfg, log); err != nil {
		log.Error("relay failed", "err", err)
		os.Exit(1)
	}
}

func run(cfg Config, log *slog.Logger) error {
	store, err := relay.OpenStore(cfg.DB, cfg.MessagesDir)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	if err := store.PurgeNonces(time.Now()); err != nil {
		log.Warn("initial nonce purge failed", "err", err)
	}
	if from := store.MigratedFrom(); from > 0 {
		log.Info("database migrated", "from", from, "to", relay.SchemaVersion)
	}
	if n := store.Reconciled(); n > 0 {
		log.Warn("queued message counters did not match the stored messages and have been recomputed",
			"mailboxes", n)
	}
	if swept := store.Swept(); !swept.Empty() {
		log.Warn("the message directory did not match the database and has been reconciled",
			"unfinished_writes", swept.Temp, "files_without_rows", swept.Orphans,
			"rows_without_files", swept.Missing)
	}

	// The bundle, before anything is served: a relay that cannot read its own
	// authority must fail at startup with the path in the message, not at the
	// first handshake or the first enrolment.
	parts, err := openBundle(cfg)
	if err != nil {
		return err
	}
	certLifetime, err := cfg.ClientCerts.ParsedLifetime()
	if err != nil {
		return err
	}
	rcfg, err := relayConfig(cfg, parts, log)
	if err != nil {
		return err
	}
	tlsCfg, err := buildTLS(cfg, parts)
	if err != nil {
		return err
	}

	handler := relay.NewServer(store, rcfg)
	srv := newHTTPServer(cfg.Listen, handler, tlsCfg, DefaultTimeouts())

	logStartup(cfg, rcfg.Admins, log)
	logClientCerts(parts, certLifetime, log)

	errCh := make(chan error, 2)
	go func() {
		var err error
		if cfg.TLS.Mode == ModeOff {
			err = srv.ListenAndServe()
		} else {
			// Empty file names: the certificate comes from TLSConfig, either
			// a loaded pair or the leaf this relay minted itself.
			err = srv.ListenAndServeTLS("", "")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("tls listener: %w", err)
		}
	}()

	// The relay's own certificate is short-lived and renewed in process, so
	// a long-running relay never needs a restart for it.
	renewStop := make(chan struct{})
	defer close(renewStop)
	go renewLeaf(parts, log, renewStop)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	}

	if err := stopServing(handler, srv, shutdownGrace); err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

// shutdownGrace is how long a stopping relay waits for the requests in
// flight to finish before the process ends anyway.
const shutdownGrace = 20 * time.Second

// stopServing ends the relay: every listing held open is answered first, with
// what it has, and only then does the listener drain what is in flight.
// A hold can be a minute long against twenty seconds of grace, so a
// shutdown that waited on one would end with the hold cut off and the
// drain reported as a failure; answered first, it is one more request
// that finished.
func stopServing(handler *relay.Server, srv *http.Server, grace time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	handler.Close()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("tls listener did not drain: %w", err)
	}
	return nil
}

// Timeouts bound how long one connection may occupy the relay.
//
// They are the only defence against a caller that declares a large body and
// then dribbles it: the handler blocks reading, holding a goroutine and an
// in-flight slot, until one of these fires. They are a struct so a test can
// use short ones.
type Timeouts struct {
	ReadHeader time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
}

// DefaultTimeouts is what the relay runs with.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		ReadHeader: 15 * time.Second,
		Read:       5 * time.Minute,
		Write:      5 * time.Minute,
		Idle:       2 * time.Minute,
	}
}

// newHTTPServer builds the relay's listener. Extracted from run so that the
// timeouts, which are a security property and not a detail, can be tested.
func newHTTPServer(addr string, h http.Handler, tlsCfg *tls.Config, t Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
	}
}

// relayConfig is what the relay package is given, built from the settings
// and the bundle. It is its own function so a test can build the shipped
// template's configuration and prove the routes a machine needs are open.
func relayConfig(cfg Config, parts *clientCertParts, log *slog.Logger) (relay.Config, error) {
	tokenMaxAge, err := cfg.TokenMaxAge()
	if err != nil {
		return relay.Config{}, err
	}
	var clientCerts *relay.ClientCertPolicy
	var anchor *x509.Certificate
	if parts != nil {
		clientCerts = parts.policy
		// The anchor is what a machine pins. It is handed to the relay
		// whether or not client certificates are required, because the
		// relay's own certificate is under it either way.
		anchor = parts.loaded.Anchor
	}
	// The administrators are loaded here, once, and the relay is handed the
	// set: what start logs is what the first request is served from, and a
	// file that goes missing between the two loses nobody their access.
	var admins *relay.Admins
	if cfg.Admin.AuthorizedFile != "" {
		if admins, err = relay.LoadAdmins(cfg.Admin.AuthorizedFile); err != nil {
			return relay.Config{}, err
		}
	}
	return relay.Config{
		MaxBytes:       cfg.MaxBytes,
		Registration:   cfg.Registration,
		PublicURL:      cfg.PublicURL,
		AdminFile:      cfg.Admin.AuthorizedFile,
		Admins:         admins,
		TokenMaxAge:    tokenMaxAge,
		ClientCerts:    clientCerts,
		TrustAnchor:    anchor,
		Streams:        cfg.Streams,
		MaxStreamBytes: cfg.MaxStreamBytes,
		Logger:         log,
		Limits:         cfg.Limits.Relay(),
		AccessLog:      cfg.AccessLog,
	}, nil
}

// portMismatch says when public_url names a port this relay does not listen
// on. Tokens name public_url and machines connect to it, so unless something
// forwards that port to this one nobody can enrol.
func portMismatch(cfg Config) string {
	if cfg.PublicURL == "" {
		return ""
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return ""
	}
	public := u.Port()
	if public == "" {
		switch u.Scheme {
		case "https":
			public = "443"
		case "http":
			public = "80"
		default:
			return ""
		}
	}
	_, listen, err := net.SplitHostPort(cfg.Listen)
	if err != nil || listen == "" || listen == public {
		return ""
	}
	return fmt.Sprintf("public_url %s names port %s but this relay listens on port %s; "+
		"tokens name public_url and machines connect to it, so unless something forwards "+
		"port %s to port %s nobody can enrol", cfg.PublicURL, public, listen, public, listen)
}

// logClientCerts says what an operator needs to know about the authority this
// relay was issued from: which anchor, and when the two things they have to
// make a trip to the offline machine for expire.
func logClientCerts(parts *clientCertParts, lifetime time.Duration, log *slog.Logger) {
	if parts == nil {
		return
	}
	log.Info("serving from an auu-ca bundle",
		"anchor", parts.loaded.AnchorSPKI[:16],
		"hosts", strings.Join(parts.loaded.Hosts, ","),
		"own_cert_expires", parts.server.NotAfter().Format(time.DateOnly),
		"mldsa", pki.ParameterNumberOf(parts.loaded.Params))
	if parts.policy != nil {
		log.Info("client certificates required", "cert_lifetime", lifetime.String())
	}
	for _, w := range intermediateWarnings(parts, time.Now()) {
		log.Warn(w.msg, "expires", w.when.Format(time.DateOnly))
	}
}

// logStartup states the settings once, at startup. admins is the set the
// relay was handed, so the count logged is the count served.
func logStartup(cfg Config, admins *relay.Admins, log *slog.Logger) {
	logEnrolment(cfg, admins, log)
	logLimits(cfg, log)
	switch cfg.TLS.Mode {
	case ModeOff:
		log.Info("relay starting", "addr", cfg.Listen, "tls", "off", "db", cfg.DB,
			"max_bytes", cfg.MaxBytes, "messages", cfg.MessagesDir)
		log.Warn("serving plain HTTP: for a try on one machine, not for a relay anybody reaches over a network")
	case ModeFiles:
		// Validate has already resolved the bundle, so the path here is
		// the one it loaded.
		where := cfg.TLS.CertFile
		if bundle, ok, err := cfg.BundlePath(); ok && err == nil {
			where = bundle
		}
		log.Info("relay starting", "addr", cfg.Listen, "tls", "files", "db", cfg.DB,
			"cert", where, "bundle_source", cfg.bundleSource(),
			"max_bytes", cfg.MaxBytes, "messages", cfg.MessagesDir)
	}
}

// logEnrolment states who may join and who may administer, once, at startup.
func logEnrolment(cfg Config, admins *relay.Admins, log *slog.Logger) {
	log.Info("enrolment",
		"registration", cfg.Registration,
		"public_url", orEmpty(cfg.PublicURL),
		"admin_file", orEmpty(cfg.Admin.AuthorizedFile),
		"token_max_age", cfg.Admin.TokenMaxAge,
		"streams", cfg.Streams, "max_stream_bytes", cfg.MaxStreamBytes)
	if cfg.Admin.AuthorizedFile == "" {
		log.Info("no admin file configured; this relay has no administrators and the admin API is closed")
	} else if admins != nil {
		log.Info("administrators loaded", "count", len(admins.Keys), "path", cfg.Admin.AuthorizedFile)
	}
	if cfg.Registration == relayapi.RegistrationToken && cfg.PublicURL == "" {
		log.Warn("registration is token but public_url is not set, so enrolment tokens " +
			"will not be checked against the relay they name; set --public-url")
	}
	if msg := portMismatch(cfg); msg != "" {
		log.Warn(msg)
	}
}

// logLimits states the policy once, at startup, so a later 429 in the log can
// be read against the numbers that produced it.
func logLimits(cfg Config, log *slog.Logger) {
	l := cfg.Limits
	log.Info("limits",
		"requests_per_minute", l.RequestsPerMinute,
		"posts_per_minute", l.PostsPerMinute,
		"post_bytes_per_hour", l.PostBytesPerHour,
		"unauthenticated_per_minute", l.UnauthenticatedPerMinute,
		"registrations_per_hour", l.RegistrationsPerHour,
		"max_mailboxes", l.MaxMailboxes,
		"mailbox_max_messages", l.MailboxMaxMessages,
		"mailbox_max_bytes", l.MailboxMaxBytes,
		"relay_max_bytes", l.RelayMaxBytes,
		"max_inflight", l.MaxInflight,
		"max_waiting", l.MaxWaiting,
		"access_log", cfg.AccessLog)
	if cfg.AccessLog == relay.AccessLogFull {
		log.Info("the access log records the verified caller and the request path, " +
			"so it records who is writing to whose mailbox; set access_log to minimal " +
			"on a relay shared beyond one team")
	}
}

func orNone(s string) string {
	if s == "" {
		return "(disabled)"
	}
	return s
}

func orEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

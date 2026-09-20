package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TLS modes. There is no acme: a relay's certificate comes from its own
// authority now, which is what frees it from ports 80 and 443. See
// PLAN-SELFCA.md, and auu-ca.
const (
	ModeOff   = "off"
	ModeFiles = "files"
)

const (
	cacheDirMode    fs.FileMode = 0o700
	messagesDirMode fs.FileMode = 0o700
	maxDomainLen                = 253
	maxLabelLen                 = 63

	// defaultTokenMaxAge is the longest an enrolment token may live. Thirty
	// days is long enough for a colleague to get around to joining and short
	// enough that a forgotten token stops mattering.
	defaultTokenMaxAge = 720 * time.Hour

	// defaultMaxStreamBytes caps one stream at four gigabytes. It is a
	// separate ceiling from max_bytes, which bounds one envelope and is the
	// threshold past which a stream attempt that stopped short is kept.
	defaultMaxStreamBytes int64 = 4 << 30
	// defaultCertLifetime is how long an issued client certificate lives.
	// Revocation is a row this relay reads on every request, so lifetime is
	// hygiene rather than security; a year is short enough to bound a lost
	// machine that never comes back and long enough that a sporadic user is
	// not forever asking for tokens.
	defaultCertLifetime = 365 * 24 * time.Hour
	// minCertLifetime and maxCertLifetime bound what an operator may set. A
	// certificate shorter than an hour could expire inside one command, and
	// one longer than the authority is pointless: Issue clamps it anyway.
	minCertLifetime = time.Hour
	maxCertLifetime = 10 * 365 * 24 * time.Hour

	clientCADirMode fs.FileMode = 0o700
)

// Config is the relay's complete configuration, however it was supplied. The
// JSON tags are the config file format.
type Config struct {
	Listen string `json:"listen"`
	DB     string `json:"db"`
	// MaxBytes caps one posted envelope.
	MaxBytes int64 `json:"max_bytes"`
	// MessagesDir holds one file per stored message. Empty means derive it
	// from the database path.
	MessagesDir string `json:"messages_dir"`
	// Registration is open, token, or closed.
	Registration string `json:"registration"`
	// Streams says whether the relay accepts chunked stream uploads.
	Streams bool `json:"streams"`
	// MaxStreamBytes is the largest declared stream; 0 is unlimited.
	MaxStreamBytes int64 `json:"max_stream_bytes"`
	// PublicURL is the URL users reach this relay at. It is the audience every
	// enrolment token must name, so that a token issued for one relay cannot
	// be spent on another. Empty skips that check.
	PublicURL   string            `json:"public_url"`
	TLS         TLSConfig         `json:"tls"`
	ClientCerts ClientCertsConfig `json:"client_certs"`
	Admin       AdminConfig       `json:"admin"`
	Limits      LimitsConfig      `json:"limits"`
	AccessLog   string            `json:"access_log"`
}

// ClientCertsConfig turns on mutual TLS: the relay issues a certificate to
// each machine at enrolment and requires one on every mailbox route.
type ClientCertsConfig struct {
	// Mode is off or required. There is no "optional": a mode that issued
	// and checked certificates but still admitted requests without one would
	// be a migration aid, and there is nothing deployed to migrate.
	Mode string `json:"mode"`
	// Lifetime is how long an issued certificate lives, as a Go duration.
	Lifetime string `json:"lifetime"`
}

// Required reports whether client certificates are on.
func (c ClientCertsConfig) Required() bool { return c.Mode == relayapi.ClientCertsRequired }

// ParsedLifetime is Lifetime as a duration.
func (c ClientCertsConfig) ParsedLifetime() (time.Duration, error) {
	if c.Lifetime == "" {
		return defaultCertLifetime, nil
	}
	d, err := time.ParseDuration(c.Lifetime)
	if err != nil {
		return 0, fmt.Errorf("client_certs.lifetime %q: %w", c.Lifetime, err)
	}
	return d, nil
}

// AdminConfig says who may administer this relay, and for how long the tokens
// they issue may live.
type AdminConfig struct {
	// AuthorizedFile holds export lines, one per administrator, in the same
	// format a user keeps in authorized_peers. Empty means this relay has no
	// administrators and the whole admin API answers 403.
	AuthorizedFile string `json:"authorized_file"`
	// TokenMaxAge is the longest lifetime a token may be registered with,
	// as a Go duration.
	TokenMaxAge string `json:"token_max_age"`
}

// LimitsConfig is the rate limit and quota policy as it appears in the config
// file. Zero means unlimited for every numeric key, so a private relay for
// three people can switch the whole thing off.
type LimitsConfig struct {
	RequestsPerMinute        int64 `json:"requests_per_minute"`
	PostsPerMinute           int64 `json:"posts_per_minute"`
	PostBytesPerHour         int64 `json:"post_bytes_per_hour"`
	UnauthenticatedPerMinute int64 `json:"unauthenticated_per_minute"`
	RegistrationsPerHour     int64 `json:"registrations_per_hour"`
	MaxMailboxes             int64 `json:"max_mailboxes"`
	MailboxMaxMessages       int64 `json:"mailbox_max_messages"`
	MailboxMaxBytes          int64 `json:"mailbox_max_bytes"`
	RelayMaxBytes            int64 `json:"relay_max_bytes"`
	// MaxOpenUploads is the one limit with a ceiling, maxOpenUploadsCeiling:
	// it is a count of files and rows the relay holds for one sender, and
	// a thousand of them is more than any sender has a use for.
	MaxOpenUploads int64 `json:"max_open_uploads"`
	MaxInflight    int64 `json:"max_inflight"`
	MaxWaiting     int64 `json:"max_waiting"`
}

// maxOpenUploadsCeiling is the most max_open_uploads may be set to.
const maxOpenUploadsCeiling = 1000

// TLSConfig selects how the relay obtains its certificate.
type TLSConfig struct {
	// Mode is off or files. Empty means infer it; see Resolve.
	Mode string `json:"mode"`
	// Bundle names an export from auu-ca: the relay's signing intermediates
	// and the public certificates that complete a chain to the trust anchor.
	// With one the relay mints its own certificate and can issue client
	// certificates; it is the alternative to bringing your own cert_file.
	Bundle string `json:"bundle"`
	// BundleCredential names the same bundle as a systemd credential: the
	// unit's LoadCredentialEncrypted= unseals it at start into the directory
	// $CREDENTIALS_DIRECTORY names, and the relay reads it from there. It is
	// the alternative to Bundle, not an addition to it; BundlePath is the
	// one place either becomes a path.
	BundleCredential string `json:"bundle_credential"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
}

// credentialsDirectoryEnv is the variable systemd sets to the directory it
// has placed a service's credentials in. It is systemd's name and not a
// setting, so that anything which follows the convention — a unit, a
// container entrypoint, a test — works.
const credentialsDirectoryEnv = "CREDENTIALS_DIRECTORY"

// maxCredentialName is the longest credential ID systemd accepts, which is
// the longest file name it can be.
const maxCredentialName = 255

// validCredentialName reports whether name is one systemd would accept as a
// credential ID and one that needs no quoting in a unit file or on a
// command line: 1 to 255 bytes of graphic ASCII, with no slash, because it
// becomes a file name; no colon, because that separates the ID from the
// path in LoadCredentialEncrypted=; no space; and neither "." nor "..".
func validCredentialName(name string) bool {
	if len(name) == 0 || len(name) > maxCredentialName || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c > '~' || c == '/' || c == ':' {
			return false
		}
	}
	return true
}

// BundlePath is where the relay reads its bundle from: tls.bundle, or the
// file systemd placed for tls.bundle_credential. ok is false when neither
// is set. It is the only place a credential name becomes a path, and every
// reader of the bundle's location goes through it, so that none can be
// added that forgets the credential.
func (c Config) BundlePath() (path string, ok bool, err error) {
	switch {
	case c.TLS.Bundle != "" && c.TLS.BundleCredential != "":
		return "", false, errors.New("tls.bundle and tls.bundle_credential both name a bundle; use one")
	case c.TLS.Bundle == "" && c.TLS.BundleCredential == "":
		return "", false, nil
	case c.TLS.Bundle != "":
		return c.TLS.Bundle, true, nil
	}
	name := c.TLS.BundleCredential
	if !validCredentialName(name) {
		return "", false, fmt.Errorf("tls.bundle_credential %q is not a credential name: "+
			"1 to 255 printable ASCII characters, no space, slash or colon", name)
	}
	dir := os.Getenv(credentialsDirectoryEnv)
	if dir == "" {
		return "", false, fmt.Errorf("tls.bundle_credential is %q but %s is not set: the relay is not "+
			"running under a unit with LoadCredentialEncrypted=%s:... in it",
			name, credentialsDirectoryEnv, name)
	}
	if !filepath.IsAbs(dir) {
		return "", false, fmt.Errorf("%s is %q, not an absolute path", credentialsDirectoryEnv, dir)
	}
	return filepath.Join(dir, name), true, nil
}

// bundleSetting names the setting the bundle came from, for an error or a
// log line: "tls.bundle" for a file and the credential by name otherwise.
func (c Config) bundleSetting() string {
	if c.TLS.BundleCredential != "" && c.TLS.Bundle == "" {
		return fmt.Sprintf("tls.bundle_credential %q", c.TLS.BundleCredential)
	}
	return "tls.bundle"
}

// bundleSource is what logStartup reports the bundle as: file or credential.
func (c Config) bundleSource() string {
	if c.TLS.BundleCredential != "" && c.TLS.Bundle == "" {
		return "credential"
	}
	return "file"
}

// Defaults returns the configuration used when nothing else is supplied.
//
// The limits come from the relay package so the command and the library cannot
// drift apart about what "default" means.
func Defaults() Config {
	d := relay.DefaultLimits()
	return Config{
		Listen:         ":8080",
		DB:             "relay.db",
		MaxBytes:       relayapi.DefaultMaxBytes,
		Registration:   relayapi.RegistrationOpen,
		Streams:        true,
		MaxStreamBytes: defaultMaxStreamBytes,
		Admin:          AdminConfig{TokenMaxAge: defaultTokenMaxAge.String()},
		ClientCerts: ClientCertsConfig{
			Mode:     relayapi.ClientCertsOff,
			Lifetime: defaultCertLifetime.String(),
		},
		Limits: LimitsConfig{
			RequestsPerMinute:        d.RequestsPerMinute,
			PostsPerMinute:           d.PostsPerMinute,
			PostBytesPerHour:         d.PostBytesPerHour,
			UnauthenticatedPerMinute: d.UnauthenticatedPerMinute,
			RegistrationsPerHour:     d.RegistrationsPerHour,
			MaxMailboxes:             d.MaxMailboxes,
			MailboxMaxMessages:       d.MailboxMaxMessages,
			MailboxMaxBytes:          d.MailboxMaxBytes,
			RelayMaxBytes:            d.RelayMaxBytes,
			MaxOpenUploads:           d.MaxOpenUploads,
			MaxInflight:              d.MaxInflight,
			MaxWaiting:               d.MaxWaiting,
		},
		AccessLog: relay.AccessLogFull,
	}
}

// Load reads a config file over the defaults. An empty path returns the
// defaults untouched: there is no implicit config location.
//
// Decoding into an already-populated struct is what makes an absent key mean
// "keep the default" rather than "set the zero value".
//
// The second return value is a startup warning to log, or empty. It is not
// part of Config because Config is printed by --print-config and round trips
// through the file format.
// removedKeys are settings earlier releases had. An unknown key is already an
// error, but "unknown field" would send an operator looking for a typo when
// what they need is to know where the setting went.
var removedKeys = map[string]string{
	"tls.acme":               "ACME was removed: a relay's certificate now comes from its own authority, so it needs no public CA and no particular port. Make one with 'auu-ca init' and 'auu-ca relay', and set tls.bundle.",
	"client_certs.dir":       "the relay no longer makes its own authority: it is issued one by 'auu-ca relay'. Set tls.bundle instead.",
	"client_certs.mldsa":     "the ML-DSA parameter set is the trust anchor's now, chosen by 'auu-ca init --mldsa'. Remove this key.",
	"limits.trusted_proxies": "reverse-proxy support was removed: the relay terminates TLS itself, on its own port, and reads no X-Forwarded-For. Remove this key and set tls.bundle or tls.bundle_credential.",
}

// checkRemovedKeys reports a setting that used to exist, by name.
func checkRemovedKeys(raw []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil // malformed JSON is reported properly elsewhere
	}
	for key, why := range removedKeys {
		section, field, _ := strings.Cut(key, ".")
		body, ok := probe[section]
		if !ok {
			continue
		}
		if field == "" {
			return fmt.Errorf("%s is no longer a setting: %s", key, why)
		}
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(body, &inner); err != nil {
			continue
		}
		if _, ok := inner[field]; ok {
			return fmt.Errorf("%s is no longer a setting: %s", key, why)
		}
	}
	return nil
}

func Load(path string) (Config, string, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, "", fmt.Errorf("config file: %w", err)
	}
	// Some editors put a byte order mark at the front of a file they save as
	// UTF-8; JSON has no place for one, and Go's decoder names it as the
	// character it is, which nobody can see.
	if bytes.HasPrefix(raw, []byte(utf8BOM)) {
		return cfg, "", fmt.Errorf("%s begins with a byte order mark, three invisible bytes an editor "+
			"put there; save it as plain UTF-8", path)
	}
	// A setting that used to exist is named before the strict decode, so an
	// operator upgrading is told where it went rather than that it is unknown.
	if err := checkRemovedKeys(raw); err != nil {
		return cfg, "", fmt.Errorf("%s: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	// A misspelled key is a silent misconfiguration otherwise, and the whole
	// point of this file is to be the record of what the relay is doing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) {
			return cfg, "", fmt.Errorf("%s: malformed JSON at byte %d: %w%s", path, syn.Offset, err,
				trailingCommaHint(raw, syn.Offset))
		}
		return cfg, "", fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return cfg, "", fmt.Errorf("%s: trailing data after the JSON object", path)
	}

	// A relative path in the file is relative to the file, not to the
	// working directory: a relay under systemd starts in a directory
	// nobody chose, and "relay.db" beside its settings is what a person
	// who wrote it meant. A flag keeps the working directory, as a path
	// typed at a shell does.
	cfg.resolveAgainst(filepath.Dir(path))

	// Nothing in the file is secret today, but it decides who may administer
	// the relay, so a file anyone can write is worth a word.
	var warning string
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o022 != 0 {
		warning = fmt.Sprintf("%s is mode %04o: anyone who can write it can change "+
			"who administers this relay; consider chmod 644 on it", path, info.Mode().Perm())
	}
	return cfg, warning, nil
}

// resolveAgainst makes every path setting the file gave absolute against
// dir, the file's own directory; an absolute one and an empty one are
// left as they are. The credential name is not a path and is not here.
func (c *Config) resolveAgainst(dir string) {
	for _, p := range []*string{&c.DB, &c.MessagesDir, &c.Admin.AuthorizedFile, &c.TLS.CertFile, &c.TLS.KeyFile, &c.TLS.Bundle} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
}

// utf8BOM is the byte order mark as UTF-8 encodes it.
const utf8BOM = "\xef\xbb\xbf"

// trailingCommaHint names the mistake behind the commonest syntax error a
// person makes in a settings file: a comma after the last item, which Go's
// decoder reports as the brace or bracket that followed it. offset is the
// decoder's, one past the character it stopped at.
func trailingCommaHint(raw []byte, offset int64) string {
	i := int(offset) - 1
	if i < 0 || i >= len(raw) || (raw[i] != '}' && raw[i] != ']') {
		return ""
	}
	for i--; i >= 0; i-- {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case ',':
			return ": the comma after the last item is one too many"
		}
		return ""
	}
	return ""
}

// Merge applies the flags that were actually typed on the command line.
//
// Only visited flags are applied. A flag left off the command line must not
// overwrite a file value with its own default, which is why this cannot simply
// read every flag value.
func (c *Config) Merge(fs *flag.FlagSet, f *flagValues) {
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "listen":
			c.Listen = f.listen
		case "db":
			c.DB = f.db
		case "messages-dir":
			c.MessagesDir = f.messagesDir
		case "max-bytes":
			c.MaxBytes = f.maxBytes
		case "registration":
			c.Registration = f.registration
		case "public-url":
			c.PublicURL = f.publicURL
		case "admin-file":
			c.Admin.AuthorizedFile = f.adminFile
		case "token-max-age":
			c.Admin.TokenMaxAge = f.tokenMaxAge
		case "streams":
			c.Streams = f.streams
		case "max-stream-bytes":
			c.MaxStreamBytes = f.maxStreamBytes
		case "client-certs":
			c.ClientCerts.Mode = f.clientCerts
		case "client-certs-dir":
		case "client-cert-lifetime":
			c.ClientCerts.Lifetime = f.clientCertLifetime
		case "tls-mode":
			c.TLS.Mode = f.tlsMode
		case "tls-cert":
			c.TLS.CertFile = f.tlsCert
		case "tls-key":
			c.TLS.KeyFile = f.tlsKey
		case "tls-bundle":
			c.TLS.Bundle = f.tlsBundle
		case "tls-bundle-credential":
			c.TLS.BundleCredential = f.tlsBundleCredential
		case "limit-requests":
			c.Limits.RequestsPerMinute = f.limitRequests
		case "limit-posts":
			c.Limits.PostsPerMinute = f.limitPosts
		case "limit-post-bytes":
			c.Limits.PostBytesPerHour = f.limitPostBytes
		case "limit-unauthenticated":
			c.Limits.UnauthenticatedPerMinute = f.limitUnauthenticated
		case "limit-registrations":
			c.Limits.RegistrationsPerHour = f.limitRegistrations
		case "max-mailboxes":
			c.Limits.MaxMailboxes = f.maxMailboxes
		case "mailbox-max-messages":
			c.Limits.MailboxMaxMessages = f.mailboxMaxMessages
		case "mailbox-max-bytes":
			c.Limits.MailboxMaxBytes = f.mailboxMaxBytes
		case "relay-max-bytes":
			c.Limits.RelayMaxBytes = f.relayMaxBytes
		case "max-open-uploads":
			c.Limits.MaxOpenUploads = f.maxOpenUploads
		case "max-inflight":
			c.Limits.MaxInflight = f.maxInflight
		case "max-waiting":
			c.Limits.MaxWaiting = f.maxWaiting
		case "access-log":
			c.AccessLog = f.accessLog
		}
	})
}

// Resolve fills in the settings that depend on other settings. Run it after
// every source has been merged and before Validate.
func (c *Config) Resolve() {
	if c.Registration == "" {
		c.Registration = relayapi.RegistrationOpen
	}
	if c.Admin.TokenMaxAge == "" {
		c.Admin.TokenMaxAge = defaultTokenMaxAge.String()
	}
	if c.AccessLog == "" {
		c.AccessLog = relay.AccessLogFull
	}
	if c.MessagesDir == "" {
		c.MessagesDir = filepath.Join(filepath.Dir(c.DB), "messages")
	}
	if c.ClientCerts.Mode == "" {
		c.ClientCerts.Mode = relayapi.ClientCertsOff
	}
	// A default is a decision: a relay serves TLS unless somebody writes
	// down that it does not. Nothing is inferred from the other settings
	// any more; a mode of files with nothing to serve from is refused at
	// startup by Validate, in a sentence that names both ways out.
	if c.TLS.Mode == "" {
		c.TLS.Mode = ModeFiles
	}
}

// msgNoTLS is what a relay started with no bundle and no certificate says.
// It is the first thing a person who ran the binary bare will read, so it
// names the two commands that make a bundle, the section that walks them,
// and the one flag that says plain HTTP on purpose.
const msgNoTLS = "no TLS bundle or certificate: a relay serves TLS; make an authority and a bundle " +
	"with 'auu-ca init' and 'auu-ca relay' (docs/relay.md, 1.5), or for a try on your own machine only, --tls-mode off"

// Validate reports the first thing wrong with the configuration.
//
// It creates the messages directory rather than only inspecting it, so a
// relay that cannot write where its message files go fails at startup with a
// path in the message instead of at the first post.
func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen address is empty")
	}
	if c.DB == "" {
		return errors.New("database path is empty")
	}
	if c.MaxBytes <= 0 {
		return fmt.Errorf("max_bytes must be positive, got %d", c.MaxBytes)
	}
	// Above the ceiling, max_bytes plus the framing allowance overflows int64,
	// and http.MaxBytesReader handed a negative limit refuses every body.
	if c.MaxBytes > relayapi.MaxBytesCeiling {
		return fmt.Errorf("max_bytes must be at most %d, got %d",
			relayapi.MaxBytesCeiling, c.MaxBytes)
	}
	switch c.Registration {
	case relayapi.RegistrationOpen, relayapi.RegistrationToken, relayapi.RegistrationClosed:
	default:
		return fmt.Errorf("registration must be %q, %q or %q, got %q",
			relayapi.RegistrationOpen, relayapi.RegistrationToken,
			relayapi.RegistrationClosed, c.Registration)
	}
	if c.PublicURL != "" {
		if err := token.ValidateRelay(c.PublicURL); err != nil {
			return fmt.Errorf("public_url %v", err)
		}
	}
	if _, err := c.TokenMaxAge(); err != nil {
		return err
	}
	if c.MaxStreamBytes < 0 {
		return fmt.Errorf("max_stream_bytes must not be negative, got %d (use 0 for unlimited)",
			c.MaxStreamBytes)
	}
	if c.Registration == relayapi.RegistrationToken && c.Admin.AuthorizedFile == "" {
		return errors.New("registration is token, which needs administrators to issue them: " +
			"set admin.authorized_file (--admin-file)")
	}
	if c.Admin.AuthorizedFile != "" {
		// Parsed now rather than at the first admin request, so a typo in the
		// file is a startup failure with a line number in it.
		if _, err := relay.LoadAdmins(c.Admin.AuthorizedFile); err != nil {
			return err
		}
	}
	// Created rather than merely inspected, so a relay that cannot store mail
	// fails at startup with the path in the message and not at the first post.
	if c.MessagesDir == "" {
		return errors.New("messages_dir is empty")
	}
	if err := os.MkdirAll(c.MessagesDir, messagesDirMode); err != nil {
		return fmt.Errorf("messages directory: %w", err)
	}
	if info, err := os.Stat(c.MessagesDir); err == nil {
		if perm := info.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("messages directory %s is mode %04o: it holds stored mail and "+
				"must not be writable by group or others", c.MessagesDir, perm)
		}
	}
	if err := c.clientCertsValidate(); err != nil {
		return err
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if c.AccessLog != relay.AccessLogFull && c.AccessLog != relay.AccessLogMinimal {
		return fmt.Errorf("access_log must be %q or %q, got %q",
			relay.AccessLogFull, relay.AccessLogMinimal, c.AccessLog)
	}

	// Resolved once, here: a credential that systemd did not provide is a
	// startup failure naming the credential and the directory, not a missing
	// file with no explanation. No mode or ownership check is made on the
	// bundle: a credential is presented read-only by systemd, and its
	// protection is where it is, not its mode bits.
	bundle, haveBundle, err := c.BundlePath()
	if err != nil {
		return err
	}
	switch c.TLS.Mode {
	case ModeOff:
		if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
			return errors.New("tls mode is off but a certificate or key file is configured")
		}
		// A bundle is what the relay serves TLS from, so one with TLS off
		// is a contradiction rather than an arrangement: nothing stands in
		// front of the relay to terminate for it.
		if haveBundle {
			return fmt.Errorf("tls mode is off but %s names a bundle; the relay serves TLS "+
				"from a bundle itself, so set tls.mode to files or remove the bundle", c.bundleSetting())
		}
	case ModeFiles:
		if haveBundle {
			if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
				return fmt.Errorf("%s and tls.cert_file name two different certificates; "+
					"use the bundle from auu-ca, or your own certificate, not both", c.bundleSetting())
			}
			// Loaded rather than merely opened: every rule the relay depends
			// on is checked here so a bad bundle is a startup failure with
			// the path in the message.
			loaded, err := pki.LoadBundle(bundle)
			if err != nil {
				return fmt.Errorf("%s: %w", c.bundleSetting(), err)
			}
			if err := hostNotInBundle(c.PublicURL, loaded.Hosts); err != nil {
				return err
			}
		} else {
			if c.TLS.CertFile == "" && c.TLS.KeyFile == "" {
				return errors.New(msgNoTLS)
			}
			if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
				return errors.New("tls mode is files: give both a certificate file and a key file, " +
					"or a bundle from auu-ca")
			}
			if _, err := loadKeyPair(c.TLS.CertFile, c.TLS.KeyFile); err != nil {
				return fmt.Errorf("tls certificate and key: %w", err)
			}
		}
	default:
		return fmt.Errorf("tls mode must be %q or %q, got %q", ModeOff, ModeFiles, c.TLS.Mode)
	}
	return nil
}

// hostNotInBundle says when public_url names a host the bundle was not
// issued for. Tokens name public_url and machines connect to it, verifying
// the relay's certificate against that name; the certificate is minted for
// the bundle's hosts, so a bundle for another host would start and then be
// refused by every machine with Go's hostname error, and a newcomer would be
// left with a half-made home. It is refused here instead, where the operator
// is, before anybody is locked out. Hosts are compared the way the verifier
// will compare them: DNS names without regard to case or a trailing dot, IP
// literals as addresses.
func hostNotInBundle(publicURL string, hosts []string) error {
	if publicURL == "" {
		return nil
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		// Already refused by token.ValidateRelay, with its own message.
		return nil
	}
	// The verifier ignores a trailing dot, and auu-ca does not take one.
	want := strings.TrimSuffix(u.Hostname(), ".")
	for _, h := range hosts {
		if sameHost(want, h) {
			return nil
		}
	}
	return fmt.Errorf("public_url names %s but the bundle was issued for %s: "+
		"run 'auu-ca relay --host %s' on the offline machine and deliver that bundle, or fix public_url",
		want, strings.Join(hosts, ", "), want)
}

// sameHost is one host name or address against another, as a certificate
// verifier sees them. Neither side is a wildcard: a bundle's hosts are plain
// names and addresses.
func sameHost(a, b string) bool {
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	if errA == nil || errB == nil {
		return errA == nil && errB == nil && ia.Unmap() == ib.Unmap()
	}
	return strings.EqualFold(a, b)
}

// validate reports the first thing wrong with the limits block.
func (l LimitsConfig) validate() error {
	for _, f := range []struct {
		name  string
		value int64
	}{
		{"requests_per_minute", l.RequestsPerMinute},
		{"posts_per_minute", l.PostsPerMinute},
		{"post_bytes_per_hour", l.PostBytesPerHour},
		{"unauthenticated_per_minute", l.UnauthenticatedPerMinute},
		{"registrations_per_hour", l.RegistrationsPerHour},
		{"max_mailboxes", l.MaxMailboxes},
		{"mailbox_max_messages", l.MailboxMaxMessages},
		{"mailbox_max_bytes", l.MailboxMaxBytes},
		{"relay_max_bytes", l.RelayMaxBytes},
		{"max_open_uploads", l.MaxOpenUploads},
		{"max_inflight", l.MaxInflight},
		{"max_waiting", l.MaxWaiting},
	} {
		if f.value < 0 {
			return fmt.Errorf("%s must not be negative, got %d (use 0 for unlimited)", f.name, f.value)
		}
	}
	if l.MaxOpenUploads > maxOpenUploadsCeiling {
		return fmt.Errorf("max_open_uploads must be at most %d, got %d (use 0 for unlimited)",
			maxOpenUploadsCeiling, l.MaxOpenUploads)
	}
	// A held listing keeps an in-flight slot for as long as it is held, so
	// holds allowed up to the in-flight cap could take every slot and the
	// relay would answer 503 to everything else. Zero on either side is
	// unlimited, and unlimited is not a number to be under.
	if l.MaxInflight > 0 && l.MaxWaiting > 0 && l.MaxWaiting >= l.MaxInflight {
		return fmt.Errorf("max_waiting (%d) must be under max_inflight (%d): a held listing keeps "+
			"an in-flight slot, and holds alone would fill the relay", l.MaxWaiting, l.MaxInflight)
	}
	return nil
}

// Relay converts the configured policy into the one the relay enforces.
func (l LimitsConfig) Relay() relay.Limits {
	return relay.Limits{
		RequestsPerMinute:        l.RequestsPerMinute,
		PostsPerMinute:           l.PostsPerMinute,
		PostBytesPerHour:         l.PostBytesPerHour,
		UnauthenticatedPerMinute: l.UnauthenticatedPerMinute,
		RegistrationsPerHour:     l.RegistrationsPerHour,
		MaxMailboxes:             l.MaxMailboxes,
		MailboxMaxMessages:       l.MailboxMaxMessages,
		MailboxMaxBytes:          l.MailboxMaxBytes,
		RelayMaxBytes:            l.RelayMaxBytes,
		MaxOpenUploads:           l.MaxOpenUploads,
		MaxInflight:              l.MaxInflight,
		MaxWaiting:               l.MaxWaiting,
	}
}

// clientCertsValidate checks the client certificate settings.
//
// The authority itself is no longer the relay's to make: it comes from an
// auu-ca bundle, whose keys were generated on a machine with no open sockets.
// So what is checked here is that one was given.
func (c Config) clientCertsValidate() error {
	switch c.ClientCerts.Mode {
	case relayapi.ClientCertsOff, relayapi.ClientCertsRequired:
	default:
		return fmt.Errorf("client_certs.mode must be %q or %q, got %q",
			relayapi.ClientCertsOff, relayapi.ClientCertsRequired, c.ClientCerts.Mode)
	}
	lifetime, err := c.ClientCerts.ParsedLifetime()
	if err != nil {
		return err
	}
	if lifetime < minCertLifetime || lifetime > maxCertLifetime {
		return fmt.Errorf("client_certs.lifetime must be between %v and %v, got %v",
			minCertLifetime, maxCertLifetime, lifetime)
	}
	if !c.ClientCerts.Required() {
		return nil
	}
	// Through the accessor, so a credential counts, and its error first, so
	// that two settings naming a bundle is reported as that rather than as
	// no bundle at all.
	_, ok, err := c.BundlePath()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("client certificates need the signing intermediate from an auu-ca " +
			"bundle: set tls.bundle or tls.bundle_credential")
	}
	// A relay that does not terminate TLS would never see a certificate,
	// and would refuse every mailbox request for ever.
	if c.TLS.Mode == ModeOff {
		return errors.New("client certificates are required but tls mode is off: " +
			"the relay must terminate TLS itself to see one; set tls.mode to files")
	}
	// Registration consults no presented certificate — it is how a machine
	// gets one — so with registration open, any holder of the identity key
	// re-registers with no token and is issued a fresh certificate, and
	// revoking a machine's certificate revokes nothing. The pair cancels
	// the guarantee certificates exist for, and is refused rather than
	// documented.
	if c.Registration == relayapi.RegistrationOpen {
		return errors.New(msgOpenWithCerts)
	}
	return nil
}

// msgOpenWithCerts is the refusal of open registration beside required
// client certificates.
const msgOpenWithCerts = "client certificates are required but registration is open: a revoked machine " +
	"could re-register with no token and be issued a new certificate, so revocation would revoke nothing; " +
	"set registration to token or closed"

// Encode writes a configuration as the config file format.
//
// HTML escaping is off: encoding/json would otherwise render the redaction
// marker as \u003credacted\u003e, and this output is meant to be read by a
// person and pasted back into a config file.
func Encode(w io.Writer, cfg Config) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

// Redacted returns a copy safe to print.
//
// Nothing in the configuration is secret today: the static invite token that
// used to live here was replaced by signed enrolment tokens, which the relay
// never holds and never prints. This stays so that the next secret to arrive
// has an obvious place to be handled.
func (c Config) Redacted() Config { return c }

// TokenMaxAge parses the configured token lifetime cap.
func (c Config) TokenMaxAge() (time.Duration, error) {
	if c.Admin.TokenMaxAge == "" {
		return defaultTokenMaxAge, nil
	}
	d, err := time.ParseDuration(c.Admin.TokenMaxAge)
	if err != nil {
		return 0, fmt.Errorf("admin.token_max_age %q is not a duration: %w", c.Admin.TokenMaxAge, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("admin.token_max_age must be positive, got %s", d)
	}
	return d, nil
}

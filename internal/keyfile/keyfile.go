// Package keyfile puts a private key under a passphrase.
//
// A file is one PEM block of type "AUU ENCRYPTED PRIVATE KEY". Its body is
// the key's PKCS#8 DER sealed with AES-256-GCM under a key derived from the
// passphrase, and its headers say how the derivation was done:
//
//	-----BEGIN AUU ENCRYPTED PRIVATE KEY-----
//	Cipher: AES-256-GCM
//	Iterations: 600000
//	KDF: Argon2id+PBKDF2-HMAC-SHA256
//	Memory: 65536
//	Salt: 7Kx0m9K1s3r2ZQxV4pBw9g==
//	Threads: 4
//	Time: 3
//
//	<base64 of nonce || ciphertext || tag>
//	-----END AUU ENCRYPTED PRIVATE KEY-----
//
// The headers are the AEAD's additional data, so a file whose parameters
// have been altered fails to open rather than opening to something else.
//
// The derivation is two standard functions in a row: Argon2id (RFC 9106)
// over the passphrase, for memory-hardness, and PBKDF2-HMAC-SHA256
// (RFC 8018) over that result, so the function that produces the key is an
// approved one. Each runs at the cost it would need on its own — Argon2id at
// RFC 9106 section 4's second recommendation, PBKDF2 at OWASP's 2023 count —
// so neither depends on the other for its strength. One salt serves both;
// they are different functions, and the salt's job is to make this file's
// derivation unlike any other file's.
//
// Argon2id is golang.org/x/crypto/argon2, the one package outside the
// standard library this project takes for cryptography, and only here: the
// standard library has PBKDF2 and nothing memory-hard. It is not used for
// anything a message or a connection depends on.
//
// The container is this project's own, deliberately. PKCS#8's PBES2
// (RFC 8018) is the standard slot, but no authenticated cipher inside it is
// one OpenSSL reads, and it has no identifier for Argon2 at all, so it would
// buy an operator no tooling and would fix the derivation at PBKDF2.
package keyfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	// BlockType is the PEM type of an encrypted key. A plain PKCS#8 key is
	// "PRIVATE KEY", which is how a home that is not under a passphrase
	// writes its keys and what IsEncrypted tells this from.
	BlockType = "AUU ENCRYPTED PRIVATE KEY"

	// DefaultTime, DefaultMemory and DefaultThreads are Argon2id's
	// parameters for a new file: three passes over 64 MiB with four lanes,
	// RFC 9106 section 4's recommendation for where two gigabytes is too
	// much. Memory is in KiB, as Argon2 counts it.
	DefaultTime    = 3
	DefaultMemory  = 64 * 1024
	DefaultThreads = 4

	// DefaultIterations is the PBKDF2 count for a new file: OWASP's 2023
	// figure for HMAC-SHA256. Every parameter is recorded in the file, so
	// raising a default changes only files written afterwards.
	DefaultIterations = 600_000

	// The bounds on what a file may claim. Each floor is what the function
	// requires; each ceiling is far above any value worth writing, so a
	// file cannot make its reader compute for a week or allocate a
	// terabyte, and each fits the type the function takes.
	MinTime       = 1
	MaxTime       = 1 << 16
	MinThreads    = 1
	MaxThreads    = 255     // argon2 takes a uint8
	MaxMemory     = 1 << 20 // 1 GiB, sixteen times DefaultMemory (S58)
	MinIterations = 1
	MaxIterations = 1 << 30

	// MinSaltSize and MaxSaltSize bound the salt a file may carry. RFC 8018
	// recommends at least eight bytes; a new file gets saltSize.
	MinSaltSize = 8
	MaxSaltSize = 64
	saltSize    = 16

	// keySize is AES-256's, and the length of Argon2id's output too.
	keySize = 32
	// nonceSize and tagSize are GCM's, and together are the least a body
	// can be. crypto/cipher chooses the nonce and puts it first.
	nonceSize = 12
	tagSize   = 16

	hdrKDF        = "KDF"
	hdrTime       = "Time"
	hdrMemory     = "Memory"
	hdrThreads    = "Threads"
	hdrIterations = "Iterations"
	hdrSalt       = "Salt"
	hdrCipher     = "Cipher"

	kdfChain  = "Argon2id+PBKDF2-HMAC-SHA256"
	cipherGCM = "AES-256-GCM"
)

var (
	// ErrPassphrase is a body that would not open: the passphrase is wrong
	// or the file has been altered, and the AEAD cannot tell which.
	ErrPassphrase = errors.New("wrong passphrase, or the file has been altered")
	// ErrEmptyPassphrase refuses to encrypt under, or open with, nothing.
	ErrEmptyPassphrase = errors.New("a passphrase is required")
	// ErrNotEncrypted is a block of some other type.
	ErrNotEncrypted = errors.New("not an encrypted key file")
)

// headerNames is every header a file has, and the only ones it may have.
var headerNames = []string{hdrCipher, hdrIterations, hdrKDF, hdrMemory, hdrSalt, hdrThreads, hdrTime}

// Passphrase is what a key is encrypted under, and how hard the derivation
// is made. A zero cost means its default; a test sets them low.
type Passphrase struct {
	Secret []byte

	// Time, Memory (KiB) and Threads are Argon2id's.
	Time    int
	Memory  int
	Threads int
	// Iterations is PBKDF2's.
	Iterations int
}

// cost is a set of derivation parameters that has been checked.
type cost struct {
	time, memory, threads, iterations int
}

// Encrypt seals der under pass and returns the PEM.
func Encrypt(der []byte, pass Passphrase) ([]byte, error) {
	if len(pass.Secret) == 0 {
		return nil, ErrEmptyPassphrase
	}
	c, err := costFor(pass)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	headers := map[string]string{
		hdrKDF:        kdfChain,
		hdrTime:       strconv.Itoa(c.time),
		hdrMemory:     strconv.Itoa(c.memory),
		hdrThreads:    strconv.Itoa(c.threads),
		hdrIterations: strconv.Itoa(c.iterations),
		hdrSalt:       base64.StdEncoding.EncodeToString(salt),
		hdrCipher:     cipherGCM,
	}
	aead, err := aeadFor(pass.Secret, salt, c)
	if err != nil {
		return nil, err
	}
	body := aead.Seal(nil, nil, der, aad(BlockType, headers))
	return pem.EncodeToMemory(&pem.Block{Type: BlockType, Headers: headers, Bytes: body}), nil
}

// Decrypt opens a PEM-encoded key file with secret and returns the DER.
func Decrypt(pemBytes, secret []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("keyfile: no PEM block")
	}
	return DecryptBlock(block, secret)
}

// DecryptBlock is Decrypt on a block already parsed.
//
// The checks run cheapest first, and the derivation, which is meant to be
// slow and to allocate, runs only once everything about the file has been
// accepted.
func DecryptBlock(block *pem.Block, secret []byte) ([]byte, error) {
	if block.Type != BlockType {
		return nil, fmt.Errorf("%w: a %q block", ErrNotEncrypted, block.Type)
	}
	if len(secret) == 0 {
		return nil, ErrEmptyPassphrase
	}
	c, salt, err := parseHeaders(block.Headers)
	if err != nil {
		return nil, err
	}
	if len(block.Bytes) < nonceSize+tagSize {
		return nil, fmt.Errorf("keyfile: body is %d bytes, shorter than a nonce and a tag", len(block.Bytes))
	}
	aead, err := aeadFor(secret, salt, c)
	if err != nil {
		return nil, err
	}
	der, err := aead.Open(nil, nil, block.Bytes, aad(BlockType, block.Headers))
	if err != nil {
		return nil, ErrPassphrase
	}
	return der, nil
}

// IsEncrypted says whether pemBytes hold an encrypted key rather than a
// plain one. It reads the block's type and nothing else.
func IsEncrypted(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	return block != nil && block.Type == BlockType
}

// parseHeaders accepts exactly the headers Encrypt writes.
func parseHeaders(h map[string]string) (cost, []byte, error) {
	for _, want := range headerNames {
		if _, ok := h[want]; !ok {
			return cost{}, nil, fmt.Errorf("keyfile: no %s header", want)
		}
	}
	if len(h) != len(headerNames) {
		var extra []string
		for k := range h {
			if !known(k) {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		return cost{}, nil, fmt.Errorf("keyfile: unknown header %q", extra[0])
	}
	if kdf := h[hdrKDF]; kdf != kdfChain {
		return cost{}, nil, fmt.Errorf("keyfile: unknown key derivation %q; this build knows %s", kdf, kdfChain)
	}
	if ci := h[hdrCipher]; ci != cipherGCM {
		return cost{}, nil, fmt.Errorf("keyfile: unknown cipher %q; this build knows %s", ci, cipherGCM)
	}
	var p Passphrase
	for _, f := range []struct {
		name string
		into *int
	}{
		{hdrTime, &p.Time}, {hdrMemory, &p.Memory}, {hdrThreads, &p.Threads}, {hdrIterations, &p.Iterations},
	} {
		n, err := strconv.Atoi(h[f.name])
		if err != nil {
			return cost{}, nil, fmt.Errorf("keyfile: %s is not a number: %q", f.name, h[f.name])
		}
		if n == 0 {
			// Zero means the default to a caller of Encrypt and nothing in
			// a file, where every count must be the one actually used.
			return cost{}, nil, fmt.Errorf("keyfile: %s is 0", f.name)
		}
		*f.into = n
	}
	c, err := costFor(p)
	if err != nil {
		return cost{}, nil, err
	}
	// The encoded length is checked before decoding, which allocates.
	if enc := h[hdrSalt]; len(enc) > base64.StdEncoding.EncodedLen(MaxSaltSize) {
		return cost{}, nil, fmt.Errorf("keyfile: %s is %d characters, longer than a %d-byte salt",
			hdrSalt, len(enc), MaxSaltSize)
	}
	salt, err := base64.StdEncoding.DecodeString(h[hdrSalt])
	if err != nil {
		return cost{}, nil, fmt.Errorf("keyfile: %s is not base64: %v", hdrSalt, err)
	}
	if len(salt) < MinSaltSize || len(salt) > MaxSaltSize {
		return cost{}, nil, fmt.Errorf("keyfile: salt must be between %d and %d bytes, got %d",
			MinSaltSize, MaxSaltSize, len(salt))
	}
	return c, salt, nil
}

func known(header string) bool {
	for _, h := range headerNames {
		if h == header {
			return true
		}
	}
	return false
}

// costFor resolves a caller's parameters: zero is the default, anything
// else must be within bounds and consistent.
//
// Argon2 wants the memory to be a multiple of four blocks per lane and no
// less than eight, and would silently round rather than refuse; refusing
// here keeps the header the truth about what was done.
func costFor(p Passphrase) (cost, error) {
	c := cost{time: p.Time, memory: p.Memory, threads: p.Threads, iterations: p.Iterations}
	if c.time == 0 {
		c.time = DefaultTime
	}
	if c.memory == 0 {
		c.memory = DefaultMemory
	}
	if c.threads == 0 {
		c.threads = DefaultThreads
	}
	if c.iterations == 0 {
		c.iterations = DefaultIterations
	}
	if c.time < MinTime || c.time > MaxTime {
		return cost{}, fmt.Errorf("keyfile: %s must be between %d and %d, got %d", hdrTime, MinTime, MaxTime, c.time)
	}
	if c.threads < MinThreads || c.threads > MaxThreads {
		return cost{}, fmt.Errorf("keyfile: %s must be between %d and %d, got %d", hdrThreads, MinThreads, MaxThreads, c.threads)
	}
	if lo := 8 * c.threads; c.memory < lo || c.memory > MaxMemory {
		return cost{}, fmt.Errorf("keyfile: %s must be between %d and %d KiB with %d threads, got %d",
			hdrMemory, lo, MaxMemory, c.threads, c.memory)
	}
	if c.memory%(4*c.threads) != 0 {
		return cost{}, fmt.Errorf("keyfile: %s must be a multiple of %d KiB with %d threads, got %d",
			hdrMemory, 4*c.threads, c.threads, c.memory)
	}
	if c.iterations < MinIterations || c.iterations > MaxIterations {
		return cost{}, fmt.Errorf("keyfile: %s must be between %d and %d, got %d",
			hdrIterations, MinIterations, MaxIterations, c.iterations)
	}
	return c, nil
}

// deriveFileKey turns a passphrase into a file key: Argon2id, then PBKDF2
// over its output. This is the slow step, and both halves are meant to be.
//
// One salt serves both. They are different functions, and what a salt is for
// is to make this file's derivation unlike any other file's.
func deriveFileKey(secret, salt []byte, c cost) ([]byte, error) {
	stretched := argon2.IDKey(secret, salt, uint32(c.time), uint32(c.memory), uint8(c.threads), keySize)
	key, err := pbkdf2.Key(sha256.New, string(stretched), salt, c.iterations, keySize)
	if err != nil {
		return nil, fmt.Errorf("keyfile: deriving the key: %w", err)
	}
	return key, nil
}

// aeadFor derives the key and builds the cipher.
func aeadFor(secret, salt []byte, c cost) (cipher.AEAD, error) {
	key, err := deriveFileKey(secret, salt, c)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// aad is the additional data: the block type and every header, in a fixed
// order that does not depend on how the PEM was laid out. Both formats in
// this package use it, each with its own type, so a body cannot be moved
// from a block of one type into a block of the other.
func aad(blockType string, h map[string]string) []byte {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString(blockType)
	b.WriteByte('\n')
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(h[k])
		b.WriteByte('\n')
	}
	return b.Bytes()
}

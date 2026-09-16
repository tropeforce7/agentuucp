package keyfile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/pem"
	"errors"
	"fmt"
)

// The second format in this package: a key sealed under a home key rather
// than a passphrase.
//
// An auu home that has been put under a passphrase holds one file,
// home.key, in the format above — an AUU ENCRYPTED PRIVATE KEY whose
// plaintext is HomeKeySize random bytes — and every other private key in
// the home is sealed under those bytes with this format. There is no
// derivation and no salt, because the home key is uniform already; what is
// left is AES-256-GCM with a random nonce, and the block type and header
// bound in as additional data exactly as the passphrase format binds its
// own, so a body cannot be moved between the two:
//
//	-----BEGIN AUU WRAPPED PRIVATE KEY-----
//	Cipher: AES-256-GCM
//
//	<base64 of nonce || ciphertext || tag>
//	-----END AUU WRAPPED PRIVATE KEY-----
//
// The indirection is the ordinary key-wrapping kind, the same shape as a
// LUKS keyslot: unlocking is one derivation however many keys a home holds,
// changing the passphrase rewrites home.key alone, and a process that holds
// the home key can seal a new key without ever having seen the passphrase.

const (
	// WrappedBlockType is the PEM type of a key sealed under a home key.
	WrappedBlockType = "AUU WRAPPED PRIVATE KEY"

	// HomeKeySize is the length of a home key: AES-256's.
	HomeKeySize = keySize
)

var (
	// ErrWrapped is a block that is not a wrapped key.
	ErrWrapped = errors.New("not a wrapped key file")
	// ErrHomeKey is a wrapped body that would not open: the home key is
	// wrong or the file has been altered, and the AEAD cannot tell which.
	ErrHomeKey = errors.New("wrong home key, or the file has been altered")
	// ErrHomeKeySize is a home key of the wrong length.
	ErrHomeKeySize = fmt.Errorf("a home key is %d bytes", HomeKeySize)
)

// wrappedHeaders is every header a wrapped block has, and the only ones it
// may have.
var wrappedHeaders = []string{hdrCipher}

// Wrap seals der under a home key. The result is a PEM block of type
// WrappedBlockType with a Cipher header, sealed with AES-256-GCM and a
// random nonce, the headers bound in as additional data.
func Wrap(der, homeKey []byte) ([]byte, error) {
	aead, err := homeAEAD(homeKey)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{hdrCipher: cipherGCM}
	body := aead.Seal(nil, nil, der, aad(WrappedBlockType, headers))
	return pem.EncodeToMemory(&pem.Block{Type: WrappedBlockType, Headers: headers, Bytes: body}), nil
}

// Unwrap reverses Wrap. It returns ErrWrapped when the bytes are not a
// wrapped block, and ErrHomeKey when the key is wrong or the file altered.
func Unwrap(pemBytes, homeKey []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrWrapped)
	}
	return UnwrapBlock(block, homeKey)
}

// UnwrapBlock is Unwrap on a block already parsed.
func UnwrapBlock(block *pem.Block, homeKey []byte) ([]byte, error) {
	if block.Type != WrappedBlockType {
		return nil, fmt.Errorf("%w: a %q block", ErrWrapped, block.Type)
	}
	for _, want := range wrappedHeaders {
		if _, ok := block.Headers[want]; !ok {
			return nil, fmt.Errorf("keyfile: no %s header", want)
		}
	}
	if len(block.Headers) != len(wrappedHeaders) {
		for k := range block.Headers {
			if k != hdrCipher {
				return nil, fmt.Errorf("keyfile: unknown header %q", k)
			}
		}
	}
	if ci := block.Headers[hdrCipher]; ci != cipherGCM {
		return nil, fmt.Errorf("keyfile: unknown cipher %q; this build knows %s", ci, cipherGCM)
	}
	if len(block.Bytes) < nonceSize+tagSize {
		return nil, fmt.Errorf("keyfile: body is %d bytes, shorter than a nonce and a tag", len(block.Bytes))
	}
	aead, err := homeAEAD(homeKey)
	if err != nil {
		return nil, err
	}
	der, err := aead.Open(nil, nil, block.Bytes, aad(WrappedBlockType, block.Headers))
	if err != nil {
		return nil, ErrHomeKey
	}
	return der, nil
}

// IsWrapped says whether pemBytes hold a key sealed under a home key. It
// reads the block's type and nothing else.
func IsWrapped(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	return block != nil && block.Type == WrappedBlockType
}

// homeAEAD is the cipher a home key selects.
func homeAEAD(homeKey []byte) (cipher.AEAD, error) {
	if len(homeKey) != HomeKeySize {
		return nil, ErrHomeKeySize
	}
	block, err := aes.NewCipher(homeKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

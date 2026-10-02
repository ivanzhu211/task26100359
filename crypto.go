package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	kdfIterations = 600000
	keyLen        = 32
	saltLen       = 16
	nonceLen      = 12
)

// verifierPlain is a fixed constant encrypted under the master key and stored
// in meta; a successful GCM open proves the passphrase-derived key is correct.
var verifierPlain = []byte("vault-master-verifier-v1")

func deriveKey(passphrase string, salt []byte, iter int) ([32]byte, error) {
	raw, err := pbkdf2.Key(sha256.New, passphrase, salt, iter, keyLen)
	if err != nil {
		return [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], raw)
	return key, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func seal(key *[32]byte, plaintext []byte) (nonce, ct []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(nonceLen)
	if err != nil {
		return nil, nil, err
	}
	ct = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ct, nil
}

func open(key *[32]byte, nonce, ct []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func newGCM(key *[32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var errBadPassphrase = errors.New("vault: bad passphrase")

// checkVerifier reports whether key matches the stored verifier ciphertext.
func checkVerifier(key *[32]byte, nonce, ct []byte) bool {
	plain, err := open(key, nonce, ct)
	if err != nil {
		return false
	}
	if len(plain) != len(verifierPlain) {
		return false
	}
	for i := range plain {
		if plain[i] != verifierPlain[i] {
			return false
		}
	}
	return true
}

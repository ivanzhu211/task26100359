package keyvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	masterKeyLen   = 32
	gcmNonceLen    = 12
	kdfSaltLen     = 16
	kdfIterations  = 600000
	keyMaterialLen = 32
)

// deriveMasterKey derives a 32-byte master key from a passphrase and salt
// using PBKDF2-SHA256 with the given iteration count.
func deriveMasterKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	if iterations < kdfIterations {
		return nil, errWeakKDF
	}
	return pbkdf2.Key([]byte(passphrase), salt, iterations, masterKeyLen, sha256.New), nil
}

// encryptBlob encrypts plaintext with AES-256-GCM under key, returning
// nonce and ciphertext.
func encryptBlob(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// decryptBlob decrypts ciphertext with AES-256-GCM under key.
func decryptBlob(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zeroBytes best-effort wipes a byte slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

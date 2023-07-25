package abstractcypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Encrypt encrypts a plaintext string using AES 256 encryption with the given key.
// Returns the encrypted string as a hex-encoded string.
func Encrypt(key []byte, plaintext string) (string, error) {
	// Generate AES cipher block from key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad plaintext to multiple of block size
	paddedPlaintext := padPlaintext([]byte(plaintext), block.BlockSize())

	// Generate initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Encrypt padded plaintext using AES CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Combine IV and ciphertext into single byte slice
	encrypted := make([]byte, len(iv)+len(ciphertext))
	copy(encrypted[:aes.BlockSize], iv)
	copy(encrypted[aes.BlockSize:], ciphertext)

	// Return hex-encoded encrypted string
	return hex.EncodeToString(encrypted), nil
}

// Decrypt decrypts a hex-encoded encrypted string using AES 256 encryption with the given key.
// Returns the decrypted plaintext string.
func Decrypt(key []byte, encrypted string) (string, error) {
	// Decode hex-encoded encrypted string
	encryptedBytes, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	// Generate AES cipher block from key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Split IV and ciphertext from encrypted bytes
	iv := encryptedBytes[:aes.BlockSize]
	ciphertext := encryptedBytes[aes.BlockSize:]

	// Decrypt ciphertext using AES CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	paddedPlaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(paddedPlaintext, ciphertext)

	// Unpad plaintext
	plaintext, err := unpadPlaintext(paddedPlaintext, block.BlockSize())
	if err != nil {
		return "", err
	}

	// Return decrypted plaintext string
	return string(plaintext), nil
}

// HashSHA256 hashes a plaintext string using SHA2-256 hashing.
// Returns the hash as a hex-encoded string.
func HashSHA256(plaintext string) string {
	hasher := sha256.New()
	hasher.Write([]byte(plaintext))
	return hex.EncodeToString(hasher.Sum(nil))
}

// padPlaintext pads a plaintext byte slice to a multiple of the block size using PKCS#7 padding.
func padPlaintext(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// unpadPlaintext removes PKCS#7 padding from a padded plaintext byte slice.
func unpadPlaintext(paddedPlaintext []byte, blockSize int) ([]byte, error) {
	padding := int(paddedPlaintext[len(paddedPlaintext)-1])
	if padding < 1 || padding > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := 1; i <= padding; i++ {
		if paddedPlaintext[len(paddedPlaintext)-i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return paddedPlaintext[:len(paddedPlaintext)-padding], nil
}

package abstractcypto_test

import (
	"abstractcypto"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	// Test encryption and decryption of empty string
	plaintext := ""
	encrypted, err := abstractcypto.Encrypt(key, plaintext)
	if err != nil {
		t.Errorf("Encrypt returned error: %v", err)
	}
	decrypted, err := abstractcypto.Decrypt(key, encrypted)
	if err != nil {
		t.Errorf("Decrypt returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypt returned %q, expected %q", decrypted, plaintext)
	}

	// Test encryption and decryption of non-empty string
	plaintext = "hello, world!"
	encrypted, err = abstractcypto.Encrypt(key, plaintext)
	if err != nil {
		t.Errorf("Encrypt returned error: %v", err)
	}
	decrypted, err = abstractcypto.Decrypt(key, encrypted)
	if err != nil {
		t.Errorf("Decrypt returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypt returned %q, expected %q", decrypted, plaintext)
	}
}

func TestHashSHA256(t *testing.T) {
	// Test hashing of empty string
	plaintext := ""
	hash := abstractcypto.HashSHA256(plaintext)
	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expectedHash {
		t.Errorf("HashSHA256 returned %q, expected %q", hash, expectedHash)
	}

	// Test hashing of non-empty string
	plaintext = "hello, world!"
	hash = abstractcypto.HashSHA256(plaintext)
	expectedHash = "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728"
	if hash != expectedHash {
		t.Errorf("HashSHA256 returned %q, expected %q", hash, expectedHash)
	}
}

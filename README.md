# abstractcypto
The idea of this simple library is to extract away some of the basics involved in cryptography. It is not meant to be a full fledged library, but rather a simple way to get started with cryptography. It is 100% covered by unit tests and this can be used in production code safely but you may want to do more with this.

## Usage
```go
import (
	"github.com/greenygh0st/abstractcrypto"
)

key := []byte("0123456789abcdef0123456789abcdef")
plaintext := "hello, world!"

// Encrypt plaintext using AES 256 encryption
encrypted, err := cryptoutil.Encrypt(key, plaintext)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Encrypted:", encrypted)

// Decrypt encrypted string using AES 256 encryption
decrypted, err := cryptoutil.Decrypt(key, encrypted)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Decrypted:", decrypted)

// Hash plaintext using SHA2-256 hashing
hash := cryptoutil.HashSHA256(plaintext)
fmt.Println("Hash:", hash)
```

## Testing 
`go test`

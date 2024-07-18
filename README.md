# HPPK: Homomorphic Polynomial Public Key

![348665850-c2575c66-4f87-42a9-8b86-e81991de03c0](https://github.com/user-attachments/assets/31b9dc56-f353-4df8-9aca-247a5c8d79ad)

[![GoDoc][1]][2] [![Go Report Card][3]][4]

[1]: https://godoc.org/github.com/xtaci/hppk?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/hppk
[3]: https://goreportcard.com/badge/github.com/xtaci/hppk
[4]: https://goreportcard.com/report/github.com/xtaci/hppk

## Overview

HPPK is an implementation of a Homomorphic Polynomial Public Key (HPPK) system, designed for both Key Encapsulation Mechanisms (KEM) and Digital Signatures (DS). This cryptographic protocol leverages the properties of polynomials to create secure, efficient methods for key exchange and message signing.

The main objectives of HPPK are to provide:

- **Secure key encapsulation**: Facilitating the secure exchange of symmetric keys.
- **Robust digital signatures**: Ensuring the authenticity and integrity of messages.

For a detailed explanation of the underlying theory and security proofs, please refer to the [research paper](https://arxiv.org/pdf/2402.01852).

## Features

- **Homomorphic Encryption**: Allows computations on ciphertexts that result in encrypted outcomes, which match the operations performed on the plaintexts.
- **Polynomial-Based Cryptography**: Utilizes polynomials to create robust public and private keys.
- **Efficient Key Encapsulation Mechanism (KEM)**: Securely exchanges symmetric keys.
- **Strong Digital Signatures (DS)**: Provides authentication and integrity verification of messages.
- **Scalable and Efficient**: Suitable for various applications, ranging from small-scale systems to large, complex networks.
  
![348681154-37b88d3c-9bd6-4436-9837-1a0b078e5ac1](https://github.com/user-attachments/assets/8bd6fd28-b7be-4c0e-b417-7ab5e95b13bc)


## Installation

To use HPPK, you need to have Go installed. You can download and install Go from [the official website](https://golang.org/dl/).

1. Clone the repository:

    ```console
    git clone https://github.com/xtaci/hppk.git
    cd hppk
    ```

2. Build the project:

    ```console
    go build
    ```

## Usage

### Generating Keys

To generate a new pair of private and public keys:

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privateKey, err := hppk.GenerateKey(5)
    if err != nil {
        fmt.Println("Error generating keys:", err)
        return
    }
    fmt.Println("Private Key:", privateKey)
    fmt.Println("Public Key:", privateKey.PublicKey)
}
```

### Encryption

To encrypt a message using the public key:

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privKey, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pubKey := privKey.Public()

    message := []byte("hello world")
    kem, err := hppk.Encrypt(pubKey, message)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted KEM: %+v\n", kem)
}
```

### Decryption

To decrypt the encrypted values using the private key:

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privKey, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pubKey := privKey.Public()

    message := []byte("hello world")
    kem, err := hppk.Encrypt(pubKey, message)
    if err != nil {
        panic(err)
    }

    decryptedMessage, err := privKey.Decrypt(kem)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted Message: %s\n", decryptedMessage)
}
```

### Signing
```go
package main

import (
    "crypto/sha256"
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privKey, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }

    digest := sha256.Sum256([]byte("hello world"))
    signature, err := privKey.Sign(digest[:])
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %+v\n", signature)
}

```

### Verification
```go
package main

import (
    "crypto/sha256"
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privKey, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pubKey := privKey.Public()

    digest := sha256.Sum256([]byte("hello world"))
    signature, err := privKey.Sign(digest[:])
    if err != nil {
        panic(err)
    }

    isValid := hppk.VerifySignature(signature, digest[:], pubKey)
    fmt.Printf("Signature valid: %v\n", isValid)
}


```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or additional features.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

## References

For more detailed information, please refer to the [research paper](https://arxiv.org/pdf/2402.01852).

## Acknowledgments

Special thanks to the authors of the research paper for their groundbreaking work on HPPK and its applications in KEM and DS.

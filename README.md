# HPPK: Homomorphic Polynomial Public Key

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Installation

To use HPPK, you need to have Go installed. You can download and install Go from [the official website](https://golang.org/dl/).

1. Clone the repository:

    ```bash
    git clone https://github.com/xtaci/hppk.git
    cd hppk
    ```

2. Build the project:

    ```bash
    go build
    ```

## Usage

### Generating Keys

To generate a new pair of private and public keys:

```go
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

### Encrypting a Message

To encrypt a message using the public key:

```go
import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privateKey, _ := hppk.GenerateKey(5)
    publicKey := privateKey.PublicKey
    message := []byte("Hello, World!")
    
    P, Q, err := privateKey.Encrypt(&publicKey, message)
    if err != nil {
        fmt.Println("Error encrypting message:", err)
        return
    }
    fmt.Println("Encrypted P:", P)
    fmt.Println("Encrypted Q:", Q)
}
```

### Decrypting a Message

To decrypt the encrypted values using the private key:

```go
import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    privateKey, _ := hppk.GenerateKey(5)
    publicKey := privateKey.PublicKey
    message := []byte("Hello, World!")
    
    P, Q, _ := privateKey.Encrypt(&publicKey, message)
    decryptedMessage, err := privateKey.Decrypt(P, Q)
    if err != nil {
        fmt.Println("Error decrypting message:", err)
        return
    }
    fmt.Println("Decrypted Message:", string(decryptedMessage.Bytes()))
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or additional features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## References

For more detailed information, please refer to the [research paper](https://arxiv.org/pdf/2402.01852).

## Acknowledgments

Special thanks to the authors of the research paper for their groundbreaking work on HPPK and its applications in KEM and DS.
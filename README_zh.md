## HPPK: 同态多项式公钥密码学

[English](README.md) | [中文](README_zh.md)

[![GoDoc][1]][2] [![Go Report Card][3]][4] [![CreatedAt][5]][6] 

[1]: https://godoc.org/github.com/xtaci/hppk?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/hppk
[3]: https://goreportcard.com/badge/github.com/xtaci/hppk
[4]: https://goreportcard.com/report/github.com/xtaci/hppk
[5]: https://img.shields.io/github/created-at/xtaci/hppk
[6]: https://img.shields.io/github/created-at/xtaci/hppk

## 概览

HPPK 是同态多项式公钥（Homomorphic Polynomial Public Key）系统的实现，设计用于密钥封装机制（KEM）和数字签名（DS）。该加密协议利用多项式的特性，为密钥交换和消息签名提供了安全、高效的方法。

HPPK 的主要目标是提供：

- **安全的密钥封装**：促进对称密钥的安全交换。
- **稳健的数字签名**：确保消息的真实性和完整性。

有关底层理论和安全性证明的详细解释，请参阅[研究论文](https://arxiv.org/pdf/2402.01852)。

## 特性

- **同态加密**：允许对密文进行计算，其结果是加密的，解密后与对明文执行相同操作的结果一致。
- **基于多项式的密码学**：利用多项式创建稳健的公钥和私钥。
- **高效的密钥封装机制 (KEM)**：安全地交换对称密钥。
- **强大的数字签名 (DS)**：提供消息的身份验证和完整性验证。
- **可扩展且高效**：适用于各种应用场景，从小型系统到大型复杂网络。
  
![348681154-37b88d3c-9bd6-4436-9837-1a0b078e5ac1](https://github.com/user-attachments/assets/8bd6fd28-b7be-4c0e-b417-7ab5e95b13bc)


## 使用库

要使用 HPPK，您需要安装 Go。您可以从[官方网站](https://golang.org/dl/)下载并安装 Go。

1. 克隆仓库：

    ```console
    git clone https://github.com/xtaci/hppk.git
    cd hppk
    ```

2. 构建项目：

    ```console
    go build
    ```

## 使用方法

### 生成密钥

生成一对新的私钥和公钥：

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

### 加密

使用公钥加密消息：

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

### 解密

使用私钥解密加密值：

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

### 签名

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

### 验签

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

## 贡献

欢迎贡献！请提交 Issue 或 Pull Request 以进行任何改进、错误修复或添加新功能。

## 许可证

本项目采用 GPLv3 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 参考文献
* QPP and HPPK: Unifying Non-Commutativity for Quantum-Secure Cryptography with Galois Permutation Group (https://arxiv.org/pdf/2402.01852).
* Homomorphic Polynomial Public Key Cryptography for Quantum-secure Digital Signature (https://www.academia.edu/123150574/Homomorphic_Polynomial_Public_Key_Cryptography_for_Quantum_secure_Digital_Signature?email_work_card=view-paper)

## 致谢

特别感谢研究论文的作者在 HPPK 及其在 KEM 和 DS 中的应用方面所做的开创性工作。

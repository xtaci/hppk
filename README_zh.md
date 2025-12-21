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

HPPK（Homomorphic Polynomial Public Key）是一个完整实现的同态多项式公钥密码系统，原生支持密钥封装机制（KEM）与数字签名（DS）。协议通过在多项式环上构造公私钥对，以同态运算保障密钥协商与签名场景中的安全性与效率。

核心目标：

- **安全密钥封装**：实现对称密钥在不可信信道中的安全分发。
- **稳健数字签名**：提供可验证的消息认证与防篡改能力。
- **量子安全设计**：基础原理详见[研究论文](https://arxiv.org/pdf/2402.01852)。

## 特性

- **同态友好**：支持在密文域执行多项式运算，解密后结果与明文直接运算保持一致。
- **多项式结构**：利用多项式系数与排列的组合构造公钥体系，既可扩展又便于实现。
- **高效 KEM**：提供轻量化的共享密钥建立接口，易于集成到协议中。
- **强签名能力**：内置签名与验签 API，支持常规摘要算法产生的哈希值。
- **工程可扩展**：代码清晰、接口稳定，适配从嵌入式到分布式的多种部署形态。

![348681154-37b88d3c-9bd6-4436-9837-1a0b078e5ac1](https://github.com/user-attachments/assets/8bd6fd28-b7be-4c0e-b417-7ab5e95b13bc)

## 快速开始

使用 HPPK 需要先安装 Go，可前往[官方页面](https://golang.org/dl/)获取。

1. 克隆仓库：

    ```console
    git clone https://github.com/xtaci/hppk.git
    cd hppk
    ```

2. 构建库及工具：

    ```console
    go build ./...
    ```

## API 示例

### 生成密钥

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    priv, err := hppk.GenerateKey(5)
    if err != nil {
        fmt.Println("生成密钥失败:", err)
        return
    }
    fmt.Println("Private Key:", priv)
    fmt.Println("Public Key:", priv.PublicKey)
}
```

### 加密

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    priv, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pub := priv.Public()

    msg := []byte("hello world")
    kem, err := hppk.Encrypt(pub, msg)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted KEM: %+v\n", kem)
}
```

### 解密

```go
package main

import (
    "fmt"
    "github.com/xtaci/hppk"
)

func main() {
    priv, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pub := priv.Public()

    msg := []byte("hello world")
    kem, err := hppk.Encrypt(pub, msg)
    if err != nil {
        panic(err)
    }

    plain, err := priv.Decrypt(kem)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted Message: %s\n", plain)
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
    priv, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }

    digest := sha256.Sum256([]byte("hello world"))
    sig, err := priv.Sign(digest[:])
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %+v\n", sig)
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
    priv, err := hppk.GenerateKey(10)
    if err != nil {
        panic(err)
    }
    pub := priv.Public()

    digest := sha256.Sum256([]byte("hello world"))
    sig, err := priv.Sign(digest[:])
    if err != nil {
        panic(err)
    }

    ok := hppk.VerifySignature(sig, digest[:], pub)
    fmt.Printf("Signature valid: %v\n", ok)
}
```

## 贡献

任何关于性能优化、漏洞修复或功能扩展的想法都欢迎通过 Issue 与 Pull Request 提交。请在提交前确认代码通过现有测试并遵循项目编码风格。

## 许可证

本项目以 GPLv3 授权发布，详细条款见 [LICENSE](LICENSE)。

## 参考

- QPP and HPPK: Unifying Non-Commutativity for Quantum-Secure Cryptography with Galois Permutation Group (https://arxiv.org/pdf/2402.01852)
- Homomorphic Polynomial Public Key Cryptography for Quantum-secure Digital Signature (https://www.academia.edu/123150574/Homomorphic_Polynomial_Public_Key_Cryptography_for_Quantum_secure_Digital_Signature?email_work_card=view-paper)

## 致谢

致谢相关研究工作为 HPPK 的设计与实现奠定了理论与工程基础。

package hppk

import (
	"bytes"
	"crypto/rand"
	"log"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(5)
	assert.Nil(t, err, "GenerateKey() failed")
	gcd := new(big.Int)
	one := big.NewInt(1)
	assert.Equal(t, gcd.GCD(nil, nil, key.r1, key.s1), one, "GCD(r0, s0) != 1")
	assert.Equal(t, gcd.GCD(nil, nil, key.r2, key.s2), one, "GCD(r1, s1) != 1")
}

func TestKEM(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	secret := []byte("hello quantum")
	Ps, Qs, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", secret)

	x, err := alice.Decrypt(Ps, Qs)
	assert.Nil(t, err)
	t.Log("x:", x.Bytes())

	equal := bytes.Equal(secret, x.Bytes())
	assert.True(t, equal)
}

func TestSig(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	digest := []byte("hello quantum")
	sign, err := alice.Sign(digest)
	assert.Nil(t, err)

	assert.True(t, VerifySignature(sign, digest, &alice.PublicKey))
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(5)
	}
}

func TestRing(t *testing.T) {
	prime := big.NewInt(977)
	r0, s0, _ := createCoPrimePair(prime)
	revR0 := new(big.Int).ModInverse(r0, s0)
	log.Println(r0, s0, revR0)
	x, _ := rand.Int(rand.Reader, prime)
	t.Log(x)
	ring(r0, s0, x)
	t.Log(x)

}

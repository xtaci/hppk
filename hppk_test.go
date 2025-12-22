// # Copyright (c) 2024 xtaci
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package hppk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenerateKey tests the key generation
func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(5)
	assert.Nil(t, err, "GenerateKey() failed")
	gcd := new(big.Int)
	one := big.NewInt(1)
	assert.Equal(t, key.Order(), 5)
	assert.Equal(t, gcd.GCD(nil, nil, key.R1, key.S1), one, "GCD(r0, s0) != 1")
	assert.Equal(t, gcd.GCD(nil, nil, key.R2, key.S2), one, "GCD(r1, s1) != 1")
}

// TestKEM tests the key encapsulation mechanism
func TestKEM(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	secret := []byte("hello quantum")
	kem, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", secret)

	x, err := alice.Decrypt(kem)
	assert.Nil(t, err)
	t.Log("x:", x.Bytes())

	equal := bytes.Equal(secret, x.Bytes())
	assert.True(t, equal)
}

// TestDigitalSignature tests the digital signature
func TestDigitalSignature(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	digest := []byte("hello quantum")
	sign, err := alice.Sign(digest)
	assert.Nil(t, err)

	assert.True(t, VerifySignature(sign, digest, &alice.PublicKey))
}

// BenchmarkGenerateKey benchmarks the key generation
func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(5)
	}
}

// BenchmarkSigning benchmarks the signing
func BenchmarkSigning(b *testing.B) {
	alice, err := GenerateKey(10)
	assert.Nil(b, err)

	s := sha256.New()
	msg := []byte("hello quantum")
	digest := s.Sum(msg)

	for i := 0; i < b.N; i++ {
		alice.Sign(digest)
	}
}

// BenchmarkVerification benchmarks the verification
func BenchmarkVerification(b *testing.B) {
	alice, err := GenerateKey(10)
	assert.Nil(b, err)

	s := sha256.New()
	msg := []byte("hello quantum")
	digest := s.Sum(msg)
	sign, err := alice.Sign(digest)
	assert.Nil(b, err)

	for i := 0; i < b.N; i++ {
		VerifySignature(sign, digest, &alice.PublicKey)
	}
}

func TestRing(t *testing.T) {
	prime := big.NewInt(977)
	r0, s0, _ := createCoPrimePair(10, prime)
	revR0 := new(big.Int).ModInverse(r0, s0)
	log.Println(r0, s0, revR0)
	x, _ := rand.Int(rand.Reader, prime)
	t.Log(x)
	ring(r0, s0, x)
	t.Log(x)
}

// TestClientServerAuthFlow simulates a challenge-response authentication round.
func TestClientServerAuthFlow(t *testing.T) {
	client, err := GenerateKey(8)
	assert.Nil(t, err)

	serverKnownPub := client.Public()

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	assert.Nil(t, err)

	signature, err := client.Sign(challenge)
	assert.Nil(t, err)

	assert.True(t, VerifySignature(signature, challenge, serverKnownPub))

	tampered := make([]byte, len(challenge))
	copy(tampered, challenge)
	tampered[0] ^= 0xFF

	assert.False(t, VerifySignature(signature, tampered, serverKnownPub))
}

// TestClientServerAuthFlowWithSerialization adds a serialization hop to mimic network transport.
func TestClientServerAuthFlowWithSerialization(t *testing.T) {
	client, err := GenerateKey(8)
	assert.Nil(t, err)

	pubBytes, err := client.Public().MarshalBinary()
	assert.Nil(t, err)

	var serverPub PublicKey
	assert.Nil(t, serverPub.UnmarshalBinary(pubBytes))

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	assert.Nil(t, err)

	signature, err := client.Sign(challenge)
	assert.Nil(t, err)

	sigPayload, err := json.Marshal(signature)
	assert.Nil(t, err)

	var receivedSig Signature
	assert.Nil(t, json.Unmarshal(sigPayload, &receivedSig))

	assert.True(t, VerifySignature(&receivedSig, challenge, &serverPub))

	corruptedChallenge := append([]byte(nil), challenge...)
	corruptedChallenge[0] ^= 0x01
	assert.False(t, VerifySignature(&receivedSig, corruptedChallenge, &serverPub))
}

// TestPublicKeyIsValid tests the IsValid method of PublicKey
func TestPublicKeyIsValid(t *testing.T) {
	prime := big.NewInt(17)
	validP := []*big.Int{big.NewInt(1), big.NewInt(2)}
	validQ := []*big.Int{big.NewInt(3), big.NewInt(4)}
	pub := &PublicKey{Prime: prime, P: validP, Q: validQ}
	assert.True(t, pub.IsValid(), "Valid PublicKey should return true")

	// nil Prime
	pub1 := &PublicKey{Prime: nil, P: validP, Q: validQ}
	assert.False(t, pub1.IsValid(), "Nil Prime should return false")

	// P and Q length mismatch
	pub2 := &PublicKey{Prime: prime, P: validP, Q: []*big.Int{big.NewInt(1)}}
	assert.False(t, pub2.IsValid(), "Length mismatch should return false")

	// P contains nil
	pub3 := &PublicKey{Prime: prime, P: []*big.Int{nil, big.NewInt(2)}, Q: validQ}
	assert.False(t, pub3.IsValid(), "P contains nil should return false")

	// Q contains nil
	pub4 := &PublicKey{Prime: prime, P: validP, Q: []*big.Int{nil, big.NewInt(2)}}
	assert.False(t, pub4.IsValid(), "Q contains nil should return false")

	// P out of range
	pub5 := &PublicKey{Prime: prime, P: []*big.Int{big.NewInt(18), big.NewInt(2)}, Q: validQ}
	assert.False(t, pub5.IsValid(), "P out of range should return false")

	// Q out of range
	pub6 := &PublicKey{Prime: prime, P: validP, Q: []*big.Int{big.NewInt(3), big.NewInt(18)}}
	assert.False(t, pub6.IsValid(), "Q out of range should return false")

	// P negative
	pub7 := &PublicKey{Prime: prime, P: []*big.Int{big.NewInt(-1), big.NewInt(2)}, Q: validQ}
	assert.False(t, pub7.IsValid(), "P negative should return false")

	// Q negative
	pub8 := &PublicKey{Prime: prime, P: validP, Q: []*big.Int{big.NewInt(-1), big.NewInt(2)}}
	assert.False(t, pub8.IsValid(), "Q negative should return false")
}

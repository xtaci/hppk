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
	"crypto/rand" // Importing package for cryptographic random number generation
	"errors"      // Importing package for error handling
	"math/big"    // Importing package for handling arbitrary precision arithmetic
)

// DefaultPrime is a large prime number used in cryptographic operations.
const DefaultPrime = "0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d5"

const MULTIVARIATE = 5 // default variants

// Error messages for various conditions.
const (
	ERR_MSG_ORDER           = "order must be at least 5"
	ERR_MSG_NULL_ENCRYPTION = "encrypted values cannot be null"
	ERR_MSG_DATA_EXCEEDED   = "the secret to encrypt is not in the GF(p)"
	ERR_MSG_INVALID_PUBKEY  = "public key is invalid"
	ERR_MSG_INVALID_KEM     = "invalid kem value"
	ERR_MSG_INVALID_PRIME   = "invalid prime number"
)

// defaultPrime is the prime number used in cryptographic operations.
var defaultPrime *big.Int

var (
	errInvalidPrime = errors.New("Invalid Prime")
)

func init() {
	defaultPrime, _ = new(big.Int).SetString(DefaultPrime, 0)
}

// PrivateKey represents a private key in the HPPK protocol.
type PrivateKey struct {
	R1, S1    *big.Int // r1 and s1 are coprimes
	R2, S2    *big.Int // r2 and s2 are coprimes
	F0, F1    *big.Int // f(x) = f1x + f0
	H0, H1    *big.Int // h(x) = h1x + h0
	PublicKey          // Embedding PublicKey structure
}

// PublicKey represents a public key in the HPPK protocol.
type PublicKey struct {
	Prime *big.Int   // Prime number used for cryptographic operations
	P     []*big.Int // Coefficients of the polynomial P(x)
	Q     []*big.Int // Coefficients of the polynomial Q(x)
}

// Signature represents a digital signature in the HPPK protocol.
type Signature struct {
	Beta               *big.Int   // a randomly choosen number from Fp
	F, H               *big.Int   // F & H is calculated from the private key
	S1Verify, S2Verify *big.Int   // S1Verify := beta * s1 mod p, S2Verify := beta * s2 mod p
	U, V               []*big.Int // U = ⌊ R*P /S1 ⌋, V = ⌊ R*Q /S2 ⌋
	K                  int        // R = 2^K
}

// KEM represents the Encapsulated Key in the HPPK protocol.
type KEM struct {
	P *big.Int
	Q *big.Int
}

// Equal checks if two public keys are equal
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if len(pub.P) != len(other.P) || len(pub.Q) != len(other.Q) {
		return false
	}

	for i := 0; i < len(pub.P); i++ {
		if pub.P[i].Cmp(other.P[i]) != 0 {
			return false
		}
	}

	for i := 0; i < len(pub.Q); i++ {
		if pub.Q[i].Cmp(other.Q[i]) != 0 {
			return false
		}
	}

	return true
}

// GenerateKey generates a new HPPK private key with the given order and default prime number.
func GenerateKey(order int) (*PrivateKey, error) {
	return generateKey(order, defaultPrime)
}

// GenerateKey generates a new HPPK private key with the given order and custom prime number.
func GenerateKeyWithPrime(order int, strPrime string) (*PrivateKey, error) {
	customPrime, ok := big.NewInt(0).SetString(strPrime, 0)
	if !ok {
		return nil, errInvalidPrime
	}
	return generateKey(order, customPrime)
}

func generateKey(order int, prime *big.Int) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New(ERR_MSG_ORDER)
	}

RETRY:
	// Generate coprime pairs (r1, s1) and (r2, s2)
	r1, s1, err := createCoPrimePair(order+2, prime)
	if err != nil {
		return nil, err
	}
	r2, s2, err := createCoPrimePair(order+2, prime)
	if err != nil {
		return nil, err
	}

	// Generate random coefficients for f(x) and h(x)
	f0, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}
	f1, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}
	h0, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}
	h1, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	// Ensure all pairs are distinct
	if r1.Cmp(r2) == 0 || s1.Cmp(s2) == 0 || f0.Cmp(h0) == 0 || f1.Cmp(h1) == 0 {
		goto RETRY
	}

	// Ensure f(x) and h(x) are not linear depending by checking it's coefficients
	// f(x) = f1x + f0 => f(x)/f0 = f1/f0 * x + 1
	// h(x) = h1x + h0 => h(x)/h1 = h1/h0 * x + 1
	// by comparing the ratio of f1/f0 and h1/h0, we can ensure that f(x) and h(x) are not linear dependent
	revF0 := new(big.Int).ModInverse(f0, prime)
	revH0 := new(big.Int).ModInverse(h0, prime)

	f1RevF0 := new(big.Int).Mul(f1, revF0)
	h1RevH0 := new(big.Int).Mul(h1, revH0)

	f1RevF0.Mod(f1RevF0, prime)
	h1RevH0.Mod(h1RevH0, prime)
	if f1RevF0.Cmp(h1RevH0) == 0 {
		goto RETRY
	}

	// Generate random coefficients for the polynomial Bn(x)
	Bn := make([]*big.Int, order)
	for i := 0; i < len(Bn); i++ {
		r, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		Bn[i] = r
	}
	Bn = append(Bn, big.NewInt(1))

	// Initialize P and Q with zero values
	P := make([]*big.Int, len(Bn)+1)
	Q := make([]*big.Int, len(Bn)+1)
	for i := 0; i < len(P); i++ {
		P[i] = big.NewInt(0)
		Q[i] = big.NewInt(0)
	}

	t := new(big.Int)
	// Multiply f(x) and h(x) with Bn to get P and Q
	for i := 0; i < len(Bn); i++ {
		// Vector P
		t.Mul(f0, Bn[i])
		P[i].Add(P[i], t)
		P[i].Mod(P[i], prime)

		t.Mul(f1, Bn[i])
		P[i+1].Add(P[i+1], t)
		P[i+1].Mod(P[i+1], prime)

		// Vector Q
		t.Mul(h0, Bn[i])
		Q[i].Add(Q[i], t)
		Q[i].Mod(Q[i], prime)

		t.Mul(h1, Bn[i])
		Q[i+1].Add(Q[i+1], t)
		Q[i+1].Mod(Q[i+1], prime)
	}

	// Convert P, Q to Ring S
	for i := 0; i < len(P); i++ {
		ring(r1, s1, P[i])
		ring(r2, s2, Q[i])
	}

	// Return the generated private key
	return &PrivateKey{
		R1: r1,
		S1: s1,
		R2: r2,
		S2: s2,
		F0: f0,
		F1: f1,
		H0: h0,
		H1: h1,
		PublicKey: PublicKey{
			Prime: prime,
			P:     P,
			Q:     Q,
		},
	}, nil
}

// Encrypt encrypts a message using the given public key and default prime number.
func Encrypt(pub *PublicKey, msg []byte) (kem *KEM, err error) {
	return encrypt(pub, msg, pub.Prime)
}

// encrypt encrypts a message using the given public key.
func encrypt(pub *PublicKey, msg []byte, prime *big.Int) (kem *KEM, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if len(msg) == 0 {
		return nil, errors.New(ERR_MSG_NULL_ENCRYPTION)
	}

	if prime == nil {
		return nil, errors.New(ERR_MSG_INVALID_PRIME)
	}

	if secret.Cmp(prime) >= 0 {
		return nil, errors.New(ERR_MSG_DATA_EXCEEDED)
	}

	// Ensure fields in the public key are valid
	if len(pub.P) == 0 || len(pub.Q) == 0 {
		return nil, errors.New(ERR_MSG_INVALID_PUBKEY)
	}

	if len(pub.P) != len(pub.Q) {
		return nil, errors.New(ERR_MSG_INVALID_PUBKEY)
	}

	for i := 0; i < len(pub.P); i++ {
		if pub.P[i] == nil || pub.Q[i] == nil {
			return nil, errors.New(ERR_MSG_INVALID_PUBKEY)
		}
	}

	// Compute the encrypted values P and Q
	P := new(big.Int)
	Q := new(big.Int)
	t := new(big.Int)
	for c := 0; c < MULTIVARIATE; c++ {
		// Generate a random noise
		noise, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		// Initialize Si with the secret message
		Si := big.NewInt(1)

		for i := 0; i < len(pub.P); i++ {
			noised := new(big.Int).Mul(noise, Si)
			noised.Mod(noised, prime)

			P.Add(P, t.Mul(noised, pub.P[i]))
			Q.Add(Q, t.Mul(noised, pub.Q[i]))

			// Si = secret^i
			Si.Mul(Si, secret)
			Si.Mod(Si, prime)
		}
	}

	return &KEM{P: P, Q: Q}, nil
}

// Decrypt decrypts the encrypted values P and Q using the private key.
func (priv *PrivateKey) Decrypt(kem *KEM) (secret *big.Int, err error) {
	prime := priv.Prime
	// Sanity check
	if kem == nil || kem.P == nil || kem.Q == nil {
		return nil, errors.New(ERR_MSG_INVALID_KEM)
	}

	// Symmetric decryption using private key components
	revR1 := new(big.Int).ModInverse(priv.R1, priv.S1)
	revR2 := new(big.Int).ModInverse(priv.R2, priv.S2)

	pbar := new(big.Int).Set(kem.P)
	qbar := new(big.Int).Set(kem.Q)
	pbar.Mul(pbar, revR1)
	qbar.Mul(qbar, revR2)
	pbar.Mod(pbar, priv.S1)
	qbar.Mod(qbar, priv.S2)
	pbar.Mod(pbar, prime)
	qbar.Mod(qbar, prime)

	// Explanation of the decryption process:
	// pbar := Bn * (f1*(noise*x) + f0 * noise * 1) mod p
	// qbar := Bn * (h1*(noise*x) + h0 * noise * 1) mod p
	//
	// Multiplying both sides by the inverse of Bn gives:
	// pbar*revBn(s) := (f1 * noise *x + f0 * noise * 1) mod p
	// qbar*revBn(s) := (h1 * noise *x + h0 * noise * 1) mod p
	//
	// Noise elimination:
	// revNoise * pbar*revBn(s) := (f1 * x + f0 ) mod p
	// revNoise * qbar*revBn(s) := (h1 * x + h0 ) mod p
	//
	//
	// Aligning both equations:
	// revNoise * pbar * qbar * revBn(s) := (f1 * x + f0) * qbar mod p
	// revNoise * pbar * qbar * revBn(s) := (h1 * x + h0) * pbar mod p
	//
	// Thus:
	// (f1x + f0) * qbar == (h1x + h0) * pbar mod p
	//

	// Solving the equation a * x + b = 0 for x
	f1qbar := new(big.Int).Mul(priv.F1, qbar)
	f0qbar := new(big.Int).Mul(priv.F0, qbar)
	h0pbar := new(big.Int).Mul(priv.H0, pbar)
	h1pbar := new(big.Int).Mul(priv.H1, pbar)

	f1qbar.Mod(f1qbar, prime)
	f0qbar.Mod(f0qbar, prime)
	h1pbar.Mod(h1pbar, prime)
	h0pbar.Mod(h0pbar, prime)

	a := new(big.Int)
	revh1pbar := new(big.Int).Sub(prime, h1pbar)
	a.Add(f1qbar, revh1pbar)
	a.Mod(a, prime)

	b := new(big.Int)
	revh0pbar := new(big.Int).Sub(prime, h0pbar)
	b.Add(f0qbar, revh0pbar)
	b.Mod(b, prime)

	// x := -b/a
	revB := new(big.Int).Sub(prime, b)
	revA := new(big.Int).ModInverse(a, prime)

	x := new(big.Int).Mul(revA, revB)
	x.Mod(x, prime)

	return x, nil
}

// Sign the message digest, returning a signature.
func (priv *PrivateKey) Sign(digest []byte) (sign *Signature, err error) {
	md := new(big.Int).SetBytes(digest)

	prime := priv.Prime
	// alpha is a randomly choosen number from Fp
	alpha, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	// beta is a randomly choosen number from Fp
	beta, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	// calculate alpha * f(md) mod p
	// f(x) = f1* x + f0
	alphaFx := new(big.Int).Mul(priv.F1, md)
	alphaFx.Add(alphaFx, priv.F0)
	alphaFx.Mul(alphaFx, alpha)
	alphaFx.Mod(alphaFx, prime)

	alphaHx := new(big.Int).Mul(priv.H1, md)
	alphaHx.Add(alphaHx, priv.H0)
	alphaHx.Mul(alphaHx, alpha)
	alphaHx.Mod(alphaHx, prime)

	// calculate F & H
	revR2 := new(big.Int).ModInverse(priv.R2, priv.S2)
	F := new(big.Int)
	F.Mul(revR2, alphaFx)
	F.Mod(F, priv.S2)

	revR1 := new(big.Int).ModInverse(priv.R1, priv.S1)
	H := new(big.Int)
	H.Mul(revR1, alphaHx)
	H.Mod(H, priv.S1)

	// calculate V & U
	S1Pub := new(big.Int).Mul(beta, priv.S1)
	S1Pub.Mod(S1Pub, prime)
	S2Pub := new(big.Int).Mul(beta, priv.S2)
	S2Pub.Mod(S2Pub, prime)

	// Initiate V, U
	V := make([]*big.Int, len(priv.P))
	U := make([]*big.Int, len(priv.Q))

	// make K >= L+ 32
	K := priv.S1.BitLen()
	if priv.S2.BitLen() > K {
		K = priv.S2.BitLen()
	}
	K += 32
	R := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(K)), nil)

	for i := 0; i < len(V); i++ {
		V[i] = new(big.Int).Mul(priv.Q[i], R)
		V[i].Quo(V[i], priv.S2)

		U[i] = new(big.Int).Mul(priv.P[i], R)
		U[i].Quo(U[i], priv.S1)
	}

	sig := &Signature{
		Beta:     beta,
		F:        F,
		H:        H,
		V:        V,
		U:        U,
		S1Verify: S1Pub,
		S2Verify: S2Pub,
		K:        K,
	}
	return sig, nil
}

// Public returns the public key of the private key.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

// Order returns the polynomial order of the private key.
func (priv *PrivateKey) Order() int {
	return len(priv.PublicKey.P) - 2
}

// VerifySignature verifies the signature of the message digest using the public key and default prime
func VerifySignature(sig *Signature, digest []byte, pub *PublicKey) bool {
	return verifySignature(sig, digest, pub, pub.Prime)
}

func verifySignature(sig *Signature, digest []byte, pub *PublicKey, prime *big.Int) bool {
	// Ensure fields in the public key are valid
	if len(digest) == 0 {
		return false
	}

	if sig == nil {
		return false
	}

	if prime == nil {
		return false
	}

	if len(pub.P) == 0 || len(pub.Q) == 0 {
		return false
	}

	if len(pub.P) != len(pub.Q) {
		return false
	}

	for i := 0; i < len(pub.P); i++ {
		if pub.P[i] == nil || pub.Q[i] == nil {
			return false
		}
	}

	// Initiate Q,P from public key
	Q := make([]*big.Int, len(sig.U))
	P := make([]*big.Int, len(sig.V))
	for i := 0; i < len(Q); i++ {
		Q[i] = new(big.Int).Mul(pub.Q[i], sig.Beta)
		Q[i].Mod(Q[i], prime)

		P[i] = new(big.Int).Mul(pub.P[i], sig.Beta)
		P[i].Mod(P[i], prime)
	}

	// Verify signature
	t := new(big.Int)
	md := new(big.Int).SetBytes(digest)
	sumLhs := new(big.Int)
	sumRhs := new(big.Int)

	// recover R
	R := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(sig.K)), nil)

	// verify signature
	Si := big.NewInt(1)
	for i := 0; i < len(Q); i++ {
		lhsA := new(big.Int).Mul(Q[i], sig.F)

		t.Mul(sig.F, sig.V[i])
		t.Quo(t, R)
		lhsB := new(big.Int).Mul(t, sig.S2Verify)
		lhs := new(big.Int).Sub(lhsA, lhsB)

		lhs.Mul(lhs, Si)
		sumLhs.Add(sumLhs, lhs)
		sumLhs.Mod(sumLhs, prime)

		rhsA := new(big.Int).Mul(P[i], sig.H)

		t.Mul(sig.H, sig.U[i])
		t.Quo(t, R)
		rhsB := new(big.Int).Mul(t, sig.S1Verify)
		rhs := new(big.Int).Sub(rhsA, rhsB)

		rhs.Mul(rhs, Si)
		sumRhs.Add(sumRhs, rhs)
		sumRhs.Mod(sumRhs, prime)

		Si.Mul(Si, md)
		Si.Mod(Si, prime)
	}

	return sumLhs.Cmp(sumRhs) == 0
}

// createCoPrimePair generates a pair of coprime numbers (R, S) greater than the given prime p.
func createCoPrimePair(polyTerms int, p *big.Int) (R *big.Int, S *big.Int, err error) {
	one := big.NewInt(1)

	bitLength := 2*p.BitLen() + big.NewInt(int64(polyTerms*MULTIVARIATE)).BitLen()
	L := big.NewInt(1)
	L.Lsh(L, uint(bitLength))

	for {
		R, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, nil, err
		}
		R.Add(R, L)

		S, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, nil, err
		}
		S.Add(S, L)

		// Check if GCD(R, S) == 1, which means R and S are coprime
		if new(big.Int).GCD(nil, nil, R, S).Cmp(one) == 0 {
			return R, S, nil
		}
	}
}

// ring computes R*v on the ring S
func ring(R *big.Int, S *big.Int, v *big.Int) {
	v.Mul(R, v)
	v.Mod(v, S)
}

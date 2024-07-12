package hppk

import (
	"crypto/rand" // Importing package for cryptographic random number generation
	"errors"      // Importing package for error handling
	"math/big"    // Importing package for handling arbitrary precision arithmetic
)

// PRIME is a large prime number used in cryptographic operations.
const PRIME = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

// Error messages for various conditions.
const (
	ERR_MSG_ORDER           = "order must be at least 5"
	ERR_MSG_NULL_ENCRYPTION = "encrypted values cannot be null"
	ERR_MSG_DATA_EXCEEDED   = "the secret to encrypt is not in the GF(p)"
	ERR_MSG_INVALID_PUBKEY  = "public key is invalid"
	ERR_MSG_INVALID_KEM     = "invalid kem value"
)

// PrivateKey represents a private key in the HPPK protocol.
type PrivateKey struct {
	r1, s1    *big.Int // r1 and s1 are coprimes
	r2, s2    *big.Int // r2 and s2 are coprimes
	f0, f1    *big.Int // f(x) = f1x + f0
	h0, h1    *big.Int // h(x) = h1x + h0
	PublicKey          // Embedding PublicKey structure
}

// PublicKey represents a public key in the HPPK protocol.
type PublicKey struct {
	Prime *big.Int   // Prime number used for cryptographic operations
	P     []*big.Int // Coefficients of the polynomial P(x)
	Q     []*big.Int // Coefficients of the polynomial Q(x)
}

// GenerateKey generates a new HPPK private key with the given order and default prime number.
func GenerateKey(order int) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New(ERR_MSG_ORDER)
	}

RETRY:
	// Convert the prime constant to a big.Int
	prime, _ := big.NewInt(0).SetString(PRIME, 10)
	// Generate coprime pairs (r1, s1) and (r1, s1)
	r1, s1, err := createCoPrimePair(prime)
	if err != nil {
		return nil, err
	}
	r2, s2, err := createCoPrimePair(prime)
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
	revF0 := new(big.Int).ModInverse(f0, prime)
	revH0 := new(big.Int).ModInverse(h0, prime)

	f1RevF0 := new(big.Int).Mul(f1, revF0)
	f2RevH0 := new(big.Int).Mul(f1, revH0)
	f1RevF0.Mod(f1RevF0, prime)
	f2RevH0.Mod(f2RevH0, prime)
	if f1RevF0.Cmp(f2RevH0) == 0 {
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
		r1: r1,
		s1: s1,
		r2: r2,
		s2: s2,
		f0: f0,
		f1: f1,
		h0: h0,
		h1: h1,
		PublicKey: PublicKey{
			Prime: prime,
			P:     P,
			Q:     Q,
		},
	}, nil
}

// ring computes R*v on the ring S
func ring(R *big.Int, S *big.Int, v *big.Int) {
	v.Mul(R, v)
	v.Mod(v, S)
}

// Encrypt encrypts a message using the given public key.
func Encrypt(pub *PublicKey, msg []byte) (P []*big.Int, Q []*big.Int, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(pub.Prime) >= 0 {
		return nil, nil, errors.New(ERR_MSG_DATA_EXCEEDED)
	}

	// Ensure fields in the public key are valid
	if pub.P == nil || pub.Q == nil {
		return nil, nil, errors.New(ERR_MSG_INVALID_PUBKEY)
	}

	if len(pub.P) != len(pub.Q) {
		return nil, nil, errors.New(ERR_MSG_INVALID_PUBKEY)
	}

	for i := 0; i < len(pub.P); i++ {
		if pub.P[i] == nil || pub.Q[i] == nil {
			return nil, nil, errors.New(ERR_MSG_INVALID_PUBKEY)
		}
	}

	// Generate a random noise
	noise, err := rand.Int(rand.Reader, pub.Prime)
	if err != nil {
		return nil, nil, err
	}

	// Initialize Si with the secret message
	Si := big.NewInt(1)
	// Compute the encrypted values P and Q
	P = make([]*big.Int, len(pub.P))
	Q = make([]*big.Int, len(pub.Q))

	for i := 0; i < len(pub.P); i++ {
		noised := new(big.Int).Mul(noise, Si)
		noised.Mod(noised, pub.Prime)

		P[i] = new(big.Int).Mul(noised, pub.P[i])
		Q[i] = new(big.Int).Mul(noised, pub.Q[i])

		// Si = secret^i
		Si.Mul(Si, secret)
		Si.Mod(Si, pub.Prime)
	}

	return P, Q, nil
}

// Decrypt decrypts the encrypted values P and Q using the private key.
func (priv *PrivateKey) Decrypt(P []*big.Int, Q []*big.Int) (secret *big.Int, err error) {
	// Sanity check
	if len(P) != len(Q) {
		return nil, errors.New(ERR_MSG_INVALID_KEM)
	}

	for i := 0; i < len(P); i++ {
		if P[i] == nil || Q[i] == nil {
			return nil, errors.New(ERR_MSG_INVALID_KEM)
		}
	}

	// Symmetric decryption using private key components
	revR1 := new(big.Int).ModInverse(priv.r1, priv.s1)
	revR2 := new(big.Int).ModInverse(priv.r2, priv.s2)

	pbar := new(big.Int)
	qbar := new(big.Int)
	for i := 0; i < len(P); i++ {
		t := new(big.Int).Mul(P[i], revR1)
		t.Mod(t, priv.s1)
		pbar.Add(pbar, t)

		t = new(big.Int).Mul(Q[i], revR2)
		t.Mod(t, priv.s2)
		qbar.Add(qbar, t)
	}

	pbar.Mod(pbar, priv.PublicKey.Prime)
	qbar.Mod(qbar, priv.PublicKey.Prime)

	// Explanation of the decryption process:
	// pbar := Bn * (f1*x + f0) mod p
	// qbar := Bn * (h1*x + h0) mod p
	//
	// Multiplying both sides by the inverse of Bn gives:
	// pbar*revBn(s) := (f1x + f0) mod p
	// qbar*revBn(s) := (h1x + h0) mod p
	//
	// Aligning both equations:
	// pbar * qbar * revBn(s) := (f1x + f0) * qbar mod p
	// pbar * qbar * revBn(s) := (h1x + h0) * pbar mod p
	//
	// Thus:
	// (f1x + f0) * qbar == (h1x + h0) * pbar mod p
	//

	// Solving the equation a * x + b = 0 for x
	f1qbar := new(big.Int).Mul(priv.f1, qbar)
	f0qbar := new(big.Int).Mul(priv.f0, qbar)
	h0pbar := new(big.Int).Mul(priv.h0, pbar)
	h1pbar := new(big.Int).Mul(priv.h1, pbar)

	f1qbar.Mod(f1qbar, priv.PublicKey.Prime)
	f0qbar.Mod(f0qbar, priv.PublicKey.Prime)
	h1pbar.Mod(h1pbar, priv.PublicKey.Prime)
	h0pbar.Mod(h0pbar, priv.PublicKey.Prime)

	a := new(big.Int)
	revh1pbar := new(big.Int).Sub(priv.PublicKey.Prime, h1pbar)
	a.Add(f1qbar, revh1pbar)
	a.Mod(a, priv.PublicKey.Prime)

	b := new(big.Int)
	revh0pbar := new(big.Int).Sub(priv.PublicKey.Prime, h0pbar)
	b.Add(f0qbar, revh0pbar)
	b.Mod(b, priv.PublicKey.Prime)

	// x := -b/a
	revB := new(big.Int).Sub(priv.PublicKey.Prime, b)
	revA := new(big.Int).ModInverse(a, priv.PublicKey.Prime)

	x := new(big.Int).Mul(revA, revB)
	x.Mod(x, priv.PublicKey.Prime)

	return x, nil
}

// Signature represents a digital signature in the HPPK protocol.
type Signature struct {
	Beta         *big.Int
	F, H         *big.Int
	S1Pub, S2Pub *big.Int
	Q, P, U, V   []*big.Int
	R            *big.Int
}

// Sign the message digest, returning a signature.
func (priv *PrivateKey) Sign(digest []byte) (sign *Signature, err error) {
	md := new(big.Int).SetBytes(digest)

	// alpha is a randomly choosen number from Fp
	alpha, err := rand.Int(rand.Reader, priv.PublicKey.Prime)
	if err != nil {
		return nil, err
	}

	// beta is a randomly choosen number from Fp
	beta, err := rand.Int(rand.Reader, priv.PublicKey.Prime)
	if err != nil {
		return nil, err
	}

	// calculate alpha * f(md) mod p
	// f(x) = f1* x + f0
	alphaFx := new(big.Int).Mul(priv.f1, md)
	alphaFx.Add(alphaFx, priv.f0)
	alphaFx.Mul(alphaFx, alpha)
	alphaFx.Mod(alphaFx, priv.PublicKey.Prime)

	alphaHx := new(big.Int).Mul(priv.h1, md)
	alphaHx.Add(alphaHx, priv.h0)
	alphaHx.Mul(alphaHx, alpha)
	alphaHx.Mod(alphaHx, priv.PublicKey.Prime)

	// calculate F & H
	revR2 := new(big.Int).ModInverse(priv.r2, priv.s2)
	F := new(big.Int)
	F.Mul(revR2, alphaFx)
	F.Mod(F, priv.s2)

	revR1 := new(big.Int).ModInverse(priv.r1, priv.s1)
	H := new(big.Int)
	H.Mul(revR1, alphaHx)
	H.Mod(H, priv.s1)

	// calculate V & U
	S1Pub := new(big.Int).Mul(beta, priv.s1)
	S1Pub.Mod(S1Pub, priv.PublicKey.Prime)
	S2Pub := new(big.Int).Mul(beta, priv.s2)
	S2Pub.Mod(S2Pub, priv.PublicKey.Prime)

	// Initiate V, U
	V := make([]*big.Int, len(priv.P))
	U := make([]*big.Int, len(priv.Q))

	// make K >= L+ 32
	K := priv.s1.BitLen()
	if priv.s2.BitLen() > K {
		K = priv.s2.BitLen()
	}
	K += 32
	R := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(K)), nil)

	for i := 0; i < len(V); i++ {
		V[i] = new(big.Int).Mul(priv.Q[i], R)
		V[i].Quo(V[i], priv.s2)

		U[i] = new(big.Int).Mul(priv.P[i], R)
		U[i].Quo(U[i], priv.s1)
	}

	sig := &Signature{
		Beta:  beta,
		F:     F,
		H:     H,
		V:     V,
		U:     U,
		S1Pub: S1Pub,
		S2Pub: S2Pub,
		R:     R,
	}
	return sig, nil
}

// VerifySignature verifies the signature of the message digest using the public key.
func VerifySignature(sig *Signature, digest []byte, pub *PublicKey) bool {
	// Ensure fields in the public key are valid
	if pub.P == nil || pub.Q == nil {
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
		Q[i].Mod(Q[i], pub.Prime)

		P[i] = new(big.Int).Mul(pub.P[i], sig.Beta)
		P[i].Mod(P[i], pub.Prime)
	}

	// Verify signature
	t := new(big.Int)
	md := new(big.Int).SetBytes(digest)
	sumLhs := new(big.Int)
	sumRhs := new(big.Int)

	Si := big.NewInt(1)
	for i := 0; i < len(sig.Q); i++ {
		lhsA := new(big.Int).Mul(Q[i], sig.F)

		t.Mul(sig.F, sig.V[i])
		t.Quo(t, sig.R)
		lhsB := new(big.Int).Mul(t, sig.S2Pub)
		lhs := new(big.Int).Sub(lhsA, lhsB)

		lhs.Mul(lhs, Si)
		sumLhs.Add(sumLhs, lhs)
		sumLhs.Mod(sumLhs, pub.Prime)

		rhsA := new(big.Int).Mul(P[i], sig.H)

		t.Mul(sig.H, sig.U[i])
		t.Quo(t, sig.R)
		rhsB := new(big.Int).Mul(t, sig.S1Pub)
		rhs := new(big.Int).Sub(rhsA, rhsB)

		rhs.Mul(rhs, Si)
		sumRhs.Add(sumRhs, rhs)
		sumRhs.Mod(sumRhs, pub.Prime)

		Si.Mul(Si, md)
		Si.Mod(Si, pub.Prime)
	}

	return sumLhs.Cmp(sumRhs) == 0
}

// createCoPrimePair generates a pair of coprime numbers (R, S) greater than the given prime p.
func createCoPrimePair(p *big.Int) (R *big.Int, S *big.Int, err error) {
	one := big.NewInt(1)
	psquared := new(big.Int).Mul(p, p)

	for {
		R, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, nil, err
		}
		R.Add(R, psquared)

		S, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, nil, err
		}
		S.Add(S, psquared)

		// Check if GCD(R, S) == 1, which means R and S are coprime
		if new(big.Int).GCD(nil, nil, R, S).Cmp(one) == 0 {
			return R, S, nil
		}
	}
}

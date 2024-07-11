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
	ERRMSG_ORDER               = "order must be at least 5"
	ERRMSG_NULL_ENCRYPT        = "encrypted values cannot be null"
	ERRMSG_DATA_EXCEEDED_FIELD = "the secret to encrypt is not in the GF(p)"
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
		return nil, errors.New(ERRMSG_ORDER)
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
func (priv *PrivateKey) Encrypt(pk *PublicKey, msg []byte) (P *big.Int, Q *big.Int, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(priv.PublicKey.Prime) >= 0 {
		return nil, nil, errors.New(ERRMSG_DATA_EXCEEDED_FIELD)
	}

	// Noise generation is commented out
	/*
	   noise, err := rand.Int(rand.Reader, pk.Prime)
	   if err != nil {
	           return nil, nil, err
	   }
	   SiNoise := new(big.Int)
	*/

	// Initialize Si with the secret message
	Si := new(big.Int).Set(secret)

	// Compute the encrypted values P and Q
	P = new(big.Int).Set(pk.P[0])
	Q = new(big.Int).Set(pk.Q[0])
	t := new(big.Int)
	for i := 1; i < len(pk.P); i++ {
		// SiNoise is commented out
		//SiNoise.Mul(Si, noise)
		//SiNoise.Mod(SiNoise, pk.Prime)

		t.Mul(Si, pk.P[i])
		P.Add(P, t)

		t.Mul(Si, pk.Q[i])
		Q.Add(Q, t)

		Si.Mul(Si, secret)
		Si.Mod(Si, pk.Prime)
	}

	return P, Q, nil
}

// Decrypt decrypts the encrypted values P and Q using the private key.
func (priv *PrivateKey) Decrypt(P *big.Int, Q *big.Int) (secret *big.Int, err error) {
	// Symmetric decryption using private key components
	pbar := new(big.Int).Mod(P, priv.s1)
	qbar := new(big.Int).Mod(Q, priv.s2)
	revR1 := new(big.Int).ModInverse(priv.r1, priv.s1)
	revR2 := new(big.Int).ModInverse(priv.r2, priv.s2)

	pbar.Mul(pbar, revR1)
	qbar.Mul(qbar, revR2)
	pbar.Mod(pbar, priv.s1)
	qbar.Mod(qbar, priv.s2)

	pbar.Mod(pbar, priv.PublicKey.Prime)
	qbar.Mod(qbar, priv.PublicKey.Prime)

	// Noise elimination is commented out
	/*
	   revqbar := new(big.Int).ModInverse(qbar, priv.PublicKey.Prime)
	   k := new(big.Int).Mul(pbar, revqbar)
	   k.Mod(k, priv.PublicKey.Prime)
	   fmt.Println("K:", k)
	   fmt.Println("Prime:", priv.PublicKey.Prime)
	   fmt.Println("f0", priv.f0, "f1", priv.f1, "h0", priv.h0, "h1", priv.h1)
	   fmt.Printf("%d *(%dx + %d) = %dx +%d\n", k, priv.h1, priv.h0, priv.f1, priv.f0)
	*/

	// Explanation of the decryption process:
	// pbar := Bn * (f1*x + f0) mod p
	// qbar := Bn * (h1*x + h0) mod p
	//
	// Multiplying both sides by the inverse of Bn gives:
	// pbar*revBn(s) := (f1x + f0) mod p
	// qbar*revBn(s) := (h1x + h0) mod p
	//
	// Aligning both equations:
	// pbar * qbar * revBn(s) := (f1x + f0) * Qs mod p
	// pbar * qbar * revBn(s) := (h1x + h0) * Ps mod p
	//
	// Thus:
	// (f1x + f0) * qbar == (h1x + h0) * pbar mod p
	//

	// Solving the equation a * x + b = 0 for x
	f1qbar := new(big.Int).Mul(priv.f1, qbar)
	f0qbar := new(big.Int).Mul(priv.f0, qbar)
	h0pbar := new(big.Int).Mul(priv.h0, pbar)
	h1pbar := new(big.Int).Mul(priv.h1, pbar)

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

type Signature struct {
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

	// Initiate V, U, P, Q
	Q := make([]*big.Int, len(priv.Q))
	P := make([]*big.Int, len(priv.P))
	V := make([]*big.Int, len(priv.P))
	U := make([]*big.Int, len(priv.Q))

	// make K >= L+ 32
	K := priv.s1.BitLen()
	if priv.s2.BitLen() > K {
		K = priv.s2.BitLen()
	}
	K += 32
	R := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(K)), nil)

	for i := 0; i < len(Q); i++ {
		Q[i] = new(big.Int).Mul(priv.Q[i], beta)
		Q[i].Mod(Q[i], priv.PublicKey.Prime)

		P[i] = new(big.Int).Mul(priv.P[i], beta)
		P[i].Mod(P[i], priv.PublicKey.Prime)

		V[i] = new(big.Int).Mul(priv.Q[i], R)
		V[i].Quo(V[i], priv.s2)

		U[i] = new(big.Int).Mul(priv.P[i], R)
		U[i].Quo(U[i], priv.s1)
	}

	sig := &Signature{
		F:     F,
		H:     H,
		Q:     Q,
		P:     P,
		V:     V,
		U:     U,
		S1Pub: S1Pub,
		S2Pub: S2Pub,
		R:     R,
	}
	return sig, nil
}

// VerifySignature verifies the signature of the message digest using the public key.
func VerifySignature(sig *Signature, digest []byte, pk *PublicKey) bool {
	t := new(big.Int)
	md := new(big.Int).SetBytes(digest)
	sumLhs := new(big.Int)
	sumRhs := new(big.Int)

	Si := big.NewInt(1)
	for i := 0; i < len(sig.Q); i++ {
		lhsA := new(big.Int).Mul(sig.Q[i], sig.F)

		t.Mul(sig.F, sig.V[i])
		t.Quo(t, sig.R)
		lhsB := new(big.Int).Mul(t, sig.S2Pub)
		lhs := new(big.Int).Sub(lhsA, lhsB)

		lhs.Mul(lhs, Si)
		sumLhs.Add(sumLhs, lhs)
		sumLhs.Mod(sumLhs, pk.Prime)

		rhsA := new(big.Int).Mul(sig.P[i], sig.H)

		t.Mul(sig.H, sig.U[i])
		t.Quo(t, sig.R)
		rhsB := new(big.Int).Mul(t, sig.S1Pub)
		rhs := new(big.Int).Sub(rhsA, rhsB)

		rhs.Mul(rhs, Si)
		sumRhs.Add(sumRhs, rhs)
		sumRhs.Mod(sumRhs, pk.Prime)

		Si.Mul(Si, md)
		Si.Mod(Si, pk.Prime)
	}

	if sumLhs.Cmp(sumRhs) != 0 {
		return false
	}
	return true
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

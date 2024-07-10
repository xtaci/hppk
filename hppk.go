package hppk

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const PRIME = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

//const PRIME = "977"

const (
	ERRMSG_ORDER               = "order must be at least 5"
	ERRMSG_NULL_ENCRYPT        = "encrypted values cannot be null"
	ERRMSG_DATA_EXCEEDED_FIELD = "the secret to encrypt is not in the GF(p)"
)

// PrivateKey represents a private key in the DPPK protocol.
type PrivateKey struct {
	r0, s0 *big.Int // r,s are coprimes
	r1, s1 *big.Int
	f0, f1 *big.Int // f(x) = a1x + a0 ,h(x) = b1x+ b0
	h0, h1 *big.Int
	PublicKey
}

// PublicKey represents a public key in the DPPK protocol.
type PublicKey struct {
	Prime *big.Int
	P     []*big.Int
	Q     []*big.Int
}

// GenerateKey generates a new DPPK private key with the given order and default prime number
func GenerateKey(order int) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New(ERRMSG_ORDER)
	}

RETRY:
	prime, _ := big.NewInt(0).SetString(PRIME, 10)
	r0, s0, err := createCoPrimePair(prime)
	if err != nil {
		return nil, err
	}
	r1, s1, err := createCoPrimePair(prime)
	if err != nil {
		return nil, err
	}

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

	if r0.Cmp(r1) == 0 || s0.Cmp(s1) == 0 || f0.Cmp(f1) == 0 {
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

	// generate P, Q
	P := make([]*big.Int, order+2)
	Q := make([]*big.Int, order+2)

	// λ + n + 1 == 1 + order + 1 = order + 2
	for i := 0; i < order+2; i++ {
		P[i] = big.NewInt(0)
		Q[i] = big.NewInt(0)
	}

	bigInt := new(big.Int)
	// multiply f(x) and h(X) with Bn to get P and Q,
	// the coefficients of the polynomial Bn has a length of order + 1
	for i := 0; i < order+1; i++ {
		// Vector P
		P[i].Add(P[i], bigInt.Mul(f0, Bn[i]))
		ring(r0, s0, P[i])

		P[i+1].Add(P[i+1], bigInt.Mul(f1, Bn[i]))
		ring(r0, s0, P[i+1])

		// Vector Q
		Q[i].Add(Q[i], bigInt.Mul(h0, Bn[i]))
		ring(r1, s1, Q[i])

		Q[i+1].Add(Q[i+1], bigInt.Mul(h1, Bn[i]))
		ring(r1, s1, Q[i+1])
	}

	return &PrivateKey{
		r0: r0,
		s0: s0,
		r1: r1,
		s1: s1,
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
func (priv *PrivateKey) Encrypt(pk *PublicKey, msg []byte) (Ps *big.Int, Qs *big.Int, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(priv.PublicKey.Prime) >= 0 {
		return nil, nil, errors.New(ERRMSG_DATA_EXCEEDED_FIELD)
	}

	// generate a noise
	/*
		noise, err := rand.Int(rand.Reader, pk.Prime)
		if err != nil {
			return nil, nil, err
		}
	*/

	// Initialize variables for the encryption process
	Si := new(big.Int).Set(secret)

	// Compute the encrypted values Ps and Qs
	// constants
	Ps = new(big.Int).Set(pk.P[0])
	Qs = new(big.Int).Set(pk.Q[0])
	t := new(big.Int)
	for i := 1; i < len(pk.P); i++ { // start from non constant item
		//	SiNoise := new(big.Int).Set(Si)
		//	SiNoise.Mul(SiNoise, noise)
		//	SiNoise.Mod(SiNoise, pk.Prime)

		t.Mul(Si, pk.P[i])
		Ps.Add(Ps, t)
		Ps.Mod(Ps, pk.Prime)

		t.Mul(Si, pk.Q[i])
		Qs.Add(Qs, t)
		Qs.Mod(Qs, pk.Prime)

		Si.Mul(Si, secret)
		Si.Mod(Si, pk.Prime)
	}

	return Ps, Qs, nil
}

// Decrypt decrypts the encrypted values Ps and Qs using the private key.
func (priv *PrivateKey) Decrypt(P *big.Int, Q *big.Int) (secret *big.Int, err error) {
	// symmetric encryption
	revR0 := new(big.Int).ModInverse(priv.r0, priv.s0)
	revR1 := new(big.Int).ModInverse(priv.r1, priv.s1)

	pbar := new(big.Int).Mul(P, revR0)
	qbar := new(big.Int).Mul(Q, revR1)

	pbar.Mod(pbar, priv.s0)
	qbar.Mod(qbar, priv.s1)

	pbar.Mod(pbar, priv.PublicKey.Prime)
	qbar.Mod(qbar, priv.PublicKey.Prime)

	// noise elimination
	reqbar := new(big.Int).ModInverse(qbar, priv.PublicKey.Prime)
	k := new(big.Int).Mul(pbar, reqbar)
	k.Mod(k, priv.PublicKey.Prime)

	// solve f(x) - k*h(x) =0
	// f1 * x + f0 - k(h1x+h0) = 0
	// (f1 - k*h1)x + f0 - kh0 = 0
	//	x = (kh0 - f0)  / (f1 - k*h1)
	kh1 := new(big.Int).Mul(k, priv.h1)
	revkh1 := new(big.Int).Sub(priv.PublicKey.Prime, kh1)
	denom := new(big.Int).Add(priv.f1, revkh1)
	denom.Mod(denom, priv.PublicKey.Prime)

	kh0 := new(big.Int).Mul(k, priv.h0)
	revf0 := new(big.Int).Sub(priv.PublicKey.Prime, priv.f0)
	numer := new(big.Int).Add(kh0, revf0)
	numer.Mod(numer, priv.PublicKey.Prime)

	revDenom := new(big.Int).ModInverse(denom, priv.PublicKey.Prime)

	x := new(big.Int).Mul(numer, revDenom)
	x.Mod(x, priv.PublicKey.Prime)
	return x, nil

}

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

		if new(big.Int).GCD(nil, nil, R, S).Cmp(one) == 0 {
			return R, S, nil
		}
	}
}

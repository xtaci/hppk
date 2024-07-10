package hppk

import (
	"crypto/rand"
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
	PublicKey
}

// PublicKey represents a public key in the DPPK protocol.
type PublicKey struct {
	vecU []*big.Int // Coefficients for polynomial U
	vecV []*big.Int // Coefficients for polynomial V
}

// GenerateKey generates a new DPPK private key with the given order and default prime number
func GenerateKey() (*PrivateKey, error) {
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

	if r0.Cmp(r1) == 0 || s0.Cmp(s1) == 0 {
		goto RETRY
	}

	return &PrivateKey{
		r0: r0,
		s0: s0,
		r1: r1,
		s1: s1,
	}, nil
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

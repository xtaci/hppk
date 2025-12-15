package hppk

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKeyBinaryRoundTrip(t *testing.T) {
	priv, err := GenerateKey(6)
	require.NoError(t, err)

	original := priv.Public()
	encoded, err := original.MarshalBinary()
	require.NoError(t, err)

	var decoded PublicKey
	err = decoded.UnmarshalBinary(encoded)
	require.NoError(t, err)

	require.Equal(t, 0, original.Prime.Cmp(decoded.Prime))
	require.True(t, original.Equal(&decoded))
}

func TestPrivateKeyBinaryRoundTrip(t *testing.T) {
	priv, err := GenerateKey(6)
	require.NoError(t, err)

	encoded, err := priv.MarshalBinary()
	require.NoError(t, err)

	var decoded PrivateKey
	err = decoded.UnmarshalBinary(encoded)
	require.NoError(t, err)

	scalars := [][2]*big.Int{
		{priv.R1, decoded.R1},
		{priv.S1, decoded.S1},
		{priv.R2, decoded.R2},
		{priv.S2, decoded.S2},
		{priv.F0, decoded.F0},
		{priv.F1, decoded.F1},
		{priv.H0, decoded.H0},
		{priv.H1, decoded.H1},
	}
	for _, pair := range scalars {
		require.Equal(t, 0, pair[0].Cmp(pair[1]))
	}
	require.Equal(t, 0, priv.Prime.Cmp(decoded.Prime))
	require.True(t, priv.Public().Equal(decoded.Public()))
}

func TestPublicKeyUnmarshalRejectsCorruption(t *testing.T) {
	priv, err := GenerateKey(5)
	require.NoError(t, err)

	encoded, err := priv.Public().MarshalBinary()
	require.NoError(t, err)

	encoded[0] ^= 0xFF

	var decoded PublicKey
	err = decoded.UnmarshalBinary(encoded)
	require.ErrorIs(t, err, errInvalidPublicEncoding)
}

func TestPrivateKeyUnmarshalRejectsCorruption(t *testing.T) {
	priv, err := GenerateKey(5)
	require.NoError(t, err)

	encoded, err := priv.MarshalBinary()
	require.NoError(t, err)

	encoded[0] ^= 0xFF

	var decoded PrivateKey
	err = decoded.UnmarshalBinary(encoded)
	require.ErrorIs(t, err, errInvalidPrivateEncoding)
}

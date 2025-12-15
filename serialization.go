package hppk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

const (
	publicKeyMagic  = "HPPKPB01"
	privateKeyMagic = "HPPKPR01"
)

var (
	errNilPublicKey            = errors.New("hppk: nil public key")
	errNilPrivateKey           = errors.New("hppk: nil private key")
	errCoeffMismatch           = errors.New("hppk: mismatched polynomial degrees")
	errInvalidPublicEncoding   = errors.New("hppk: invalid public key encoding")
	errInvalidPrivateEncoding  = errors.New("hppk: invalid private key encoding")
	errSerializedIntegerTooBig = errors.New("hppk: serialized integer too large")
)

const maxUint32 = int(^uint32(0))

// MarshalBinary serializes the public key using a custom binary framing.
func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	if pub == nil {
		return nil, errNilPublicKey
	}

	if pub.Prime == nil || len(pub.P) == 0 || len(pub.Q) == 0 || len(pub.P) != len(pub.Q) {
		return nil, errCoeffMismatch
	}

	buf := &bytes.Buffer{}
	if err := writeMagic(buf, publicKeyMagic); err != nil {
		return nil, err
	}

	if err := writeBigInt(buf, pub.Prime); err != nil {
		return nil, err
	}

	if err := writePolynomial(buf, pub.P); err != nil {
		return nil, err
	}

	if err := writePolynomial(buf, pub.Q); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary restores the public key from MarshalBinary output.
func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	if pub == nil {
		return errNilPublicKey
	}

	reader := bytes.NewReader(data)
	if err := expectMagic(reader, publicKeyMagic); err != nil {
		return errInvalidPublicEncoding
	}

	prime, err := readBigInt(reader)
	if err != nil {
		return errInvalidPublicEncoding
	}

	pCoeffs, err := readPolynomial(reader)
	if err != nil {
		return errInvalidPublicEncoding
	}

	qCoeffs, err := readPolynomial(reader)
	if err != nil {
		return errInvalidPublicEncoding
	}

	if len(pCoeffs) == 0 || len(pCoeffs) != len(qCoeffs) || reader.Len() != 0 {
		return errInvalidPublicEncoding
	}

	pub.Prime = prime
	pub.P = pCoeffs
	pub.Q = qCoeffs
	return nil
}

// MarshalBinary serializes the private key including the embedded public key.
func (priv *PrivateKey) MarshalBinary() ([]byte, error) {
	if priv == nil {
		return nil, errNilPrivateKey
	}

	pubBytes, err := priv.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := writeMagic(buf, privateKeyMagic); err != nil {
		return nil, err
	}

	scalars := []*big.Int{priv.R1, priv.S1, priv.R2, priv.S2, priv.F0, priv.F1, priv.H0, priv.H1}
	for _, scalar := range scalars {
		if err := writeBigInt(buf, scalar); err != nil {
			return nil, err
		}
	}

	if err := writeLengthPrefixedBytes(buf, pubBytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a private key serialized by MarshalBinary.
func (priv *PrivateKey) UnmarshalBinary(data []byte) error {
	if priv == nil {
		return errNilPrivateKey
	}

	reader := bytes.NewReader(data)
	if err := expectMagic(reader, privateKeyMagic); err != nil {
		return errInvalidPrivateEncoding
	}

	scalars := make([]*big.Int, 8)
	for i := range scalars {
		v, err := readBigInt(reader)
		if err != nil {
			return errInvalidPrivateEncoding
		}
		scalars[i] = v
	}

	pubBytes, err := readLengthPrefixedBytes(reader)
	if err != nil {
		return errInvalidPrivateEncoding
	}

	if reader.Len() != 0 {
		return errInvalidPrivateEncoding
	}

	var pub PublicKey
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return errInvalidPrivateEncoding
	}

	priv.R1 = scalars[0]
	priv.S1 = scalars[1]
	priv.R2 = scalars[2]
	priv.S2 = scalars[3]
	priv.F0 = scalars[4]
	priv.F1 = scalars[5]
	priv.H0 = scalars[6]
	priv.H1 = scalars[7]
	priv.PublicKey = pub
	return nil
}

func writeMagic(buf *bytes.Buffer, magic string) error {
	_, err := buf.WriteString(magic)
	return err
}

func expectMagic(r io.Reader, magic string) error {
	want := []byte(magic)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("hppk: invalid magic header")
	}
	return nil
}

func writeBigInt(w io.Writer, v *big.Int) error {
	if v == nil {
		v = big.NewInt(0)
	}
	data := v.Bytes()
	if len(data) > maxUint32 {
		return errSerializedIntegerTooBig
	}
	if err := writeUint32Value(w, uint32(len(data))); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func readBigInt(r io.Reader) (*big.Int, error) {
	length, err := readUint32Value(r)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return big.NewInt(0), nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

func writePolynomial(w io.Writer, coeffs []*big.Int) error {
	if len(coeffs) > maxUint32 {
		return errSerializedIntegerTooBig
	}
	if err := writeUint32Value(w, uint32(len(coeffs))); err != nil {
		return err
	}
	for _, coeff := range coeffs {
		if err := writeBigInt(w, coeff); err != nil {
			return err
		}
	}
	return nil
}

func readPolynomial(r io.Reader) ([]*big.Int, error) {
	length, err := readUint32Value(r)
	if err != nil {
		return nil, err
	}
	coeffs := make([]*big.Int, length)
	for i := uint32(0); i < length; i++ {
		coeff, err := readBigInt(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = coeff
	}
	return coeffs, nil
}

func writeLengthPrefixedBytes(w io.Writer, data []byte) error {
	if len(data) > maxUint32 {
		return errSerializedIntegerTooBig
	}
	if err := writeUint32Value(w, uint32(len(data))); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func readLengthPrefixedBytes(r io.Reader) ([]byte, error) {
	length, err := readUint32Value(r)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeUint32Value(w io.Writer, value uint32) error {
	return binary.Write(w, binary.BigEndian, value)
}

func readUint32Value(r io.Reader) (uint32, error) {
	var v uint32
	if err := binary.Read(r, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	return v, nil
}

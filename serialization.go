package hppk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

// magic headers guard against decoding the wrong blob type/version.
const (
	publicKeyMagicString  = "HPPKPB01"
	privateKeyMagicString = "HPPKPR01"
)

var (
	publicKeyMagicBytes  = []byte(publicKeyMagicString)
	privateKeyMagicBytes = []byte(privateKeyMagicString)

	errNilPublicKey              = errors.New("hppk: nil public key")
	errNilPrivateKey             = errors.New("hppk: nil private key")
	errCoeffMismatch             = errors.New("hppk: mismatched polynomial degrees")
	errInvalidPublicEncoding     = errors.New("hppk: invalid public key encoding")
	errInvalidPrivateEncoding    = errors.New("hppk: invalid private key encoding")
	errSerializedIntegerTooLarge = errors.New("hppk: serialized integer too large")
)

// MarshalBinary encodes the public key using the custom HPPK binary layout.
func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	if pub == nil {
		return nil, errNilPublicKey
	}

	if pub.Prime == nil {
		return nil, errInvalidPublicEncoding
	}

	if len(pub.P) == 0 || len(pub.Q) == 0 || len(pub.P) != len(pub.Q) {
		return nil, errCoeffMismatch
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(publicKeyMagicBytes)))
	buf.Write(publicKeyMagicBytes)

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

// UnmarshalBinary populates the public key from MarshalBinary output.
func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	if pub == nil {
		return errNilPublicKey
	}

	reader := bytes.NewReader(data)
	if err := expectMagic(reader, publicKeyMagicBytes); err != nil {
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

	if reader.Len() != 0 {
		return errInvalidPublicEncoding
	}

	if len(pCoeffs) == 0 || len(pCoeffs) != len(qCoeffs) {
		return errInvalidPublicEncoding
	}

	pub.Prime = prime
	pub.P = pCoeffs
	pub.Q = qCoeffs
	return nil
}

// MarshalBinary encodes the private key along with its embedded public key.
func (priv *PrivateKey) MarshalBinary() ([]byte, error) {
	if priv == nil {
		return nil, errNilPrivateKey
	}

	pubBytes, err := priv.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(privateKeyMagicBytes)))
	buf.Write(privateKeyMagicBytes)

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

// UnmarshalBinary restores the private key values from MarshalBinary output.
func (priv *PrivateKey) UnmarshalBinary(data []byte) error {
	if priv == nil {
		return errNilPrivateKey
	}

	reader := bytes.NewReader(data)
	if err := expectMagic(reader, privateKeyMagicBytes); err != nil {
		return errInvalidPrivateEncoding
	}

	scalars := make([]*big.Int, 8)
	for i := range scalars {
		val, err := readBigInt(reader)
		if err != nil {
			return errInvalidPrivateEncoding
		}
		scalars[i] = val
	}

	blob, err := readLengthPrefixedBytes(reader)
	if err != nil {
		return errInvalidPrivateEncoding
	}

	if reader.Len() != 0 {
		return errInvalidPrivateEncoding
	}

	var pub PublicKey
	if err := pub.UnmarshalBinary(blob); err != nil {
		return err
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

// writeBigInt emits a uint32 length prefix followed by the big-endian value.
func writeBigInt(buf *bytes.Buffer, v *big.Int) error {
	if v == nil {
		v = big.NewInt(0)
	}
	data := v.Bytes()
	if err := writeUint32(buf, data); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := buf.Write(data)
	return err
}

// readBigInt parses the length-prefixed big integer emitted by writeBigInt.
func readBigInt(r io.Reader) (*big.Int, error) {
	data, err := readUint32Data(r)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return big.NewInt(0), nil
	}
	return new(big.Int).SetBytes(data), nil
}

// writePolynomial emits the polynomial degree followed by its coefficients.
func writePolynomial(buf *bytes.Buffer, coeffs []*big.Int) error {
	if err := writeUint32(buf, intSliceToBytesLength(len(coeffs))); err != nil {
		return err
	}
	for _, coeff := range coeffs {
		if err := writeBigInt(buf, coeff); err != nil {
			return err
		}
	}
	return nil
}

// readPolynomial restores the coefficient slice emitted by writePolynomial.
func readPolynomial(r io.Reader) ([]*big.Int, error) {
	rawLen, err := readUint32Value(r)
	if err != nil {
		return nil, err
	}
	length := int(rawLen)
	if int64(length) < 0 {
		return nil, errSerializedIntegerTooLarge
	}

	coeffs := make([]*big.Int, length)
	for i := range coeffs {
		coeff, err := readBigInt(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = coeff
	}
	return coeffs, nil
}

func expectMagic(r io.Reader, magic []byte) error {
	buf := make([]byte, len(magic))
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if !bytes.Equal(buf, magic) {
		return errors.New("hppk: invalid magic header")
	}
	return nil
}

func writeLengthPrefixedBytes(buf *bytes.Buffer, data []byte) error {
	if err := writeUint32(buf, data); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := buf.Write(data)
	return err
}

func readLengthPrefixedBytes(r io.Reader) ([]byte, error) {
	return readUint32Data(r)
}

func writeUint32(buf *bytes.Buffer, data []byte) error {
	length := len(data)
	if length < 0 {
		return errSerializedIntegerTooLarge
	}
	if length > int(^uint32(0)) {
		return errSerializedIntegerTooLarge
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(length)); err != nil {
		return err
	}
	return nil
}

func intSliceToBytesLength(length int) []byte {
	return make([]byte, length)
}

func readUint32Data(r io.Reader) ([]byte, error) {
	rawLen, err := readUint32Value(r)
	if err != nil {
		return nil, err
	}
	if rawLen == 0 {
		return nil, nil
	}
	data := make([]byte, rawLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func readUint32Value(r io.Reader) (uint32, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	return length, nil
}

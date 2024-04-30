package paillier

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
)

// public key io
func GetPublicKeyHex(pk *PublicKey) string {
	n := pk.N.Text(16)
	return n
}

func GetPublicKeyFromHex(content string) (*PublicKey, error) {
	n, isOK := new(big.Int).SetString(content, 16)
	if !isOK {
		return nil, errors.New("invalid string for Paillier public key: " + content)
	}
	return &PublicKey{
		N:        n,
		NSquared: new(big.Int).Mul(n, n),
		G:        new(big.Int).Add(n, one),
	}, nil
}

// private key io
func GetPrivateKeyHex(sk *PrivateKey) []byte {
	// TO DER
	pkDER, err := asn1.Marshal(
		struct {
			P      *big.Int
			Q      *big.Int
			PubStr string
		}{
			sk.p,
			sk.q,
			GetPublicKeyHex(&sk.PublicKey),
		})
	if err != nil {
		return nil
	}

	// PEM encode
	block := &pem.Block{
		Type:  "PAILLIER PRIVATE KEY",
		Bytes: pkDER,
	}

	buf := new(bytes.Buffer)
	if err = pem.Encode(buf, block); err != nil {
		return nil
	}

	return buf.Bytes()
}

func GetPrivateKeyFromHex(content string) (*PrivateKey, error) {
	temp := struct {
		P      *big.Int
		Q      *big.Int
		PubStr string
	}{}

	// PEM decode
	block, rest := pem.Decode([]byte(content))
	if len(rest) != 0 {
		return nil, errors.New("")
	}

	// DER to struct
	_, err := asn1.Unmarshal(block.Bytes, &temp)
	if err != nil {
		return nil, errors.New("")
	}

	p := temp.P
	q := temp.Q

	n := new(big.Int).Mul(p, q)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)
	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one),
		},
		p:         p,
		pp:        pp,
		pminusone: new(big.Int).Sub(p, one),
		q:         q,
		qq:        qq,
		qminusone: new(big.Int).Sub(q, one),
		pinvq:     new(big.Int).ModInverse(p, q),
		hp:        h(p, pp, n),
		hq:        h(q, qq, n),
		n:         n,
	}, nil
}

// private key io
func (sk *PrivateKey) MarshalBinary() []byte {
	return GetPrivateKeyHex(sk)
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {

	newP, _ := GetPrivateKeyFromHex(string(data))
	*p = *newP
	return nil
}

package go_bls

import (
	"errors"
	"github.com/phoreproject/bls/g2pubs"
)

var ErrSigMismatch = errors.New("signature mismatch")

type secret struct {
	sk *g2pubs.SecretKey
}

type public struct {
	pk *g2pubs.PublicKey
}

func (s *secret) Sign(m Message) Signature {
	sig := g2pubs.Sign(m, s.sk)
	return sig.Serialize()
}

// PubKey returns the corresponding public key.
func (s *secret) PubKey() (PublicKey, error) {
	pk := g2pubs.PrivToPub(s.sk)
	return &public{pk: pk}, nil
}

// Compress compresses the secret key to a byte slice.
func (s *secret) Compress() CompressedSecret {
	return s.sk.Serialize()
}

// Verify verifies a signature against a message and the public key.
func (p *public) Verify(m Message, sig Signature) error {
	g1sig, err := g2pubs.DeserializeSignature(sig)
	if err != nil {
		return err
	}
	if ok := g2pubs.Verify(m, p.pk, g1sig); ok {
		return nil
	}
	return ErrSigMismatch
}

// Aggregate adds an other public key to the current.
func (p *public) Aggregate(other PublicKey) error {
	op, ok := other.(*public)
	if ok {
		p.pk.Aggregate(op.pk)
		return nil
	} else {
		return errors.New("invalid public key")
	}
}

// Compress compresses the public key to a byte slice.
func (p *public) Compress() CompressedPublic {
	return p.pk.Serialize()
}

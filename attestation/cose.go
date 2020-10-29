package attestation

import (
	"crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"go.mozilla.org/cose"
)

type coseHeader struct {
	Alg int    `cbor:"1,keyasint,omitempty"`
	Kid []byte `cbor:"4,keyasint,omitempty"`
}

type signedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected coseHeader
	Payload     []byte
	Signature   []byte
}

func (s *signedCWT) verifySignature(key crypto.PublicKey) error {
	verifier := cose.Verifier{Alg: cose.ES384, PublicKey: key}

	sigload := []interface{}{
		"Signature1",
		s.Protected,
		[]byte{},
		s.Payload,
	}

	b, err := cbor.Marshal(sigload)
	if err != nil {
		return errors.WithStack(err)
	}

	h := cose.ES384.HashFunc.New()
	h.Write(b)
	digest := h.Sum(nil)

	err = verifier.Verify(digest, s.Signature)
	return errors.WithStack(err)
}

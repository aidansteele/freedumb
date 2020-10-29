package attestation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"filippo.io/age"
	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"strings"
	"time"
)

const (
	PCR0EnclaveImageFileHash            = 0
	PCR1KernelBootstrapHash             = 1
	PCR2ApplicationHash                 = 2
	PCR3InstanceIamRoleArnHash          = 3
	PCR4InstanceIdHash                  = 4
	PCR8EnclaveImageFileCertificateHash = 8
)

type AttestationDocument struct {
	InstanceId   string
	EnclaveId    string
	Timestamp    time.Time
	PublicKey    age.Recipient
	Nonce        []byte
	UserData     []byte
	Certificates []*x509.Certificate
	PCRs         map[int][]byte
}

func (doc *AttestationDocument) VerifyPCR(pcrIndex int, value string) bool {
	h := crypto.SHA384.New()
	h.Write(make([]byte, 48))
	h.Write([]byte(value))
	digest := h.Sum(nil)
	return bytes.Equal(doc.PCRs[pcrIndex], digest)
}

func ParseAttestationDocument(input []byte) (*AttestationDocument, error) {
	signed := signedCWT{}
	err := cbor.Unmarshal(input, &signed)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	doc := rawAttestationDocument{}
	err = cbor.Unmarshal(signed.Payload, &doc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	chain, err := doc.verifyCertificateChain()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = signed.verifySignature(chain[0].PublicKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	pub, err := age.ParseX25519Recipient(string(doc.PublicKey))
	if err != nil {
	    return nil, errors.WithStack(err)
	}

	moduleBits := strings.SplitN(doc.ModuleId, "-", 3)

	return &AttestationDocument{
		InstanceId:   "i-" + moduleBits[1],
		EnclaveId:    moduleBits[2],
		Timestamp:    time.Unix(0, doc.Timestamp*int64(time.Millisecond)),
		PublicKey:    pub,
		Nonce:        doc.Nonce,
		UserData:     doc.UserData,
		Certificates: chain,
		PCRs:         doc.PCRs,
	}, nil
}

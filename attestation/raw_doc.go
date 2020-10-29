package attestation

import (
	"crypto/x509"
	"github.com/pkg/errors"
)

type rawAttestationDocument struct {
	ModuleId    string         `cbor:"module_id"`
	Digest      string         `cbor:"digest"`
	Timestamp   int64          `cbor:"timestamp"`
	PCRs        map[int][]byte `cbor:"pcrs"`
	Certificate []byte         `cbor:"certificate"`
	CABundle    [][]byte       `cbor:"cabundle"`
	PublicKey   []byte         `cbor:"public_key,omitempty"`
	UserData    []byte         `cbor:"user_data,omitempty"`
	Nonce       []byte         `cbor:"nonce,omitempty"`
}

func (doc *rawAttestationDocument) verifyCertificateChain() ([]*x509.Certificate, error) {
	enclaveCertificate, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		panic(err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(root))

	intermediates := x509.NewCertPool()
	for _, der := range doc.CABundle {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		intermediates.AddCert(cert)
	}

	chains, err := enclaveCertificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return chains[0], nil
}

var root = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

// GenCertInput represent payload required to generate a certificate.
type GenCertInput struct {
	// CommonName is the target's common name.
	CommonName string
	// Dir is the directory where to export the target.
	Dir string
	// DaysDuration is the target's duration in days.
	DaysDuration int
	// Type can be one of root,intermediate or leaf.
	Type string
	// IssuerCert is the issuer certificate that is signing the target certificate.
	IssuerCert *x509.Certificate
	// IssuerPrivateKey is the issuer private key.
	IssuerPrivateKey *rsa.PrivateKey
}

// GenCertOutput represent the output after successful certificate generation.
type GenCertOutput struct {
	// Certificate represents x509 certificate.
	Certificate *x509.Certificate
	// PrivateKey is a generated private key.
	PrivateKey *rsa.PrivateKey
	// FileName is the certificate's file location on disk.
	FileName string
}

// genPrivateKey generates private key that is 'l' bits in length.
func genPrivateKey(l int) (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, l)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// exportPemPrivateKeyToFile exports PEM encoded private key to a local file.
func exportPemPrivateKeyToFile(cn, dir string, pk *rsa.PrivateKey) error {
	f, err := os.Create(fmt.Sprintf("%s/%s.key", dir, cn))
	if err != nil {
		return err
	}
	defer f.Close()

	if err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}); err != nil {
		return err
	}
	return nil
}

// exportPemCertToFile exports PEM encoded certificate to a local file.
func exportPemCertToFile(cn, dir string, c []byte) (string, error) {
	f, err := os.Create(fmt.Sprintf("%s/%s.cert", dir, cn))
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c}); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// ExportPemChain exports a list of certificates to a chain file.
func ExportPemChain(certs []*GenCertOutput, dir, name string) error {
	var buf bytes.Buffer

	// Write the files in reverse order, root CA at the bottom, as it is always the first certificate generated.
	for i := len(certs) - 1; i >= 0; i-- {
		b, err := os.ReadFile(certs[i].FileName)
		if err != nil {
			return err
		}
		buf.Write(b)
	}

	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
		return err
	}
	return nil
}

// GenCert generates a certificate file and a private key.
func GenCert(input *GenCertInput) (*GenCertOutput, error) {
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			CommonName:         input.CommonName,
			Country:            []string{"US"},
			Organization:       []string{"Example"},
			OrganizationalUnit: []string{"Example SRE"},
			Locality:           []string{"Los Angeles"},
		},
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		Version:               3,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(0, 0, input.DaysDuration).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	keySize := 4098
	switch input.Type {
	case "root":
		crt.Issuer = crt.Subject
	case "intermediate":
		crt.Issuer = input.IssuerCert.Subject
	case "leaf":
		crt.IsCA = false
		crt.Issuer = input.IssuerCert.Subject
		crt.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		crt.KeyUsage = x509.KeyUsageDigitalSignature
		crt.BasicConstraintsValid = false
		keySize = 2048
	default:
		return nil, errors.Errorf("unsupported certificate type: %s requested", input.Type)
	}

	pk, err := genPrivateKey(keySize)
	if err != nil {
		return nil, err
	}

	// If we are creating a root CA, issuer and issuerPk are its own certificate and private key.
	issuer := crt
	if input.IssuerCert != nil {
		issuer = input.IssuerCert
	}

	issuerPk := pk
	if input.IssuerPrivateKey != nil {
		issuerPk = input.IssuerPrivateKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crt, issuer, &pk.PublicKey, issuerPk)
	if err != nil {
		return nil, err
	}

	fName, err := exportPemCertToFile(input.CommonName, input.Dir, certBytes)
	if err != nil {
		return nil, err
	}

	if err = exportPemPrivateKeyToFile(input.CommonName, input.Dir, pk); err != nil {
		return nil, err
	}
	return &GenCertOutput{Certificate: crt, PrivateKey: pk, FileName: fName}, nil
}

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
)

// GenCertOutput represent the output after certificate generation.
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

// GenRootCA generates root ca certificate file and a private key.
func GenRootCA(cn, dir string, days int) (*GenCertOutput, error) {
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			CommonName:         cn,
			Country:            []string{"US"},
			Organization:       []string{"Example"},
			OrganizationalUnit: []string{"Example SRE"},
			Locality:           []string{"Los Angeles"},
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		Version:               3,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(0, 0, days).UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	pk, err := genPrivateKey(4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crt, crt, &pk.PublicKey, pk)
	if err != nil {
		return nil, err
	}

	fName, err := exportPemCertToFile(cn, dir, certBytes)
	if err != nil {
		return nil, err
	}

	if err = exportPemPrivateKeyToFile(cn, dir, pk); err != nil {
		return nil, err
	}
	return &GenCertOutput{Certificate: crt, PrivateKey: pk, FileName: fName}, nil
}

// GenIntermediateCA generates intermediate CA file and private key. Intermediate is signed by root CA 'caPk' private key.
// If more than one intermediate is requested and the hierarchy is 'ladder' each intermediate is signed by the previous
// intermediate's private key.
func GenIntermediateCA(ca *x509.Certificate, caPk *rsa.PrivateKey, cn, dir string, days int) (*GenCertOutput, error) {
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			CommonName:         cn,
			Country:            []string{"US"},
			Organization:       []string{"Example"},
			OrganizationalUnit: []string{"Example SRE"},
			Locality:           []string{"Los Angeles"},
		},
		Issuer:                ca.Subject,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		Version:               3,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(0, 0, days).UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	pk, err := genPrivateKey(4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crt, ca, &pk.PublicKey, caPk)
	if err != nil {
		return nil, err
	}

	fName, err := exportPemCertToFile(cn, dir, certBytes)
	if err != nil {
		return nil, err
	}

	if err = exportPemPrivateKeyToFile(cn, dir, pk); err != nil {
		return nil, err
	}
	return &GenCertOutput{Certificate: crt, PrivateKey: pk, FileName: fName}, nil
}

// GenServerCert generates a leaf certificate file and a private key.
func GenServerCert(ca *x509.Certificate, caPk *rsa.PrivateKey, cn, dir string, days int) error {
	crt := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			CommonName:         cn,
			Country:            []string{"US"},
			Organization:       []string{"Example"},
			OrganizationalUnit: []string{"Example SRE"},
			Locality:           []string{"Los Angeles"},
		},
		Issuer:             ca.Subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Version:            3,
		NotBefore:          time.Now().UTC(),
		NotAfter:           time.Now().AddDate(0, 0, days).UTC(),
		SubjectKeyId:       []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}

	pk, err := genPrivateKey(2048)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crt, ca, &pk.PublicKey, caPk)
	if err != nil {
		return err
	}

	if _, err = exportPemCertToFile(cn, dir, certBytes); err != nil {
		return err
	}

	if err = exportPemPrivateKeyToFile(cn, dir, pk); err != nil {
		return err
	}
	return nil
}

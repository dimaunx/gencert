package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaunx/gencert/pkg/utils"

	"github.com/stretchr/testify/assert"
)

var (
	currDir string
	tmpDir  string
)

func TestMain(m *testing.M) {
	currDir, _ = os.Getwd()
	err := utils.CreateDir("tmp")
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}
	tmpDir = filepath.Join(currDir, "tmp")

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestGenPrivateKey(t *testing.T) {
	t.Parallel()
	t.Run("genPrivateKey", func(t *testing.T) {
		t.Parallel()
		key, err := genPrivateKey(2048)
		assert.NoError(t, err)
		err = key.Validate()
		assert.NoError(t, err)
	})
	t.Run("genPrivateKeyError", func(t *testing.T) {
		t.Parallel()
		key, err := genPrivateKey(0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too few primes of given length to generate an RSA key")
		assert.Nil(t, key)
	})
}

func TestExportPemPrivateKeyToFile(t *testing.T) {
	t.Parallel()
	t.Run("exportPemPrivateKeyToFile", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = key.Validate()
		assert.NoError(t, err)
		err = exportPemPrivateKeyToFile("test.test.com", tmpDir, key)
		assert.NoError(t, err)
		f, err := os.Stat(filepath.Join(tmpDir, "test.test.com.key"))
		assert.NoError(t, err)
		assert.True(t, f.Size() > 0)
	})
	t.Run("exportPemPrivateKeyToFileErrorDirNotFound", func(t *testing.T) {
		t.Parallel()
		err := exportPemPrivateKeyToFile("test.test.com", "bad-dir", &rsa.PrivateKey{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})
}

func TestExportPemCertToFile(t *testing.T) {
	t.Parallel()
	t.Run("exportPemCertToFile", func(t *testing.T) {
		t.Parallel()
		crt := &x509.Certificate{
			SerialNumber: big.NewInt(2022),
			Subject: pkix.Name{
				CommonName:         "ca01-export",
				Country:            []string{"US"},
				Organization:       []string{"Example"},
				OrganizationalUnit: []string{"Example SRE"},
				Locality:           []string{"Los Angeles"},
			},
			SignatureAlgorithm:    x509.SHA256WithRSA,
			PublicKeyAlgorithm:    x509.RSA,
			Version:               3,
			NotBefore:             time.Now().UTC(),
			NotAfter:              time.Now().AddDate(0, 0, 1).UTC(),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}

		key, err := genPrivateKey(2048)
		assert.NoError(t, err)
		err = key.Validate()
		assert.NoError(t, err)
		certBytes, err := x509.CreateCertificate(rand.Reader, crt, crt, &key.PublicKey, key)
		assert.NoError(t, err)
		outName, err := exportPemCertToFile("ca01-export", tmpDir, certBytes)
		assert.NoError(t, err)
		out, err := os.Stat(outName)
		assert.NoError(t, err)
		assert.True(t, out.Size() > 0)
	})
	t.Run("exportPemCertToFileErrorDirNotFound", func(t *testing.T) {
		t.Parallel()
		outName, err := exportPemCertToFile("ca01-export", "bad-dir", []byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
		assert.Empty(t, outName)
	})
}

func TestExportPemChain(t *testing.T) {
	t.Parallel()
	t.Run("ExportPemChain", func(t *testing.T) {
		t.Parallel()
		certs := []*GenCertOutput{
			{
				Certificate: &x509.Certificate{},
				PrivateKey:  &rsa.PrivateKey{},
				FileName:    "./testdata/ca01.cert",
			},
			{
				Certificate: &x509.Certificate{},
				PrivateKey:  &rsa.PrivateKey{},
				FileName:    "./testdata/ca01-int01.cert",
			},
		}
		err := ExportPemChain(certs, tmpDir, "ca-chain01.cert")
		assert.NoError(t, err)
		chainFile, err := os.ReadFile(filepath.Join(tmpDir, "ca-chain01.cert"))
		assert.NoError(t, err)
		assert.True(t, len(chainFile) > 0)

		for _, f := range certs {
			data, err := os.ReadFile(f.FileName)
			assert.NoError(t, err)
			assert.Contains(t, string(chainFile), string(data))
		}
	})
	t.Run("ExportPemChainErrorReadFileNotFound", func(t *testing.T) {
		t.Parallel()
		certs := []*GenCertOutput{
			{
				Certificate: &x509.Certificate{},
				PrivateKey:  &rsa.PrivateKey{},
				FileName:    "./testdata/do-not-exist.cert",
			},
		}
		err := ExportPemChain(certs, tmpDir, "ca-chain02.cert")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})
	t.Run("ExportPemChainErrorWriteDirNotFound", func(t *testing.T) {
		t.Parallel()
		err := ExportPemChain([]*GenCertOutput{}, "bad-dir", "ca-chain03.cert")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})
}

func TestGenCert(t *testing.T) {
	t.Parallel()
	t.Run("GenCertRootCA", func(t *testing.T) {
		t.Parallel()
		root, err := GenCert(&GenCertInput{
			CommonName:   "ca02",
			Dir:          tmpDir,
			DaysDuration: 1,
			Type:         "root",
		})
		assert.NoError(t, err)
		assert.NotNil(t, root)
		assert.Equal(t, true, root.Certificate.IsCA)

		intermediate, err := GenCert(&GenCertInput{
			CommonName:       "ca02-int01",
			Dir:              tmpDir,
			DaysDuration:     1,
			Type:             "intermediate",
			IssuerCert:       root.Certificate,
			IssuerPrivateKey: root.PrivateKey,
		})
		assert.NoError(t, err)
		assert.NotNil(t, intermediate)
		assert.Equal(t, true, intermediate.Certificate.IsCA)

		leaf, err := GenCert(&GenCertInput{
			CommonName:       "test2.test.com",
			Dir:              tmpDir,
			DaysDuration:     1,
			Type:             "leaf",
			IssuerCert:       intermediate.Certificate,
			IssuerPrivateKey: intermediate.PrivateKey,
		})
		assert.NoError(t, err)
		assert.NotNil(t, leaf)
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, leaf.Certificate.ExtKeyUsage)

		rootBytes, err := os.ReadFile(root.FileName)
		assert.NoError(t, err)
		rootBlock, _ := pem.Decode(rootBytes)
		rootPem, err := x509.ParseCertificate(rootBlock.Bytes)
		assert.NoError(t, err)

		interBytes, err := os.ReadFile(intermediate.FileName)
		assert.NoError(t, err)
		interBlock, _ := pem.Decode(interBytes)
		interPem, err := x509.ParseCertificate(interBlock.Bytes)
		assert.NoError(t, err)

		crtBytes, err := os.ReadFile(leaf.FileName)
		assert.NoError(t, err)
		crtBlock, _ := pem.Decode(crtBytes)
		crt, err := x509.ParseCertificate(crtBlock.Bytes)
		assert.NoError(t, err)

		opts := x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
			Roots:         x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		opts.Roots.AddCert(rootPem)
		opts.Intermediates.AddCert(interPem)
		_, err = crt.Verify(opts)
		assert.NoError(t, err)
	})
	t.Run("GenCertRootCAErrorUnsupportedType", func(t *testing.T) {
		t.Parallel()
		root, err := GenCert(&GenCertInput{
			CommonName:   "ca03",
			Dir:          tmpDir,
			DaysDuration: 1,
			Type:         "unsupported",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported certificate type")
		assert.Nil(t, root)
	})
}

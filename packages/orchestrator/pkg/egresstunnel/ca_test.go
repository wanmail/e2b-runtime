package egresstunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerCertificateSPIFFEURI(t *testing.T) {
	t.Parallel()

	ca, key := mustTestCA(t)
	signer := NewSigner(ca, key)
	id := "spiffe://e2b.local/ns/team/sbx/s1/exec/e1"

	cert, err := signer.Certificate(id)
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	require.Len(t, cert.Leaf.URIs, 1)
	assert.Equal(t, id, cert.Leaf.URIs[0].String())

	again, err := signer.Certificate(id)
	require.NoError(t, err)
	assert.Equal(t, cert.Leaf.SerialNumber, again.Leaf.SerialNumber)
}

func TestLoadSignerRoundTrip(t *testing.T) {
	t.Parallel()

	ca, key := mustTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, pemEncodeCert(t, ca), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pemEncodeKey(t, key), 0o600))

	signer, err := LoadSigner(certPath, keyPath)
	require.NoError(t, err)
	_, err = signer.Certificate("spiffe://e2b.local/ns/t/sbx/s/exec/e")
	require.NoError(t, err)
}

func TestAuthority(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "api.example.com:443", Authority("api.example.com", net.IPv4(1, 2, 3, 4), 443))
	assert.Equal(t, "1.2.3.4:80", Authority("", net.IPv4(1, 2, 3, 4), 80))
	assert.Equal(t, "", Authority("", nil, 443))
}

func mustTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test egress tunnel CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

func pemEncodeCert(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func pemEncodeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func issueServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ip net.IP) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gateway"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}

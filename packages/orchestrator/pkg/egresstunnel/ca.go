package egresstunnel

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	leafTTL      = time.Hour
	leafRefreshAt = 10 * time.Minute
)

type cachedLeaf struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// Signer issues short-lived X.509-SVIDs from an in-process intermediate CA.
type Signer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer

	mu    sync.Mutex
	cache map[string]cachedLeaf
}

// NewSigner wraps an already-parsed CA certificate and key.
func NewSigner(caCert *x509.Certificate, caKey crypto.Signer) *Signer {
	return &Signer{
		caCert: caCert,
		caKey:  caKey,
		cache:  make(map[string]cachedLeaf),
	}
}

// LoadSigner reads PEM-encoded CA cert and key from disk.
func LoadSigner(certPath, keyPath string) (*Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read tunnel CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read tunnel CA key: %w", err)
	}

	cert, key, err := parseCA(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return NewSigner(cert, key), nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("tunnel CA cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("tunnel CA key: no PEM block")
	}

	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel CA key: %w", err)
	}

	return cert, key, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", k)
		}

		return s, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}

	return nil, fmt.Errorf("unrecognized private key encoding")
}

// Certificate returns a tls.Certificate for spiffeID, minting or rotating as needed.
func (s *Signer) Certificate(spiffeID string) (*tls.Certificate, error) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if leaf, ok := s.cache[spiffeID]; ok && now.Add(leafRefreshAt).Before(leaf.expiresAt) {
		return leaf.cert, nil
	}

	cert, expiresAt, err := s.issue(spiffeID, now)
	if err != nil {
		return nil, err
	}
	s.cache[spiffeID] = cachedLeaf{cert: cert, expiresAt: expiresAt}

	return cert, nil
}

func (s *Signer) issue(spiffeID string, now time.Time) (*tls.Certificate, time.Time, error) {
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse SPIFFE id: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("serial: %w", err)
	}

	expiresAt := now.Add(leafTTL)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create leaf: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse leaf: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, s.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}

	return tlsCert, expiresAt, nil
}

func (s *Signer) forget(spiffeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, spiffeID)
}

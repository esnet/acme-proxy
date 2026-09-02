// Command probe: end-to-end ACME test client against the local acme-proxy.
// It registers an account, orders a cert for the given domain using http-01
// with a no-op challenge provider (the proxy is expected to mark the
// challenge valid without contacting us), and finalizes the order.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

const (
	proxyHost = "acmeproxy.example.com"
	proxyIP   = "192.0.2.10"
)

type acct struct {
	email string
	reg   *acme.ExtendedAccount
	key   crypto.Signer
}

func (a *acct) GetEmail() string                       { return a.email }
func (a *acct) GetRegistration() *acme.ExtendedAccount { return a.reg }
func (a *acct) GetPrivateKey() crypto.Signer           { return a.key }

type noopProvider struct{}

func (noopProvider) Present(ctx context.Context, domain, token, keyAuth string) error { return nil }
func (noopProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error { return nil }

func main() {
	domain := os.Args[1]

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("keygen:", err)
		os.Exit(1)
	}
	u := &acct{email: "probe@example.com", key: acctKey}

	cfg := lego.NewConfig(u)
	cfg.CADirURL = "https://" + proxyHost + "/acme/acme/directory"

	// Pin the proxy hostname to its client-facing IP (labca's own resolver
	// returns the challenge IP 10.11.11.217, where nothing listens on :443).
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	cfg.HTTPClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if host, port, err := net.SplitHostPort(addr); err == nil && host == proxyHost {
					addr = net.JoinHostPort(proxyIP, port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		fmt.Println("client:", err)
		os.Exit(1)
	}
	if err := client.Challenge.SetHTTP01Provider(noopProvider{}); err != nil {
		fmt.Println("provider:", err)
		os.Exit(1)
	}

	fmt.Printf("[%s] registering account...\n", time.Now().Format("15:04:05.000"))
	reg, err := client.Registration.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		fmt.Println("register:", err)
		os.Exit(1)
	}
	u.reg = reg

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("certkey:", err)
		os.Exit(1)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}, certKey)
	if err != nil {
		fmt.Println("csr:", err)
		os.Exit(1)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		fmt.Println("parse csr:", err)
		os.Exit(1)
	}

	fmt.Printf("[%s] ordering %s (http-01, no-op provider)...\n", time.Now().Format("15:04:05.000"), domain)
	start := time.Now()
	res, err := client.Certificate.ObtainForCSR(context.Background(), certificate.ObtainForCSRRequest{CSR: csr, Bundle: true})
	if err != nil {
		fmt.Printf("[%s] FAILED after %v: %v\n", time.Now().Format("15:04:05.000"), time.Since(start), err)
		os.Exit(1)
	}

	block, _ := pem.Decode(res.Certificate)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("parse leaf:", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] SUCCESS in %v: cn=%s issuer=%s valid=%v→%v\n",
		time.Now().Format("15:04:05.000"), time.Since(start).Round(time.Millisecond),
		leaf.Subject.CommonName, leaf.Issuer.CommonName,
		leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
}

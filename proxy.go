package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

func generateCA() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	// Certificate template with proper CA settings
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"HTTPS Filter Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "HTTPS Filter Proxy CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour), // Valid from yesterday
		NotAfter:              time.Now().AddDate(10, 0, 0),    // Valid for 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save certificate PEM to file
	err = os.WriteFile("https-filter-ca.pem", certPEM, 0644)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Save key PEM to file (for backup)
	err = os.WriteFile("https-filter-ca-key.pem", keyPEM, 0600)
	if err != nil {
		return tls.Certificate{}, err
	}

	log.Println("✓ Generated CA certificate: https-filter-ca.pem")
	log.Println("✓ Generated CA private key: https-filter-ca-key.pem")
	log.Println("")
	log.Println("IMPORTANT: Install the certificate to trust it:")
	log.Println("  Windows: Run as Admin -> certutil -addstore Root https-filter-ca.pem")
	log.Println("  Or: Double-click https-filter-ca.pem -> Install Certificate -> Local Machine -> Trusted Root Certification Authorities")
	log.Println("")

	// Create tls.Certificate from PEM
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}

func main() {
	// Check if CA already exists
	var caCert tls.Certificate
	

	if _, err := os.Stat("https-filter-ca.pem"); err == nil {
		// Load existing CA
		log.Println("Loading existing CA certificate...")
		certPEM, err := os.ReadFile("https-filter-ca.pem")
		if err != nil {
			log.Fatal("Failed to read CA certificate: ", err)
		}
		keyPEM, err := os.ReadFile("https-filter-ca-key.pem")
		if err != nil {
			log.Fatal("Failed to read CA key: ", err)
		}
		caCert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatal("Failed to load CA: ", err)
		}
		log.Println("✓ Loaded existing CA certificate")
	} else {
		// Generate new CA
		log.Println("Generating new CA certificate...")
		caCert, err = generateCA()
		if err != nil {
			log.Fatal("Failed to generate CA: ", err)
		}
	}

	// Set the CA for MITM
	goproxy.GoproxyCa = caCert

	// Create proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	// Enable HTTPS MITM for all connections
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Block specific domains
	blockedDomains := regexp.MustCompile(`(example\.com|blocked-site\.com)`)

	// Block HTTPS connections to blocked domains
	proxy.OnRequest(goproxy.ReqHostMatches(blockedDomains)).
		HandleConnect(goproxy.AlwaysReject)

	// Block HTTP requests to blocked domains
	proxy.OnRequest(goproxy.ReqHostMatches(blockedDomains)).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			log.Printf("❌ Blocked request to: %s", req.URL.Host)
			return req, goproxy.NewResponse(req,
				goproxy.ContentTypeHtml, http.StatusForbidden,
				`<html><body><h1>Access Denied</h1><p>This site is blocked by HTTPS Filter Proxy.</p></body></html>`)
		})

	// Log all HTTPS requests (after MITM)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Printf("→ Request: %s %s", req.Method, req.URL.String())
		return req, nil
	})

	// Filter responses by keyword and content
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text") && !strings.Contains(contentType, "application/json") {
			return resp
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			return resp
		}
		resp.Body.Close()

		bodyStr := string(body)

		// Check for blocked keywords
		blockedKeywords := []string{"vulture", "bullrun", "eagle"}
		for _, keyword := range blockedKeywords {
			if strings.Contains(strings.ToLower(bodyStr), keyword) {
				log.Printf("❌ Blocked response from %s - contains keyword: %s", ctx.Req.URL, keyword)
				return goproxy.NewResponse(ctx.Req,
					goproxy.ContentTypeHtml, http.StatusForbidden,
					`<html><body><h1>Content Blocked</h1><p>This content was blocked due to prohibited keywords.</p></body></html>`)
			}
		}

		// Reconstruct response body
		resp.Body = io.NopCloser(bytes.NewReader(body))
		log.Printf("✓ Response from %s (%d bytes)", ctx.Req.URL.Host, len(body))
		return resp
	})

	// Start proxy
	log.Println("")
	log.Println("========================================")
	log.Println("HTTPS Filter Proxy Server")
	log.Println("========================================")
	log.Println("Listening on: http://localhost:8080")
	log.Println("Blocked domains: example.com, blocked-site.com")
	log.Println("Blocked keywords: spam, malware, phishing")
	log.Println("========================================")
	log.Println("")

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", proxy))
}
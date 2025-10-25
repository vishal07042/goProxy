package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/disintegration/imaging"
	"github.com/elazarl/goproxy"
)

// generateCA function to generate a self-signed CA certificate
func generateCA() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

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
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	err = os.WriteFile("https-filter-ca.pem", certPEM, 0644)
	if err != nil {
		return tls.Certificate{}, err
	}

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

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}

var inputName string = "images" // Typical for YOLO-based NudeNet; confirm with Netron if needed
var outputName string = "output0"
var nudenetEnabled bool = false

var nudenetLabels = []string{
	"SEXY", "FEMALE_GENITALIA", "FEMALE_BREAST", "FEMALE_BUTTOCKS",
	"MALE_GENITALIA", "MALE_CHEST", "FEMALE_FLESH", "MALE_FLESH",
	"FEET", "FACE", "SEXUAL_ACT", "LINGERIE", "SWIMWEAR",
}

func initNudeNetONNX() error {
	// Get current working directory
	dir, _ := os.Getwd()
	dllPath := dir + "\\onnxruntime.dll"
	
	log.Println("Attempting to initialize ONNX Runtime...")
	log.Printf("Current working directory: %s", dir)
	log.Printf("Attempting to load DLL from: %s", dllPath)
	
	// Check if the DLL file exists
	if _, err := os.Stat(dllPath); err != nil {
		log.Printf("ONNX Runtime DLL not found at: %s", dllPath)
		return fmt.Errorf("ONNX Runtime DLL not found at: %s", dllPath)
	} else {
		log.Println("ONNX Runtime DLL found")
	}
	
	// Set the DLL path explicitly
	ort.SetSharedLibraryPath(dllPath)
	log.Printf("Set DLL path to: %s", dllPath)

	// Initialize environment with error handling
	if err := ort.InitializeEnvironment(); err != nil {
		log.Printf("ONNX Runtime initialization failed: %v", err)
		log.Println("Images will pass through without filtering.")
		nudenetEnabled = false
		return fmt.Errorf("ONNX Runtime initialization failed: %v", err)
	}

	// Check if model exists
	modelPath := "./nudenet.onnx"
	if _, err := os.Stat(modelPath); err != nil {
		log.Printf("NudeNet model not found: %s", modelPath)
		log.Println("Images will pass through without filtering.")
		nudenetEnabled = false
		return fmt.Errorf("NudeNet model not found: %s", modelPath)
	}

	nudenetEnabled = true
	log.Println("✓ NudeNet ONNX environment initialized successfully")
	return nil
}

func isNSFW(imageBytes []byte) (bool, error) {
	if !nudenetEnabled {
		return false, nil // Skip NSFW detection if not enabled
	}

	// Decode image
	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return false, err
	}

	// Preprocess: Resize to 320x320 for NudeNet (adjust if model differs)
	// Changed from 640x640 to 320x320 to match model expectations
	resized := imaging.Resize(img, 320, 320, imaging.Lanczos)
	rgba := image.NewRGBA(resized.Bounds())
	draw.Draw(rgba, rgba.Bounds(), resized, image.Point{}, draw.Src)

	// Prepare input: CHW, float32 [0,255]
	// Changed dimensions from 640x640 to 320x320
	inputData := make([]float32, 3*320*320)
	for y := 0; y < 320; y++ {
		for x := 0; x < 320; x++ {
			r, g, b, _ := rgba.At(x, y).RGBA()
			// CHW order
			inputData[(0*320+y)*320+x] = float32(r >> 8) // R
			inputData[(1*320+y)*320+x] = float32(g >> 8) // G
			inputData[(2*320+y)*320+x] = float32(b >> 8) // B
		}
	}

	// Create tensors
	// Changed input shape from [1, 3, 640, 640] to [1, 3, 320, 320]
	inputShape := ort.NewShape(1, 3, 320, 320)
	inputTensor, err := ort.NewTensor[float32](inputShape, inputData)
	if err != nil {
		log.Printf("Failed to create input tensor: %v", err)
		return false, nil // Fall back to not filtering
	}
	defer inputTensor.Destroy()

	// For detection, output shape is typically [1, 25200, 85] for YOLOv8
	// This should remain the same regardless of input size
	outputShape := ort.NewShape(1, 25200, 85)
	outputData := make([]float32, 1*25200*85)
	outputTensor, err := ort.NewTensor[float32](outputShape, outputData)
	if err != nil {
		log.Printf("Failed to create output tensor: %v", err)
		return false, nil // Fall back to not filtering
	}
	defer outputTensor.Destroy()

	// Create new session with actual tensors
	session, err := ort.NewSession[float32]("./nudenet.onnx", []string{inputName}, []string{outputName}, []*ort.Tensor[float32]{inputTensor}, []*ort.Tensor[float32]{outputTensor})
	if err != nil {
		log.Printf("Failed to create ONNX session: %v", err)
		return false, nil // Fall back to not filtering
	}
	defer session.Destroy()

	// Run inference
	if err := session.Run(); err != nil {
		log.Printf("ONNX inference failed: %v", err)
		return false, nil // Fall back to not filtering
	}

	probs := outputTensor.GetData()
	log.Printf("NudeNet Output Shape: len=%d", len(probs))

	// For detection, parse bounding boxes and classes; flag if any explicit class conf > 0.3 (lowered from 0.5)
	// Simplified: Check if any conf > 0.3 for explicit classes (indices 5+ for classes)
	isNsfw := false
	maxConf := float32(0.0)
	for i := 0; i < len(probs); i += 85 {
		conf := probs[i+4] // Conf index
		if conf > maxConf {
			maxConf = conf
		}
		if conf > 0.3 { // Lowered from 0.5
			// Check class indices 5 to 84 for explicit (e.g., map to labels)
			for j := 5; j < 85; j++ {
				classConf := probs[i+j]
				if classConf > maxConf {
					maxConf = classConf
				}
				if classConf > 0.3 { // Lowered from 0.5
					isNsfw = true
					log.Printf("NSFW detected - Object confidence: %.2f, Class confidence: %.2f", conf, classConf)
					break
				}
			}
			if isNsfw {
				break
			}
		}
	}

	log.Printf("NudeNet NSFW: %v, Max confidence: %.2f", isNsfw, maxConf)
	return isNsfw, nil
}

func blurImage(imageBytes []byte, contentType string) ([]byte, error) {
	format := strings.TrimPrefix(contentType, "image/")
	format = strings.TrimSuffix(format, ";")

	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return nil, err
	}

	blurred := imaging.Blur(img, 20.0)

	var buf bytes.Buffer
	var encErr error
	switch format {
	case "jpeg", "jpg":
		encErr = imaging.Encode(&buf, blurred, imaging.JPEG, imaging.JPEGQuality(90))
	case "png":
		encErr = imaging.Encode(&buf, blurred, imaging.PNG)
	case "gif":
		encErr = imaging.Encode(&buf, blurred, imaging.GIF)
	default:
		return nil, fmt.Errorf("unsupported image format: %s", format)
	}

	if encErr != nil {
		return nil, encErr
	}

	return buf.Bytes(), nil
}

func main() {
	log.Println("Starting HTTPS Filter Proxy...")
	
	// CA setup
	var caCert tls.Certificate

	if _, err := os.Stat("https-filter-ca.pem"); err == nil {
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
		log.Println("Generating new CA certificate...")
		var err error
		caCert, err = generateCA()
		if err != nil {
			log.Fatal("Failed to generate CA: ", err)
		}
	}

	goproxy.GoproxyCa = caCert

	// Init NudeNet ONNX
	log.Println("Initializing NudeNet ONNX...")
	if err := initNudeNetONNX(); err != nil {
		log.Printf("Warning: %v", err)
		log.Println("Images will pass through without filtering.")
		nudenetEnabled = false
	} else {
		log.Println("NudeNet ONNX initialized successfully")
	}

	// Create proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	// Enable HTTPS MITM
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Block domains
	blockedDomains := regexp.MustCompile(`(example\.com|blocked-site\.com)`)

	proxy.OnRequest(goproxy.ReqHostMatches(blockedDomains)).HandleConnect(goproxy.AlwaysReject)

	proxy.OnRequest(goproxy.ReqHostMatches(blockedDomains)).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			log.Printf("❌ Blocked request to: %s", req.URL.Host)
			return req, goproxy.NewResponse(req,
				goproxy.ContentTypeHtml, http.StatusForbidden,
				`<html><body><h1>Access Denied</h1><p>This site is blocked by HTTPS Filter Proxy.</p></body></html>`)
		})

	// Log requests
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Printf("→ Request: %s %s", req.Method, req.URL.String())
		return req, nil
	})

	// Response filter: keywords + NudeNet blurring
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			resp.Body.Close()
			return resp
		}
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(contentType, "text") || strings.Contains(contentType, "application/json") {
			blockedKeywords := []string{"vulture", "bullrun", "eagle"}
			for _, keyword := range blockedKeywords {
				if strings.Contains(strings.ToLower(bodyStr), keyword) {
					log.Printf("❌ Blocked response from %s - contains keyword: %s", ctx.Req.URL, keyword)
					return goproxy.NewResponse(ctx.Req,
						goproxy.ContentTypeHtml, http.StatusForbidden,
						`<html><body><h1>Content Blocked</h1><p>This content was blocked due to prohibited keywords.</p></body></html>`)
				}
			}
		} else if strings.HasPrefix(contentType, "image/") {
			log.Printf("🔍 Processing image from %s (%d bytes, type: %s)", ctx.Req.URL.Host, len(body), contentType)
			isNsfw, err := isNSFW(body)
			if err != nil {
				log.Printf("NSFW check error for %s: %v", ctx.Req.URL, err)
				isNsfw = false
			}
			if isNsfw {
				newBody, err := blurImage(body, contentType)
				if err != nil {
					log.Printf("❌ Blur error for %s: %v", ctx.Req.URL, err)
				} else {
					body = newBody
					log.Printf("🔒 Blurred NSFW image from %s", ctx.Req.URL)
				}
			} else {
				log.Printf("✓ Safe image from %s (%d bytes)", ctx.Req.URL.Host, len(body))
			}
		} else {
			log.Printf("✓ Passed through non-text/image from %s (%d bytes)", ctx.Req.URL.Host, len(body))
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	})

	log.Println("Starting HTTPS Filter Proxy on :8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", proxy))
}

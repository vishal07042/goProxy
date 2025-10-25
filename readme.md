# HTTPS Filter Proxy with NSFW Content Filtering

## Overview
This is a HTTPS proxy server that can filter content including:
- Block specific domains
- Filter content by keywords
- Detect and blur NSFW images using AI

## Setup Instructions

### 1. Certificate Installation
```bash
# Install the CA certificate to trust it
certutil -addstore -f Root https-filter-ca.pem

# For Edge/Chrome, also import your certificate here:
# edge://settings/certificates
```

### 2. ONNX Runtime Requirements
This project requires ONNX Runtime for NSFW image detection. The following versions have been tested and work together:

- Go wrapper: `github.com/yalue/onnxruntime_go v1.22.0`
- ONNX Runtime DLL: `v1.22.1` (Downloaded from https://github.com/microsoft/onnxruntime/releases/tag/v1.22.1)

The ONNX Runtime files should be placed in the project root directory:
- `onnxruntime.dll`
- `onnxruntime_providers_shared.dll`

### 3. NudeNet Model
The project uses the NudeNet ONNX model for NSFW detection. Make sure `nudenet.onnx` is in the project root directory.
You can download it from: https://huggingface.co/vladmandic/nudenet/resolve/main/nudenet.onnx

### 4. Running the Proxy
```bash
go run proxy.go
```

The proxy will start on `http://127.0.0.1:8083`

### 5. Configure Your Browser
Set your browser's proxy settings to:
- HTTP Proxy: `127.0.0.1`
- Port: `8080`

## Features
- HTTPS MITM (Man-in-the-Middle) with automatic certificate generation
- Domain blocking (configured in the code)
- Keyword filtering in text content
- NSFW image detection and automatic blurring
- Detailed logging of all requests

## Configuration
- Blocked domains: Edit the regex in `proxy.go`
- Blocked keywords: Edit the `blockedKeywords` array in `proxy.go`
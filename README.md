# Mews

A TLS-terminating HTTP proxy with SSH bastion support and mandatory certificate pinning.

## Features

- **TLS termination** - Proxy HTTPS backends with self-signed certificates
- **Certificate pinning** - Mandatory SHA-256 fingerprint verification for TLS
- **SSH host key pinning** - Mandatory fingerprint verification for SSH bastions
- **SSH bastion support** - Access remote hosts through SSH jump hosts
- **Automatic failover** - Round-robin through bastion sets with reconnection
- **Touch-verified SSH** - Auto-refresh waiting page for SSH touch verification
- **Localhost-only** - Always binds to localhost for security

## Installation

```bash
# Build
go build

# Install to $GOPATH/bin
go install
```

## Usage

```bash
# Default (listens on localhost:6189)
./mews --config config.yaml

# Custom port (always localhost)
./mews --config config.yaml --port 3000
```

Visit `http://localhost:6189/` to see the index page with all configured upstreams.

## Development

```bash
# Run tests
go test ./...

# Run tests with coverage
go test ./... -cover

# Run tests with verbose output
go test ./... -v

# Build for current platform
go build

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o mews-linux

# Clean build artifacts
go clean
rm -f mews mews-*
```

## Configuration

See `config-example.yaml` for a complete example.

### Minimal Example

```yaml
bastions:
  dc1-bastions:
    - name: "bastion-a"
      host: "bastion-a.example.com"
      user: "admin"
      fingerprint: "SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

upstreams:
  - local: "bmc1"  # Becomes bmc1.localhost automatically
    remote: "https://10.1.1.1"
    bastion_set: "dc1-bastions"
    fingerprint: "a3d0405e7f32a7a2b408974830bfe673b9f3e8c76600df73e7e809d0dff09d18"
```

### Discovering SSH Host Key Fingerprints

```bash
ssh-keyscan -t ed25519 bastion-a.example.com 2>/dev/null | \
  ssh-keygen -lf - | awk '{print $2}'
```

### Discovering TLS Certificate Fingerprints

```bash
openssl s_client -connect 10.1.1.1:443 < /dev/null 2>/dev/null | \
  openssl x509 -fingerprint -sha256 -noout | \
  cut -d'=' -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]'
```

## Architecture

```
Browser → Mews Proxy → SSH Bastion → Remote HTTPS Server
          (localhost)   (jump host)    (self-signed cert)
```

### Project Structure

```
mews/
├── main.go             # Main entry point
├── config.go           # Configuration loading
├── bastion.go          # SSH connection management
├── proxy.go            # HTTP proxy server
├── proxy_test.go       # Tests
├── config-example.yaml
├── go.mod
└── README.md
```

## How It Works

1. **Configuration** - Load config with bastions and upstreams
2. **Connection** - Establish SSH connection to random bastion on first request
3. **SSH Pinning** - Verify SSH host key fingerprint matches configured pin
4. **Tunneling** - Proxy HTTPS requests through SSH tunnel
5. **TLS Pinning** - Verify TLS certificate fingerprint matches configured pin
6. **Failover** - Reconnect to different bastion if connection fails

## License

Apache 2.0


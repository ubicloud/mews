# Mews

**mews** -- noun
An alley where there are stables; a narrow passage; a confined place.
*GNU version of the Collaborative International Dictionary of English*

`mews` is a SSH-tunneling, public-key pinning, TLS-terminating local
HTTP proxy.

`mews` uses a configuration file containing addresses and fingerprints
that is intended to be stored in version control and shared by a team.

`mews` relies on behavior specified in RFC 6761, where any subdomain
of `localhost`, e.g. `foo.localhost`, resolves to the same address as
`localhost`. This property is powerful when combined with HTTP
virtual hosting, a fundamental underpinning of `mews`. Some operating
systems implement this in their DNS stacks, though macOS is not among
them. However, Firefox and Chrome (but not Safari) take it upon
themselves to implement this, so the feature remains usable.

`mews` exclusively relies on ssh agent protocol for its credentials.
It sources its `ssh-agent` in an order similar to OpenSSH, listed here
in **increasing** precedence:

1. The environment variable `SSH_AUTH_SOCK`
2. Via .`ssh/config` by running `ssh -G <TARGET>`
3. The flag `-agent=<SOMEPATH>`

### Minimal `mews.yaml` example

```yaml
bastions:
  dc1-bastions:
    - name: "bastion-a"
      host: "bastion-a.example.com"
      user: "tunneluser"
      fingerprint: "SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

upstreams:
  - local: "bmc1"  # Implies visiting http://bmc1.localhost
    remote: "https://10.1.1.1"
    bastion_set: "dc1-bastions"
    fingerprint: "a3d0405e7f32a7a2b408974830bfe673b9f3e8c76600df73e7e809d0dff09d18"
```

## Usage

```bash

# Default to config.yml and listening on localhost:6189
./mews

# Custom port on localhost and configuration file
./mews --config mews.yaml --port 3000
```

Visit `http://localhost:6189/` to see the index page with all configured upstreams.

## Installation

```bash
# Build
go build

# Install to $GOPATH/bin
go install
```

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

## License

Apache 2.0

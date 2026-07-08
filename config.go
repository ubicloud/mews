package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Protocol selects how mews carries upstream dials over the SSH connection
// to a bastion.
//
//   - ProtocolDirectTCPIP: plain direct-tcpip through the SSH transport.
//     One SSH channel per dial. No bastion-side program required.
//   - ProtocolFunpipe: the bastion's sshd ForceCommand runs the funpipe
//     server, and mews speaks the funpipe stream-mux protocol over one
//     session's stdin/stdout, multiplexing all dials over it.
type Protocol string

const (
	ProtocolDirectTCPIP Protocol = "direct-tcpip"
	ProtocolFunpipe     Protocol = "funpipe"
)

type Bastion struct {
	Name        string `yaml:"name"`
	Host        string `yaml:"host"`
	Port        string `yaml:"port"`
	User        string `yaml:"user"`
	Fingerprint string `yaml:"fingerprint"`
	// How mews carries dials over this bastion. One of "direct-tcpip"
	// or "funpipe". Defaults to "direct-tcpip" when unset. See Protocol.
	Protocol Protocol `yaml:"protocol,omitempty"`
}

type Config struct {
	BastionSets map[string][]Bastion `yaml:"bastions"`
	Upstreams   []Upstream           `yaml:"upstreams"`
}

type Upstream struct {
	Local       string `yaml:"local"`
	Remote      string `yaml:"remote"`
	BastionSet  string `yaml:"bastion_set,omitempty"`
	Fingerprint string `yaml:"fingerprint"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	for i, upstream := range config.Upstreams {
		if upstream.Fingerprint == "" {
			return nil, fmt.Errorf("upstream %d (%s): fingerprint is required for all upstreams", i, upstream.Local)
		}
		// Automatically append .localhost to all local names
		if !strings.HasSuffix(upstream.Local, ".localhost") {
			config.Upstreams[i].Local = upstream.Local + ".localhost"
		}
	}

	for setName, bastions := range config.BastionSets {
		for i := range bastions {
			if bastions[i].Port == "" {
				bastions[i].Port = "22"
			}
			if bastions[i].User == "" {
				bastions[i].User = os.Getenv("USER")
			}
			if bastions[i].Fingerprint == "" {
				return nil, fmt.Errorf("bastion set %s, bastion %s: fingerprint is required", setName, bastions[i].Name)
			}
			switch bastions[i].Protocol {
			case ProtocolDirectTCPIP, ProtocolFunpipe:
				// ok
				//
			case "":
				bastions[i].Protocol = ProtocolDirectTCPIP

			default:
				return nil, fmt.Errorf("bastion set %s, bastion %s: unknown protocol %q (expected %q or %q)",
					setName, bastions[i].Name, bastions[i].Protocol, ProtocolDirectTCPIP, ProtocolFunpipe)
			}
		}
		// Shuffle bastions once for random load distribution
		rand.Shuffle(len(bastions), func(i, j int) {
			bastions[i], bastions[j] = bastions[j], bastions[i]
		})
		config.BastionSets[setName] = bastions
	}

	return &config, nil

}

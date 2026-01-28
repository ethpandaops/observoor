package beacon

import "time"

// Config holds configuration for the beacon node client.
type Config struct {
	// Endpoint is the HTTP URL of the CL beacon node API.
	Endpoint string `yaml:"endpoint"`

	// Timeout for HTTP requests to the beacon node.
	// Defaults to 10s.
	Timeout time.Duration `yaml:"timeout"`
}

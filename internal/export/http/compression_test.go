package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressor_Gzip(t *testing.T) {
	c, err := NewCompressor(CompressionGzip)
	require.NoError(t, err)
	defer c.Close()

	// Use larger data to ensure compression is effective.
	original := []byte("hello world, this is test data for compression, " +
		"hello world, this is test data for compression, " +
		"hello world, this is test data for compression")
	compressed, err := c.Compress(original)
	require.NoError(t, err)

	assert.Less(t, len(compressed), len(original))
	assert.Equal(t, "gzip", c.ContentEncoding())

	// Verify round-trip.
	decompressed, err := DecompressGzip(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressor_Zstd(t *testing.T) {
	c, err := NewCompressor(CompressionZstd)
	require.NoError(t, err)
	defer c.Close()

	original := []byte("hello world, this is test data for compression")
	compressed, err := c.Compress(original)
	require.NoError(t, err)

	assert.Equal(t, "zstd", c.ContentEncoding())

	// Verify round-trip.
	decompressed, err := DecompressZstd(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressor_Zlib(t *testing.T) {
	c, err := NewCompressor(CompressionZlib)
	require.NoError(t, err)
	defer c.Close()

	// Use larger data to ensure compression is effective.
	original := []byte("hello world, this is test data for compression, " +
		"hello world, this is test data for compression, " +
		"hello world, this is test data for compression")
	compressed, err := c.Compress(original)
	require.NoError(t, err)

	assert.Less(t, len(compressed), len(original))
	assert.Equal(t, "deflate", c.ContentEncoding())

	// Verify round-trip.
	decompressed, err := DecompressZlib(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressor_Snappy(t *testing.T) {
	c, err := NewCompressor(CompressionSnappy)
	require.NoError(t, err)
	defer c.Close()

	original := []byte("hello world, this is test data for compression, " +
		"hello world, this is test data for compression")
	compressed, err := c.Compress(original)
	require.NoError(t, err)

	assert.Equal(t, "snappy", c.ContentEncoding())

	// Verify round-trip.
	decompressed, err := DecompressSnappy(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressor_None(t *testing.T) {
	c, err := NewCompressor(CompressionNone)
	require.NoError(t, err)
	defer c.Close()

	original := []byte("hello world")
	compressed, err := c.Compress(original)
	require.NoError(t, err)

	assert.Equal(t, original, compressed)
	assert.Equal(t, "", c.ContentEncoding())
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Enabled:      true,
				Address:      "http://localhost:8080",
				BatchSize:    100,
				MaxQueueSize: 1000,
				Workers:      1,
			},
			wantErr: false,
		},
		{
			name: "disabled config - no validation",
			cfg: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "missing address",
			cfg: Config{
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "invalid compression",
			cfg: Config{
				Enabled:     true,
				Address:     "http://localhost:8080",
				Compression: "invalid",
			},
			wantErr: true,
		},
		{
			name: "batch size > queue size",
			cfg: Config{
				Enabled:      true,
				Address:      "http://localhost:8080",
				BatchSize:    1000,
				MaxQueueSize: 100,
				Workers:      1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ApplyDefaults()
			err := tt.cfg.Validate()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

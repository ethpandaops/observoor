package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

// Compression type constants.
const (
	CompressionNone   = "none"
	CompressionGzip   = "gzip"
	CompressionZstd   = "zstd"
	CompressionZlib   = "zlib"
	CompressionSnappy = "snappy"
)

// Compressor compresses data using a specified algorithm.
type Compressor struct {
	algorithm string
	encoder   *zstd.Encoder
}

// NewCompressor creates a new Compressor for the specified algorithm.
func NewCompressor(algorithm string) (*Compressor, error) {
	c := &Compressor{algorithm: algorithm}

	// Pre-create zstd encoder since it's expensive to create.
	if algorithm == CompressionZstd {
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if err != nil {
			return nil, fmt.Errorf("creating zstd encoder: %w", err)
		}

		c.encoder = encoder
	}

	return c, nil
}

// Compress compresses the data using the configured algorithm.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	switch c.algorithm {
	case CompressionNone, "":
		return data, nil
	case CompressionGzip:
		return compressGzip(data)
	case CompressionZstd:
		return c.compressZstd(data)
	case CompressionZlib:
		return compressZlib(data)
	case CompressionSnappy:
		return compressSnappy(data)
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", c.algorithm)
	}
}

// ContentEncoding returns the Content-Encoding header value for the algorithm.
func (c *Compressor) ContentEncoding() string {
	switch c.algorithm {
	case CompressionGzip:
		return "gzip"
	case CompressionZstd:
		return "zstd"
	case CompressionZlib:
		return "deflate"
	case CompressionSnappy:
		return "snappy"
	default:
		return ""
	}
}

// Close closes the compressor and releases resources.
func (c *Compressor) Close() error {
	if c.encoder != nil {
		return c.encoder.Close()
	}

	return nil
}

func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w := gzip.NewWriter(&buf)

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return buf.Bytes(), nil
}

func (c *Compressor) compressZstd(data []byte) ([]byte, error) {
	return c.encoder.EncodeAll(data, make([]byte, 0, len(data))), nil
}

func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w := zlib.NewWriter(&buf)

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("zlib write: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zlib close: %w", err)
	}

	return buf.Bytes(), nil
}

func compressSnappy(data []byte) ([]byte, error) {
	return snappy.Encode(nil, data), nil
}

// DecompressGzip decompresses gzip data (for testing).
func DecompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// DecompressZstd decompresses zstd data (for testing).
func DecompressZstd(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	return io.ReadAll(decoder)
}

// DecompressZlib decompresses zlib data (for testing).
func DecompressZlib(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// DecompressSnappy decompresses snappy data (for testing).
func DecompressSnappy(data []byte) ([]byte, error) {
	return snappy.Decode(nil, data)
}

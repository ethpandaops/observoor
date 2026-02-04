package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEvent struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func TestExporter_ExportItems(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var receivedBody []byte
	var receivedContentType string
	var receivedContentEncoding string
	var receivedCustomHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedContentEncoding = r.Header.Get("Content-Encoding")
		receivedCustomHeader = r.Header.Get("X-Custom-Header")

		body, _ := io.ReadAll(r.Body)
		receivedBody = body

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:     true,
		Address:     server.URL,
		Compression: CompressionGzip,
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	}

	exporter, err := NewExporter[testEvent](log, cfg)
	require.NoError(t, err)
	defer exporter.Shutdown(context.Background())

	// Export items.
	items := []*testEvent{
		{Name: "event1", Value: 1},
		{Name: "event2", Value: 2},
	}

	err = exporter.ExportItems(context.Background(), items)
	require.NoError(t, err)

	// Verify request.
	assert.Equal(t, "application/x-ndjson", receivedContentType)
	assert.Equal(t, "gzip", receivedContentEncoding)
	assert.Equal(t, "test-value", receivedCustomHeader)

	// Decompress and verify NDJSON.
	decompressed, err := DecompressGzip(receivedBody)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(decompressed)), "\n")
	assert.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"name":"event1"`)
	assert.Contains(t, lines[1], `"name":"event2"`)
}

func TestExporter_NoCompression(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var receivedBody []byte
	var receivedContentEncoding string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentEncoding = r.Header.Get("Content-Encoding")

		body, _ := io.ReadAll(r.Body)
		receivedBody = body

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:     true,
		Address:     server.URL,
		Compression: CompressionNone,
	}

	exporter, err := NewExporter[testEvent](log, cfg)
	require.NoError(t, err)
	defer exporter.Shutdown(context.Background())

	items := []*testEvent{
		{Name: "event1", Value: 1},
	}

	err = exporter.ExportItems(context.Background(), items)
	require.NoError(t, err)

	// No Content-Encoding header for uncompressed data.
	assert.Empty(t, receivedContentEncoding)

	// Body should be plain NDJSON.
	assert.Contains(t, string(receivedBody), `"name":"event1"`)
}

func TestExporter_ServerError(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:     true,
		Address:     server.URL,
		Compression: CompressionNone,
	}

	exporter, err := NewExporter[testEvent](log, cfg)
	require.NoError(t, err)
	defer exporter.Shutdown(context.Background())

	items := []*testEvent{
		{Name: "event1", Value: 1},
	}

	err = exporter.ExportItems(context.Background(), items)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code: 500")
}

func TestExporter_EmptyBatch(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:     true,
		Address:     server.URL,
		Compression: CompressionNone,
	}

	exporter, err := NewExporter[testEvent](log, cfg)
	require.NoError(t, err)
	defer exporter.Shutdown(context.Background())

	// Export empty batch.
	err = exporter.ExportItems(context.Background(), []*testEvent{})
	require.NoError(t, err)

	// Server should not be called for empty batch.
	assert.False(t, serverCalled)
}

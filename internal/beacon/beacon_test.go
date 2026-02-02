package beacon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

func testLog() logrus.FieldLogger {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	return log
}

func TestFetchGenesis(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"data": map[string]string{
				"genesis_time":            "1695902400",
				"genesis_validators_root": "0xabc123",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := newTestServer(t, mux)
	client := NewClient(testLog(), Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	}, nil)

	genesis, err := client.FetchGenesis(context.Background())
	require.NoError(t, err)
	assert.Equal(t,
		time.Unix(1695902400, 0),
		genesis.GenesisTime,
	)
	assert.Equal(t, "0xabc123", genesis.GenesisValidatorsRoot)
}

func TestFetchSpec(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/config/spec", func(w http.ResponseWriter, _ *http.Request) {
		// Real beacon nodes include non-string values like BLOB_SCHEDULE.
		resp := map[string]any{
			"data": map[string]any{
				"SECONDS_PER_SLOT": "12",
				"SLOTS_PER_EPOCH":  "32",
				"BLOB_SCHEDULE": []map[string]string{
					{"EPOCH": "412672", "MAX_BLOBS_PER_BLOCK": "15"},
					{"EPOCH": "419072", "MAX_BLOBS_PER_BLOCK": "21"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := newTestServer(t, mux)
	client := NewClient(testLog(), Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	}, nil)

	spec, err := client.FetchSpec(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(12), spec.SecondsPerSlot)
	assert.Equal(t, uint64(32), spec.SlotsPerEpoch)
}

func TestFetchSyncStatus(t *testing.T) {
	tests := []struct {
		name           string
		isSyncing      bool
		headSlot       string
		syncDist       string
		isOptimistic   bool
		elOffline      bool
		wantSyncing    bool
		wantHead       uint64
		wantDist       uint64
		wantOptimistic bool
		wantELOffline  bool
	}{
		{
			name:           "synced",
			isSyncing:      false,
			headSlot:       "100000",
			syncDist:       "0",
			isOptimistic:   false,
			elOffline:      false,
			wantSyncing:    false,
			wantHead:       100000,
			wantDist:       0,
			wantOptimistic: false,
			wantELOffline:  false,
		},
		{
			name:           "syncing",
			isSyncing:      true,
			headSlot:       "50000",
			syncDist:       "50000",
			isOptimistic:   false,
			elOffline:      false,
			wantSyncing:    true,
			wantHead:       50000,
			wantDist:       50000,
			wantOptimistic: false,
			wantELOffline:  false,
		},
		{
			name:           "optimistic sync",
			isSyncing:      true,
			headSlot:       "75000",
			syncDist:       "25000",
			isOptimistic:   true,
			elOffline:      false,
			wantSyncing:    true,
			wantHead:       75000,
			wantDist:       25000,
			wantOptimistic: true,
			wantELOffline:  false,
		},
		{
			name:           "el offline",
			isSyncing:      false,
			headSlot:       "100000",
			syncDist:       "0",
			isOptimistic:   false,
			elOffline:      true,
			wantSyncing:    false,
			wantHead:       100000,
			wantDist:       0,
			wantOptimistic: false,
			wantELOffline:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/eth/v1/node/syncing", func(w http.ResponseWriter, _ *http.Request) {
				resp := map[string]any{
					"data": map[string]any{
						"is_syncing":    tt.isSyncing,
						"head_slot":     tt.headSlot,
						"sync_distance": tt.syncDist,
						"is_optimistic": tt.isOptimistic,
						"el_offline":    tt.elOffline,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			})

			server := newTestServer(t, mux)
			client := NewClient(testLog(), Config{
				Endpoint: server.URL,
				Timeout:  5 * time.Second,
			}, nil)

			status, err := client.FetchSyncStatus(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.wantSyncing, status.IsSyncing)
			assert.Equal(t, tt.wantHead, status.HeadSlot)
			assert.Equal(t, tt.wantDist, status.SyncDistance)
			assert.Equal(t, tt.wantOptimistic, status.IsOptimistic)
			assert.Equal(t, tt.wantELOffline, status.ELOffline)
		})
	}
}

func TestFetchGenesis_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	server := newTestServer(t, mux)
	client := NewClient(testLog(), Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	}, nil)

	_, err := client.FetchGenesis(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 500")
}

func TestFetchGenesis_InvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	})

	server := newTestServer(t, mux)
	client := NewClient(testLog(), Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	}, nil)

	_, err := client.FetchGenesis(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding response")
}

func TestFetchGenesis_Timeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	})

	server := newTestServer(t, mux)
	client := NewClient(testLog(), Config{
		Endpoint: server.URL,
		Timeout:  100 * time.Millisecond,
	}, nil)

	_, err := client.FetchGenesis(context.Background())
	require.Error(t, err)
}

func TestDefaultTimeout(t *testing.T) {
	client := NewClient(testLog(), Config{
		Endpoint: "http://localhost:9999",
	}, nil)
	// Just verify it doesn't panic — timeout defaults to 10s.
	assert.NotNil(t, client)
}

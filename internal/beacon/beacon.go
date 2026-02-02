package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// GenesisResponse contains the genesis information from the beacon node.
type GenesisResponse struct {
	GenesisTime           time.Time
	GenesisValidatorsRoot string
}

// SpecResponse contains relevant chain spec parameters.
type SpecResponse struct {
	SecondsPerSlot uint64
	SlotsPerEpoch  uint64
}

// SyncStatus indicates the sync state of the beacon node.
type SyncStatus struct {
	IsSyncing    bool
	HeadSlot     uint64
	SyncDistance uint64
	IsOptimistic bool
	ELOffline    bool
}

// Client defines the interface for interacting with a CL beacon node.
type Client interface {
	// FetchGenesis retrieves the genesis time and validators root.
	FetchGenesis(ctx context.Context) (*GenesisResponse, error)
	// FetchSpec retrieves chain spec parameters.
	FetchSpec(ctx context.Context) (*SpecResponse, error)
	// FetchSyncStatus retrieves the node's sync status.
	FetchSyncStatus(ctx context.Context) (*SyncStatus, error)
}

type client struct {
	log      logrus.FieldLogger
	endpoint string
	http     *http.Client
	health   *export.HealthMetrics
}

// NewClient creates a new beacon node API client.
func NewClient(
	log logrus.FieldLogger,
	cfg Config,
	health *export.HealthMetrics,
) Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &client{
		log:      log.WithField("component", "beacon"),
		endpoint: cfg.Endpoint,
		http: &http.Client{
			Timeout: timeout,
		},
		health: health,
	}
}

func (c *client) FetchGenesis(
	ctx context.Context,
) (*GenesisResponse, error) {
	var resp struct {
		Data struct {
			GenesisTime           string `json:"genesis_time"`
			GenesisValidatorsRoot string `json:"genesis_validators_root"`
		} `json:"data"`
	}

	if err := c.getJSON(ctx, "/eth/v1/beacon/genesis", &resp); err != nil {
		return nil, fmt.Errorf("fetching genesis: %w", err)
	}

	genesisUnix, err := strconv.ParseInt(resp.Data.GenesisTime, 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing genesis time %q: %w",
			resp.Data.GenesisTime,
			err,
		)
	}

	return &GenesisResponse{
		GenesisTime:           time.Unix(genesisUnix, 0),
		GenesisValidatorsRoot: resp.Data.GenesisValidatorsRoot,
	}, nil
}

func (c *client) FetchSpec(
	ctx context.Context,
) (*SpecResponse, error) {
	// The spec response contains mostly string values but some keys
	// (e.g. BLOB_SCHEDULE) are arrays/objects, so we use json.RawMessage
	// and extract only the string fields we need.
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}

	if err := c.getJSON(ctx, "/eth/v1/config/spec", &resp); err != nil {
		return nil, fmt.Errorf("fetching spec: %w", err)
	}

	secondsPerSlot, err := specUint64(resp.Data, "SECONDS_PER_SLOT")
	if err != nil {
		return nil, err
	}

	slotsPerEpoch, err := specUint64(resp.Data, "SLOTS_PER_EPOCH")
	if err != nil {
		return nil, err
	}

	return &SpecResponse{
		SecondsPerSlot: secondsPerSlot,
		SlotsPerEpoch:  slotsPerEpoch,
	}, nil
}

// specUint64 extracts a uint64 from a spec data map where values are
// JSON-encoded strings (e.g. `"12"`).
func specUint64(
	data map[string]json.RawMessage,
	key string,
) (uint64, error) {
	raw, ok := data[key]
	if !ok {
		return 0, fmt.Errorf("spec missing required key %q", key)
	}

	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf(
			"spec key %q is not a string: %w", key, err,
		)
	}

	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s value %q: %w", key, s, err)
	}

	return v, nil
}

func (c *client) FetchSyncStatus(
	ctx context.Context,
) (*SyncStatus, error) {
	var resp struct {
		Data struct {
			IsSyncing    bool   `json:"is_syncing"`
			HeadSlot     string `json:"head_slot"`
			SyncDistance string `json:"sync_distance"`
			IsOptimistic bool   `json:"is_optimistic"`
			ELOffline    bool   `json:"el_offline"`
		} `json:"data"`
	}

	if err := c.getJSON(ctx, "/eth/v1/node/syncing", &resp); err != nil {
		return nil, fmt.Errorf("fetching sync status: %w", err)
	}

	headSlot, err := strconv.ParseUint(resp.Data.HeadSlot, 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing head_slot %q: %w",
			resp.Data.HeadSlot,
			err,
		)
	}

	syncDistance, err := strconv.ParseUint(resp.Data.SyncDistance, 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing sync_distance %q: %w",
			resp.Data.SyncDistance,
			err,
		)
	}

	return &SyncStatus{
		IsSyncing:    resp.Data.IsSyncing,
		HeadSlot:     headSlot,
		SyncDistance: syncDistance,
		IsOptimistic: resp.Data.IsOptimistic,
		ELOffline:    resp.Data.ELOffline,
	}, nil
}

func (c *client) getJSON(
	ctx context.Context,
	path string,
	target any,
) error {
	start := time.Now()
	endpoint := endpointFromPath(path)

	url := c.endpoint + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.recordRequest(endpoint, "error", time.Since(start))

		return fmt.Errorf("creating request for %s: %w", path, err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.recordRequest(endpoint, "error", time.Since(start))

		return fmt.Errorf("executing request for %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.recordRequest(endpoint, "error", time.Since(start))

		return fmt.Errorf(
			"unexpected status %d from %s: %s",
			resp.StatusCode,
			path,
			string(body),
		)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		c.recordRequest(endpoint, "error", time.Since(start))

		return fmt.Errorf("decoding response from %s: %w", path, err)
	}

	c.recordRequest(endpoint, "success", time.Since(start))

	return nil
}

// recordRequest records beacon request metrics.
func (c *client) recordRequest(endpoint, status string, duration time.Duration) {
	if c.health == nil {
		return
	}

	c.health.BeaconRequestsTotal.WithLabelValues(endpoint, status).Inc()
	c.health.BeaconRequestDuration.WithLabelValues(endpoint).Observe(duration.Seconds())
}

// endpointFromPath extracts a short endpoint name from the API path.
func endpointFromPath(path string) string {
	switch path {
	case "/eth/v1/beacon/genesis":
		return "genesis"
	case "/eth/v1/config/spec":
		return "spec"
	case "/eth/v1/node/syncing":
		return "syncing"
	default:
		return "other"
	}
}

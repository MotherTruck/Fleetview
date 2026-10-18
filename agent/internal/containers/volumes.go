package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Volume is one Docker volume as reported by the dashboard's "Volumes"
// panel -- a sibling view to the container list, for the same
// "see what's taking up space, clean up what's unused" workflow
// Portainer's volume browser covers.
type Volume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
	CreatedAt  string `json:"created_at"`
	// InUse is true when the volume is attached to at least one container
	// (running or stopped) -- derived from Docker's own "dangling" filter
	// rather than cross-referencing container mounts ourselves, so it
	// matches exactly what `docker volume prune` would remove.
	InUse bool `json:"in_use"`
}

type dockerVolume struct {
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Mountpoint string `json:"Mountpoint"`
	CreatedAt  string `json:"CreatedAt"`
}

type dockerVolumeListResponse struct {
	Volumes []dockerVolume `json:"Volumes"`
}

// CollectVolumes lists every Docker volume on this host, each flagged
// with whether it's currently attached to a container. Called
// unconditionally alongside Collect (container inventory) -- "available"
// mirrors Collect's own meaning (false when Docker itself isn't reachable,
// not when there simply are no volumes).
func CollectVolumes(ctx context.Context) (bool, []Volume, error) {
	return collectVolumesWithClient(ctx, dockerClient())
}

func collectVolumesWithClient(ctx context.Context, client *http.Client) (bool, []Volume, error) {
	all, err := fetchVolumeList(ctx, client, "")
	if err != nil {
		return false, []Volume{}, nil
	}
	danglingFilter := url.QueryEscape(`{"dangling":["true"]}`)
	dangling, err := fetchVolumeList(ctx, client, "?filters="+danglingFilter)
	if err != nil {
		// Falling back to "every volume counted in-use" (rather than
		// failing the whole collection) is the safe direction to err in:
		// it only suppresses the prune-candidate badge, never offers to
		// delete something we failed to confirm is actually unused.
		dangling = nil
	}
	danglingNames := make(map[string]bool, len(dangling))
	for _, volume := range dangling {
		danglingNames[volume.Name] = true
	}
	result := make([]Volume, 0, len(all))
	for _, volume := range all {
		result = append(result, Volume{
			Name:       volume.Name,
			Driver:     volume.Driver,
			Mountpoint: volume.Mountpoint,
			CreatedAt:  volume.CreatedAt,
			InUse:      !danglingNames[volume.Name],
		})
	}
	return true, result, nil
}

func fetchVolumeList(ctx context.Context, client *http.Client, query string) ([]dockerVolume, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/volumes"+query, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Docker returned %s", response.Status)
	}
	var decoded dockerVolumeListResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode Docker volumes: %w", err)
	}
	return decoded.Volumes, nil
}

// volumeNamePattern mirrors Docker's own volume name constraints
// (alphanumeric plus . _ -), which already rules out anything that could
// be a path traversal or URL-manipulation attempt once interpolated into
// a request path below.
var volumeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

// RemoveVolume deletes one named volume. Docker itself refuses with 409 if
// the volume is still attached to any container (even a stopped one), so
// this never needs its own "is it actually unused" check -- the engine is
// the source of truth.
func RemoveVolume(ctx context.Context, name string) error {
	client := dockerClient()
	client.Timeout = 15 * time.Second
	return removeVolumeWithClient(ctx, client, name)
}

func removeVolumeWithClient(ctx context.Context, client *http.Client, name string) error {
	if !volumeNamePattern.MatchString(name) {
		return fmt.Errorf("invalid Docker volume name")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/volumes/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Docker volume remove: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("Docker volume remove: %s", dockerErrorMessage(response))
}

type dockerPruneVolumesResponse struct {
	VolumesDeleted []string `json:"VolumesDeleted"`
	SpaceReclaimed uint64   `json:"SpaceReclaimed"`
}

// PruneVolumes removes every volume not attached to any container, the
// same operation `docker volume prune` (and Portainer's "Remove unused
// volumes" button) performs -- one request rather than looping
// RemoveVolume per name, so it's atomic from the caller's point of view
// and matches exactly what Docker itself considers prunable at the
// moment the request runs.
func PruneVolumes(ctx context.Context) (deleted []string, spaceReclaimed uint64, err error) {
	client := dockerClient()
	client.Timeout = 2 * time.Minute
	return pruneVolumesWithClient(ctx, client)
}

func pruneVolumesWithClient(ctx context.Context, client *http.Client) (deleted []string, spaceReclaimed uint64, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/volumes/prune", nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("Docker volume prune: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("Docker volume prune: %s", dockerErrorMessage(response))
	}
	var decoded dockerPruneVolumesResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, 0, fmt.Errorf("decode Docker volume prune response: %w", err)
	}
	return decoded.VolumesDeleted, decoded.SpaceReclaimed, nil
}

func dockerErrorMessage(response *http.Response) string {
	var message struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&message)
	if message.Message != "" {
		return message.Message
	}
	return response.Status
}

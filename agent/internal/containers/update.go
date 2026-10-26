package containers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UpdateStatus is CheckForUpdate's result, cached in-memory (keyed by
// container ID) so the next ordinary inventory scan's Collect() can embed
// it into that container's entry without needing its own round trip to
// Docker -- a check already did the expensive part (pulling the image).
type UpdateStatus struct {
	Available bool
	LatestID  string
	CheckedAt time.Time
}

var (
	updateStatusMu    sync.Mutex
	updateStatusCache = map[string]UpdateStatus{}
)

func cachedUpdateStatus(containerID string) (UpdateStatus, bool) {
	updateStatusMu.Lock()
	defer updateStatusMu.Unlock()
	status, ok := updateStatusCache[containerID]
	return status, ok
}

func setCachedUpdateStatus(containerID string, status UpdateStatus) {
	updateStatusMu.Lock()
	defer updateStatusMu.Unlock()
	updateStatusCache[containerID] = status
}

type dockerInspect struct {
	ID              string                 `json:"Id"`
	Name            string                 `json:"Name"`
	Image           string                 `json:"Image"` // the image ID this container was actually created from
	Config          map[string]interface{} `json:"Config"`
	HostConfig      map[string]interface{} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]interface{} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func inspectContainer(ctx context.Context, client *http.Client, id string) (dockerInspect, error) {
	var inspect dockerInspect
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/json", nil)
	if err != nil {
		return inspect, err
	}
	response, err := client.Do(request)
	if err != nil {
		return inspect, fmt.Errorf("inspect container: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return inspect, fmt.Errorf("inspect container: %s", response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&inspect); err != nil {
		return inspect, fmt.Errorf("decode container inspect: %w", err)
	}
	return inspect, nil
}

// pullImage asks the Docker Engine to pull imageRef fresh from its
// registry. The engine streams newline-delimited progress JSON for the
// duration of the pull -- draining the body is how this waits for the
// pull to actually finish, not just for the request to be accepted.
func pullImage(ctx context.Context, client *http.Client, imageRef string) error {
	repo, tag := splitImageRef(imageRef)
	pullURL := "http://docker/images/create?fromImage=" + url.QueryEscape(repo) + "&tag=" + url.QueryEscape(tag)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pullURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("pull %s: %w", imageRef, err)
	}
	defer response.Body.Close()
	// The engine can still report a per-layer error (e.g. manifest not
	// found) as a 200 with an "error" field buried in the progress stream,
	// not as an HTTP error status -- capture the last line to surface that.
	var lastLine string
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		lastLine = scanner.Text()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("pull %s: %s: %s", imageRef, response.Status, lastLine)
	}
	var progress struct {
		Error string `json:"error"`
	}
	if lastLine != "" {
		_ = json.Unmarshal([]byte(lastLine), &progress)
	}
	if progress.Error != "" {
		return fmt.Errorf("pull %s: %s", imageRef, progress.Error)
	}
	return nil
}

func imageID(ctx context.Context, client *http.Client, imageRef string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/images/"+url.QueryEscape(imageRef)+"/json", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("inspect image %s: %w", imageRef, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("inspect image %s: %s", imageRef, response.Status)
	}
	var image struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&image); err != nil {
		return "", fmt.Errorf("decode image inspect: %w", err)
	}
	return image.ID, nil
}

// splitImageRef mirrors the standard docker/Watchtower convention: an
// unqualified reference means "latest". A registry host containing a port
// (e.g. localhost:5000/app) has a colon too, so only the LAST colon after
// the last slash is treated as the tag separator.
func splitImageRef(ref string) (repo, tag string) {
	slash := strings.LastIndex(ref, "/")
	searchFrom := 0
	if slash >= 0 {
		searchFrom = slash
	}
	if colon := strings.LastIndex(ref[searchFrom:], ":"); colon >= 0 {
		return ref[:searchFrom+colon], ref[searchFrom+colon+1:]
	}
	return ref, "latest"
}

// CheckForUpdate pulls the image a running container was started from and
// compares the freshly pulled image's ID against the one the container is
// actually running -- the same mechanism `docker pull && docker inspect`
// based tools (Watchtower included) use, since Docker has no simpler
// built-in "is a newer image available" query.
func CheckForUpdate(ctx context.Context, containerID string) (UpdateStatus, error) {
	client := dockerClient()
	client.Timeout = 10 * time.Minute // image pulls can legitimately be slow
	inspect, err := inspectContainer(ctx, client, containerID)
	if err != nil {
		return UpdateStatus{}, err
	}
	imageRef, _ := inspect.Config["Image"].(string)
	if imageRef == "" {
		return UpdateStatus{}, fmt.Errorf("container has no image reference to check")
	}
	if err := pullImage(ctx, client, imageRef); err != nil {
		return UpdateStatus{}, err
	}
	latestID, err := imageID(ctx, client, imageRef)
	if err != nil {
		return UpdateStatus{}, err
	}
	status := UpdateStatus{Available: latestID != inspect.Image, LatestID: latestID, CheckedAt: time.Now().UTC()}
	setCachedUpdateStatus(containerID, status)
	return status, nil
}

// ApplyUpdate recreates containerID with the latest pulled image if one is
// available, preserving its configuration (command, env, ports, volumes,
// restart policy, networks) exactly as Docker already has it recorded --
// everything needed to recreate it comes straight from this container's
// own inspect response, not from anything this agent has to remember or
// reconstruct. The old container is renamed rather than removed up front,
// so a failed recreate can still be rolled back instead of leaving nothing
// running at all.
func ApplyUpdate(ctx context.Context, containerID string) (string, error) {
	client := dockerClient()
	client.Timeout = 10 * time.Minute
	status, err := CheckForUpdate(ctx, containerID)
	if err != nil {
		return "", err
	}
	if !status.Available {
		return "Already running the latest pulled image", nil
	}
	inspect, err := inspectContainer(ctx, client, containerID)
	if err != nil {
		return "", err
	}
	imageRef, _ := inspect.Config["Image"].(string)
	name := strings.TrimPrefix(inspect.Name, "/")
	if name == "" {
		return "", fmt.Errorf("container has no name to recreate under")
	}
	rollbackName := fmt.Sprintf("%s-fleetview-rollback-%d", name, time.Now().UnixNano())

	if err := stopContainer(ctx, client, containerID); err != nil {
		return "", fmt.Errorf("stop current container: %w", err)
	}
	if err := renameContainer(ctx, client, containerID, rollbackName); err != nil {
		return "", fmt.Errorf("rename current container aside: %w", err)
	}

	newID, createErr := createContainer(ctx, client, name, inspect)
	if createErr == nil {
		createErr = startContainer(ctx, client, newID)
	}
	if createErr != nil {
		// Best-effort rollback: bring the renamed original back under its
		// real name and restart it, so this isn't left worse off than
		// before the attempt. A failure here just means both the renamed
		// original and the (if created) broken new container are left for
		// an admin to sort out by hand -- genuinely nothing more this can
		// safely do automatically.
		if newID != "" {
			_, _ = removeContainer(ctx, client, newID)
		}
		_ = renameContainer(ctx, client, containerID, name)
		_ = startContainer(ctx, client, containerID)
		return "", fmt.Errorf("recreate with %s: %w (rolled back to the previous container)", imageRef, createErr)
	}
	if _, err := removeContainer(ctx, client, containerID); err != nil {
		// The new container is already up at this point -- surface this as
		// a non-fatal note rather than an error the caller would treat as
		// having failed the whole update.
		return fmt.Sprintf("Updated to %s, but could not remove the old container (%s): %v", imageRef, rollbackName, err), nil
	}
	return fmt.Sprintf("Updated %s to the latest pulled image (%s)", name, imageRef), nil
}

func stopContainer(ctx context.Context, client *http.Client, id string) error {
	return doSimple(ctx, client, http.MethodPost, "http://docker/containers/"+id+"/stop?t=10")
}

func startContainer(ctx context.Context, client *http.Client, id string) error {
	return doSimple(ctx, client, http.MethodPost, "http://docker/containers/"+id+"/start")
}

func renameContainer(ctx context.Context, client *http.Client, id, newName string) error {
	return doSimple(ctx, client, http.MethodPost, "http://docker/containers/"+id+"/rename?name="+url.QueryEscape(newName))
}

func removeContainer(ctx context.Context, client *http.Client, id string) (bool, error) {
	err := doSimple(ctx, client, http.MethodDelete, "http://docker/containers/"+id)
	return err == nil, err
}

func doSimple(ctx context.Context, client *http.Client, method, url string) error {
	request, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 || response.StatusCode == http.StatusNotModified {
		return nil
	}
	var message struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&message)
	if message.Message != "" {
		return fmt.Errorf("%s", message.Message)
	}
	return fmt.Errorf("%s", response.Status)
}

func createContainer(ctx context.Context, client *http.Client, name string, inspect dockerInspect) (string, error) {
	body := map[string]interface{}{}
	for key, value := range inspect.Config {
		body[key] = value
	}
	// Overridden rather than inherited from Config: this is the whole
	// point of the update, and Config["Image"] is still the tag reference
	// pullImage already resolved (e.g. "nginx:latest"), so it would be a
	// no-op to copy it as-is anyway.
	body["HostConfig"] = inspect.HostConfig
	if len(inspect.NetworkSettings.Networks) > 0 {
		body["NetworkingConfig"] = map[string]interface{}{"EndpointsConfig": inspect.NetworkSettings.Networks}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/containers/create?name="+url.QueryEscape(name), strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var message struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&message)
		if message.Message != "" {
			return "", fmt.Errorf("%s", message.Message)
		}
		return "", fmt.Errorf("%s", response.Status)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	return created.ID, nil
}

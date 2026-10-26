//go:build linux

package containers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSplitImageRef(t *testing.T) {
	cases := []struct{ ref, wantRepo, wantTag string }{
		{"nginx", "nginx", "latest"},
		{"nginx:1.27", "nginx", "1.27"},
		{"library/nginx:latest", "library/nginx", "latest"},
		{"ghcr.io/mothertruck/fleetview-server:latest", "ghcr.io/mothertruck/fleetview-server", "latest"},
		// A registry host with its own port has a colon before the slash --
		// only the colon AFTER the last slash is the tag separator.
		{"localhost:5000/app", "localhost:5000/app", "latest"},
		{"localhost:5000/app:v2", "localhost:5000/app", "v2"},
	}
	for _, tc := range cases {
		repo, tag := splitImageRef(tc.ref)
		if repo != tc.wantRepo || tag != tc.wantTag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", tc.ref, repo, tag, tc.wantRepo, tc.wantTag)
		}
	}
}

func TestWithUpdateStatusMergesCachedResult(t *testing.T) {
	container := Container{ID: "abc123", Name: "web"}
	if got := withUpdateStatus(container); got.UpdateAvailable != nil || got.UpdateCheckedAt != "" {
		t.Fatalf("expected no status for an uncached container, got %+v", got)
	}

	setCachedUpdateStatus("abc123", UpdateStatus{Available: true, LatestID: "sha256:new", CheckedAt: mustParseRFC3339(t, "2026-01-02T03:04:05Z")})
	got := withUpdateStatus(container)
	if got.UpdateAvailable == nil || !*got.UpdateAvailable {
		t.Fatalf("expected UpdateAvailable=true, got %+v", got.UpdateAvailable)
	}
	if got.UpdateCheckedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("expected the cached timestamp to be formatted as RFC3339, got %q", got.UpdateCheckedAt)
	}

	setCachedUpdateStatus("abc123", UpdateStatus{Available: false, CheckedAt: mustParseRFC3339(t, "2026-01-02T03:05:00Z")})
	got = withUpdateStatus(container)
	if got.UpdateAvailable == nil || *got.UpdateAvailable {
		t.Fatalf("expected a later check to overwrite the cached result, got %+v", got.UpdateAvailable)
	}
}

func mustParseRFC3339(t *testing.T, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return ts
}

func TestCreateContainerMergesConfigAndOverridesImage(t *testing.T) {
	var capturedBody map[string]interface{}
	var capturedPath string
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		capturedPath = req.URL.Path + "?" + req.URL.RawQuery
		body, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(body, &capturedBody)
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"Id":"newid123"}`)), Header: http.Header{}}, nil
	})}
	inspect := dockerInspect{
		Name:  "/web",
		Image: "sha256:old",
		Config: map[string]interface{}{
			"Image": "nginx:latest",
			"Env":   []interface{}{"FOO=bar"},
		},
		HostConfig: map[string]interface{}{"RestartPolicy": map[string]interface{}{"Name": "always"}},
	}
	inspect.NetworkSettings.Networks = map[string]interface{}{"bridge": map[string]interface{}{"IPAddress": "172.17.0.2"}}

	id, err := createContainer(context.Background(), client, "web", inspect)
	if err != nil {
		t.Fatalf("createContainer: %v", err)
	}
	if id != "newid123" {
		t.Fatalf("expected the created container's ID to come from the response, got %q", id)
	}
	if capturedPath != "/containers/create?name=web" {
		t.Fatalf("unexpected create path %q", capturedPath)
	}
	if capturedBody["Image"] != "nginx:latest" {
		t.Fatalf("expected Config.Image to carry through as the create payload's Image, got %v", capturedBody["Image"])
	}
	if capturedBody["Env"] == nil {
		t.Fatal("expected other Config fields (Env) to be preserved")
	}
	hostConfig, _ := capturedBody["HostConfig"].(map[string]interface{})
	if hostConfig["RestartPolicy"] == nil {
		t.Fatal("expected HostConfig to be carried through from inspect")
	}
	networking, _ := capturedBody["NetworkingConfig"].(map[string]interface{})
	if networking == nil || networking["EndpointsConfig"] == nil {
		t.Fatal("expected NetworkingConfig.EndpointsConfig to be built from inspect's NetworkSettings.Networks")
	}
}

func TestPullImageSurfacesStreamedError(t *testing.T) {
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/images/create" || req.URL.Query().Get("fromImage") != "nginx" || req.URL.Query().Get("tag") != "latest" {
			t.Errorf("unexpected pull request %s", req.URL.String())
		}
		body := `{"status":"Pulling"}` + "\n" + `{"error":"manifest unknown"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	err := pullImage(context.Background(), client, "nginx")
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("expected the streamed error to surface, got %v", err)
	}
}

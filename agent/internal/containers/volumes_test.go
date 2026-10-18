package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type volumeTransportFunc func(*http.Request) (*http.Response, error)

func (fn volumeTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func jsonResponse(t *testing.T, status int, body any) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewReader(data)),
		Header:     http.Header{},
	}
}

func TestCollectVolumesFlagsDanglingVolumesAsUnused(t *testing.T) {
	all := dockerVolumeListResponse{Volumes: []dockerVolume{
		{Name: "used-volume", Driver: "local", Mountpoint: "/var/lib/docker/volumes/used-volume/_data", CreatedAt: "2026-01-01T00:00:00Z"},
		{Name: "unused-volume", Driver: "local", Mountpoint: "/var/lib/docker/volumes/unused-volume/_data", CreatedAt: "2026-01-02T00:00:00Z"},
	}}
	dangling := dockerVolumeListResponse{Volumes: []dockerVolume{all.Volumes[1]}}
	client := &http.Client{Transport: volumeTransportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("filters") != "" {
			return jsonResponse(t, 200, dangling), nil
		}
		return jsonResponse(t, 200, all), nil
	})}
	available, volumes, err := collectVolumesWithClient(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	if len(volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(volumes))
	}
	byName := map[string]Volume{}
	for _, v := range volumes {
		byName[v.Name] = v
	}
	if !byName["used-volume"].InUse {
		t.Error("used-volume should be InUse=true")
	}
	if byName["unused-volume"].InUse {
		t.Error("unused-volume should be InUse=false")
	}
}

func TestCollectVolumesUnavailableWhenDockerUnreachable(t *testing.T) {
	client := &http.Client{Transport: volumeTransportFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}
	available, volumes, err := collectVolumesWithClient(context.Background(), client)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if available {
		t.Error("expected available=false")
	}
	if len(volumes) != 0 {
		t.Errorf("expected no volumes, got %d", len(volumes))
	}
}

func TestRemoveVolumeRejectsUntrustedNames(t *testing.T) {
	for _, name := range []string{"../etc/passwd", "name with spaces", "", strings.Repeat("a", 300)} {
		if err := removeVolumeWithClient(context.Background(), http.DefaultClient, name); err == nil {
			t.Errorf("accepted invalid volume name %q", name)
		}
	}
}

func TestRemoveVolumeUsesConstrainedDockerRequest(t *testing.T) {
	client := &http.Client{Transport: volumeTransportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != "DELETE" || req.URL.Host != "docker" || req.URL.Path != "/volumes/my-volume" {
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody, Header: http.Header{}}, nil
	})}
	if err := removeVolumeWithClient(context.Background(), client, "my-volume"); err != nil {
		t.Fatal(err)
	}
	client.Transport = volumeTransportFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 409, Status: "409 Conflict", Body: http.NoBody, Header: http.Header{}}, nil
	})
	if err := removeVolumeWithClient(context.Background(), client, "my-volume"); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("expected Docker 409 error, got %v", err)
	}
}

func TestPruneVolumesParsesResponse(t *testing.T) {
	client := &http.Client{Transport: volumeTransportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != "POST" || req.URL.Path != "/volumes/prune" {
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
		}
		return jsonResponse(t, 200, dockerPruneVolumesResponse{VolumesDeleted: []string{"a", "b"}, SpaceReclaimed: 4096}), nil
	})}
	deleted, reclaimed, err := pruneVolumesWithClient(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 || reclaimed != 4096 {
		t.Fatalf("unexpected result: deleted=%v reclaimed=%d", deleted, reclaimed)
	}
}

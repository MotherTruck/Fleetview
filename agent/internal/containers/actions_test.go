//go:build linux

package containers

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestActionRejectsUntrustedPaths(t *testing.T) {
	for _, tc := range []struct{ action, id string }{
		{"exec", "abcdef012345"}, {"stop", "../docker"}, {"start", "short"},
	} {
		if err := actionWithClient(context.Background(), http.DefaultClient, tc.action, tc.id); err == nil {
			t.Errorf("accepted action=%q id=%q", tc.action, tc.id)
		}
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestActionUsesConstrainedDockerRequest(t *testing.T) {
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != "POST" || req.URL.Host != "docker" || req.URL.Path != "/containers/abcdef012345/restart" || req.URL.Query().Get("t") != "10" {
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody, Header: http.Header{}}, nil
	})}
	if err := actionWithClient(context.Background(), client, "restart", "abcdef012345"); err != nil {
		t.Fatal(err)
	}
	client.Transport = transportFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Status: "404 Not Found", Body: http.NoBody, Header: http.Header{}}, nil
	})
	if err := actionWithClient(context.Background(), client, "stop", "abcdef012345"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected Docker error, got %v", err)
	}
}

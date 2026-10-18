package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"fleetview-agent/internal/model"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func newTestClient(transport http.RoundTripper) *Client {
	return &Client{
		baseURL: "http://test",
		http:    &http.Client{Transport: transport},
		state:   model.State{DeviceID: "device-1", AgentToken: "token-1"},
	}
}

func TestCompleteJobRetriesUntilItSucceeds(t *testing.T) {
	original := completeJobBackoff
	completeJobBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { completeJobBackoff = original }()

	var attempts int
	c := newTestClient(transportFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts < 3 {
			return nil, context.DeadlineExceeded
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody, Header: http.Header{}}, nil
	}))

	err := c.CompleteJob(context.Background(), "job-1", model.JobResult{Status: "succeeded"})
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestCompleteJobGivesUpAfterExhaustingRetries(t *testing.T) {
	original := completeJobBackoff
	completeJobBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { completeJobBackoff = original }()

	var attempts int
	c := newTestClient(transportFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return nil, context.DeadlineExceeded
	}))

	err := c.CompleteJob(context.Background(), "job-1", model.JobResult{Status: "succeeded"})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	// len(completeJobBackoff) retries after the first attempt.
	if attempts != 1+len(completeJobBackoff) {
		t.Errorf("expected %d attempts, got %d", 1+len(completeJobBackoff), attempts)
	}
}

func TestCompleteJobStopsRetryingWhenContextIsCancelled(t *testing.T) {
	original := completeJobBackoff
	completeJobBackoff = []time.Duration{time.Hour}
	defer func() { completeJobBackoff = original }()

	var attempts int
	c := newTestClient(transportFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return nil, context.DeadlineExceeded
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.CompleteJob(ctx, "job-1", model.JobResult{Status: "succeeded"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Errorf("expected to bail after the first attempt once the context was cancelled, got %d attempts", attempts)
	}
}

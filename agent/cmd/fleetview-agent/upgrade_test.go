package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fleetview-agent/internal/client"
	"fleetview-agent/internal/config"
	"fleetview-agent/internal/model"
)

func testClient(t *testing.T, serverURL string) *client.Client {
	t.Helper()
	return client.New(config.Config{ServerURL: serverURL, RequestTimeout: 5 * time.Second}, model.State{})
}

func TestStageUpgradeVerifiesChecksum(t *testing.T) {
	payload := []byte("pretend this is a compiled agent binary")
	digest := sha256.Sum256(payload)
	hash := hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	api := testClient(t, server.URL)

	data, err := stageUpgrade(context.Background(), api, "/install/agent-linux-amd64", hash)
	if err != nil {
		t.Fatalf("unexpected error with a correct checksum: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("staged data does not match the served payload")
	}

	if _, err := stageUpgrade(context.Background(), api, "/install/agent-linux-amd64", "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected a checksum-mismatch error, got nil")
	}
}

func TestStageUpgradeRejectsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	api := testClient(t, server.URL)
	if _, err := stageUpgrade(context.Background(), api, "/install/agent-linux-amd64", "irrelevant"); err == nil {
		t.Fatal("expected an error when the download fails, got nil")
	}
}

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"fleetview-agent/internal/config"
	"fleetview-agent/internal/model"
)

type Client struct {
	baseURL string
	http    *http.Client
	state   model.State
}

// New builds the HTTP client the agent uses for every server request. TLS
// verification is on by default; FLEETVIEW_CA_FILE trusts one additional
// private CA (for a self-signed/internal-CA server, e.g. behind the
// project's optional Caddy TLS profile — see docs/TLS.md) without disabling
// verification entirely, which FLEETVIEW_ALLOW_INSECURE_TLS does and should
// be a last resort.
func New(cfg config.Config, state model.State) (*Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.AllowInsecureTLS} // #nosec G402 -- explicit opt-in for test environments
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read FLEETVIEW_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("FLEETVIEW_CA_FILE does not contain a valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &Client{baseURL: cfg.ServerURL, http: &http.Client{Timeout: cfg.RequestTimeout, Transport: transport}, state: state}, nil
}

func LoadState(path string) (model.State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return model.State{}, nil
	}
	if err != nil {
		return model.State{}, err
	}
	var state model.State
	if err := json.Unmarshal(data, &state); err != nil {
		return model.State{}, err
	}
	return state, nil
}

func SaveState(path string, state model.State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (c *Client) Enroll(ctx context.Context, token, hostname, version string) (model.State, error) {
	payload := map[string]string{"enrollment_token": token, "hostname": hostname, "platform": runtime.GOOS, "agent_version": version}
	var response model.State
	if err := c.request(ctx, http.MethodPost, "/api/v1/agent/enroll", payload, &response, false); err != nil {
		return model.State{}, err
	}
	c.state = response
	return response, nil
}

func (c *Client) Report(ctx context.Context, report model.Report) error {
	return c.request(ctx, http.MethodPost, "/api/v1/agent/report", report, nil, true)
}

func (c *Client) ReportVulnerabilities(ctx context.Context, report model.VulnerabilityReport) error {
	return c.request(ctx, http.MethodPost, "/api/v1/agent/vulnerabilities", report, nil, true)
}

func (c *Client) ReportMetrics(ctx context.Context, report model.MetricsReport) error {
	return c.request(ctx, http.MethodPost, "/api/v1/agent/metrics", report, nil, true)
}

func (c *Client) AgentSettings(ctx context.Context) (model.AgentSettings, error) {
	var result model.AgentSettings
	err := c.request(ctx, http.MethodGet, "/api/v1/agent/settings", nil, &result, true)
	return result, err
}

func (c *Client) Heartbeat(ctx context.Context) error {
	return c.request(ctx, http.MethodPost, "/api/v1/agent/heartbeat", nil, nil, true)
}

// VerifyUninstall checks the managed-uninstall code with the server before
// the caller removes the agent. It errors (rather than skipping the check)
// when the device's credentials aren't loaded, since that's exactly the
// state client.state would be in if this were called without LoadState.
func (c *Client) VerifyUninstall(ctx context.Context, code string) error {
	if c.state.DeviceID == "" || c.state.AgentToken == "" {
		return fmt.Errorf("no enrollment found to verify")
	}
	return c.request(ctx, http.MethodPost, "/api/v1/agent/uninstall/verify", map[string]string{"code": code}, nil, true)
}

func (c *Client) NextJob(ctx context.Context) (*model.Job, error) {
	var result model.Job
	noContent, err := c.requestAllowNoContent(ctx, http.MethodGet, "/api/v1/agent/jobs/next", nil, &result, true)
	if err != nil || noContent {
		return nil, err
	}
	return &result, nil
}

func (c *Client) CompleteJob(ctx context.Context, jobID string, result model.JobResult) error {
	return c.request(ctx, http.MethodPost, "/api/v1/agent/jobs/"+jobID+"/result", result, nil, true)
}

type BundleFile struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
	SHA256   string `json:"sha256"`
}

type Bundle struct {
	Platform string       `json:"platform"`
	Command  string       `json:"command"`
	Files    []BundleFile `json:"files"`
}

func (c *Client) Bundle(ctx context.Context, jobID string) (Bundle, error) {
	var result Bundle
	err := c.request(ctx, http.MethodGet, "/api/v1/agent/jobs/"+jobID+"/bundle", nil, &result, true)
	return result, err
}

func (c *Client) BundleFile(ctx context.Context, jobID, fileID string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/agent/jobs/"+jobID+"/bundle/files/"+fileID, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.state.AgentToken)
	request.Header.Set("X-Device-ID", c.state.DeviceID)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle download returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 8*1024*1024 {
		return nil, fmt.Errorf("bundle file too large")
	}
	return data, nil
}

// DownloadFile fetches a public, unauthenticated file such as a published
// agent binary (the /install/ routes, same trust tier as the install
// scripts they already serve). maxSize bounds the response to guard
// against a misbehaving or compromised server exhausting memory/disk.
func (c *Client) DownloadFile(ctx context.Context, path string, maxSize int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s returned %s", path, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("download %s exceeded the maximum expected size", path)
	}
	return data, nil
}

func (c *Client) request(ctx context.Context, method, path string, payload, result interface{}, authenticated bool) error {
	_, err := c.requestAllowNoContent(ctx, method, path, payload, result, authenticated)
	return err
}

func (c *Client) requestAllowNoContent(ctx context.Context, method, path string, payload, result interface{}, authenticated bool) (bool, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return false, err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+c.state.AgentToken)
		request.Header.Set("X-Device-ID", c.state.DeviceID)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return true, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		return false, fmt.Errorf("server returned %s: %s", response.Status, string(data))
	}
	if result != nil {
		if err := json.NewDecoder(response.Body).Decode(result); err != nil {
			return false, err
		}
	}
	return false, nil
}

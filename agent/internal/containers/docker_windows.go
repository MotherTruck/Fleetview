package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const dockerPipeName = `\\.\pipe\docker_engine`

type dockerPort struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
	IP          string `json:"IP"`
}

type dockerContainer struct {
	ID      string       `json:"Id"`
	Names   []string     `json:"Names"`
	Image   string       `json:"Image"`
	Created int64        `json:"Created"`
	State   string       `json:"State"`
	Status  string       `json:"Status"`
	Ports   []dockerPort `json:"Ports"`
}

func Collect(ctx context.Context) (bool, []Container, error) {
	client := dockerClient()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=1", nil)
	if err != nil {
		return false, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return false, []Container{}, nil
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return true, nil, fmt.Errorf("Docker returned %s", response.Status)
	}
	var source []dockerContainer
	if err := json.NewDecoder(response.Body).Decode(&source); err != nil {
		return true, nil, fmt.Errorf("decode Docker containers: %w", err)
	}
	result := make([]Container, 0, len(source))
	for _, item := range source {
		name := ""
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		identifier := item.ID
		if len(identifier) > 12 {
			identifier = identifier[:12]
		}
		ports := make([]Port, 0, len(item.Ports))
		for _, port := range item.Ports {
			ports = append(ports, Port{PrivatePort: port.PrivatePort, PublicPort: port.PublicPort, Type: port.Type, IP: port.IP})
		}
		result = append(result, withUpdateStatus(Container{
			ID: identifier, Name: name, Image: item.Image, State: item.State,
			Status: item.Status, CreatedAt: time.Unix(item.Created, 0).UTC().Format(time.RFC3339), Ports: ports,
		}))
	}
	return true, result, nil
}

func dockerClient() *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialDockerPipe(ctx)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return client
}

// dialDockerPipe opens Docker Desktop's named pipe, retrying briefly on
// ERROR_PIPE_BUSY the way WaitNamedPipe is meant to be used for (Docker's
// pipe server only accepts one pending connection at a time).
func dialDockerPipe(ctx context.Context) (net.Conn, error) {
	pathPtr, err := windows.UTF16PtrFromString(dockerPipeName)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		handle, err := windows.CreateFile(pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return &namedPipeConn{file: os.NewFile(uintptr(handle), dockerPipeName)}, nil
		}
		if err != windows.ERROR_PIPE_BUSY || time.Now().After(deadline) {
			return nil, fmt.Errorf("open %s: %w", dockerPipeName, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// namedPipeConn adapts a Windows named-pipe file handle to net.Conn so it can
// back an http.Transport the same way the Linux build dials a Unix socket.
// Deadlines are best-effort no-ops: the http.Client's overall Timeout and the
// request's context (which the transport watches to close the connection on
// cancellation) already bound how long a call can hang.
type namedPipeConn struct {
	file *os.File
}

func (c *namedPipeConn) Read(b []byte) (int, error)       { return c.file.Read(b) }
func (c *namedPipeConn) Write(b []byte) (int, error)      { return c.file.Write(b) }
func (c *namedPipeConn) Close() error                     { return c.file.Close() }
func (c *namedPipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (c *namedPipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (c *namedPipeConn) SetDeadline(time.Time) error      { return nil }
func (c *namedPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *namedPipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return dockerPipeName }

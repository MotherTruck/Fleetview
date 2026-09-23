package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const dockerSocket = "/var/run/docker.sock"

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
		result = append(result, Container{
			ID: identifier, Name: name, Image: item.Image, State: item.State,
			Status: item.Status, CreatedAt: time.Unix(item.Created, 0).UTC().Format(time.RFC3339), Ports: ports,
		})
	}
	return true, result, nil
}

func dockerClient() *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", dockerSocket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return client
}

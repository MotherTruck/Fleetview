package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

var containerIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{12,64}$`)

// Action sends one constrained request to the local Docker Engine.
func Action(ctx context.Context, action, id string) error {
	client := dockerClient()
	client.Timeout = 25 * time.Second
	return actionWithClient(ctx, client, action, id)
}

func actionWithClient(ctx context.Context, client *http.Client, action, id string) error {
	if !containerIDPattern.MatchString(id) || (action != "start" && action != "stop" && action != "restart") {
		return fmt.Errorf("invalid Docker container action or ID")
	}
	url := "http://docker/containers/" + id + "/" + action
	if action != "start" {
		url += "?t=10"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Docker %s: %w", action, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == http.StatusNotModified {
		return fmt.Errorf("Docker container state did not change (%s)", action)
	}
	var message struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&message)
	if message.Message != "" {
		return fmt.Errorf("Docker %s: %s", action, message.Message)
	}
	return fmt.Errorf("Docker %s: %s", action, response.Status)
}

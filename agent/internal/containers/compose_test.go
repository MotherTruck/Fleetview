package containers

import (
	"context"
	"strings"
	"testing"
)

func TestComposeUpRejectsInvalidProjectNames(t *testing.T) {
	for _, project := range []string{"", "Has-Upper", "-leading-dash", "has a space", strings.Repeat("a", 64)} {
		if _, err := ComposeUp(context.Background(), project, "services: {}"); err == nil {
			t.Errorf("accepted invalid project %q", project)
		}
	}
}

func TestComposeUpRejectsEmptyOrOversizedCompose(t *testing.T) {
	if _, err := ComposeUp(context.Background(), "myproject", ""); err == nil {
		t.Error("accepted empty compose file")
	}
	oversized := strings.Repeat("a", maxComposeBytes+1)
	if _, err := ComposeUp(context.Background(), "myproject", oversized); err == nil {
		t.Error("accepted oversized compose file")
	}
}

func TestTruncateComposeOutputKeepsTail(t *testing.T) {
	input := strings.Repeat("x", maxComposeOutput+500) + "END"
	got := truncateComposeOutput([]byte(input))
	if len(got) != maxComposeOutput {
		t.Fatalf("expected truncated length %d, got %d", maxComposeOutput, len(got))
	}
	if !strings.HasSuffix(got, "END") {
		t.Fatalf("expected truncation to keep the tail, got suffix %q", got[len(got)-10:])
	}
}

package packages

import (
	"context"
	"testing"
)

func TestUninstallRejectsInvalidNamesWithoutExecuting(t *testing.T) {
	for _, name := range []string{"", "--help", "foo*", "foo bar", "foo;bar", "/tmp/pkg"} {
		_, code, err := Uninstall(context.Background(), "apt", name)
		if err == nil || code != -1 {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
}

func TestUninstallRejectsUnsupportedManager(t *testing.T) {
	_, _, err := Uninstall(context.Background(), "unknown", "htop")
	if err == nil {
		t.Fatal("accepted unknown manager")
	}
}

package packages

import (
	"context"
	"strings"
	"testing"

	"fleetview-agent/internal/model"
)

type approvalManager struct{ updates []model.Update }

func (m approvalManager) Name() string                                       { return "pacman" }
func (m approvalManager) Installed(context.Context) ([]model.Package, error) { return nil, nil }
func (m approvalManager) Updates(context.Context) ([]model.Update, error)    { return m.updates, nil }
func (m approvalManager) InstallUpdates() (string, int, error) {
	panic("must not install an unapproved patch set")
}
func (m approvalManager) Install(context.Context, string) (string, int, error) {
	panic("unexpected install")
}

func TestRejectsStaleAndPartialArchApprovalsBeforeExecution(t *testing.T) {
	manager := approvalManager{updates: []model.Update{
		{Package: "kernel", AvailableVersion: "2"}, {Package: "openssl", AvailableVersion: "3"},
	}}
	_, _, err := InstallApproved(context.Background(), manager, []model.ApprovedUpdate{{Package: "kernel", Version: "1"}})
	if err == nil || !strings.Contains(err.Error(), "no longer pending") {
		t.Fatalf("stale approval: %v", err)
	}
	_, _, err = InstallApproved(context.Background(), manager, []model.ApprovedUpdate{{Package: "kernel", Version: "2"}})
	if err == nil || !strings.Contains(err.Error(), "every pending") {
		t.Fatalf("partial Arch upgrade: %v", err)
	}
}

func TestAPTPlanRejectsUnapprovedDependenciesAndVersionChanges(t *testing.T) {
	wanted := map[string]string{"curl": "2.0"}
	if err := verifyAPTPlan("Inst curl [1.0] (2.0 Debian:stable [amd64])\n", wanted); err != nil {
		t.Fatal(err)
	}
	for _, plan := range []string{
		"Inst curl [1.0] (2.0 Debian:stable [amd64])\nInst libcurl [1] (2 Debian:stable [amd64])\n",
		"Inst curl [1.0] (2.1 Debian:stable [amd64])\n",
		"0 upgraded, 0 newly installed\n",
	} {
		if err := verifyAPTPlan(plan, wanted); err == nil {
			t.Fatalf("unexpectedly accepted %q", plan)
		}
	}
}

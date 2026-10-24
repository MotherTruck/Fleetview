package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"fleetview-agent/internal/client"
	"fleetview-agent/internal/config"
	"fleetview-agent/internal/model"
	"fleetview-agent/internal/selfinstall"
)

func programDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "fleetview-agent")
}

func defaultConfigPath() string {
	return filepath.Join(programDataDir(), "agent.env")
}

func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "FleetView Agent")
}

func installedExePath() string {
	return filepath.Join(installDir(), "fleetview-agent.exe")
}

// runAsServiceIfHosted runs the agent through the Windows service framework
// when the process was actually started by the service control manager
// (svc.IsWindowsService() is false for an interactive console run, so
// running the binary by hand for testing still uses the plain path in main).
func runAsServiceIfHosted(logger *log.Logger, configPath string) (handled bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("determine whether running as a Windows service: %w", err)
	}
	if !isService {
		return false, nil
	}
	if logFile, logErr := openServiceLogFile(); logErr == nil {
		defer logFile.Close()
		logger = log.New(logFile, "fleetview-agent: ", log.LstdFlags|log.LUTC)
	}
	handler := &agentService{configPath: configPath, logger: logger}
	if err := svc.Run(serviceName, handler); err != nil {
		return true, fmt.Errorf("run as Windows service: %w", err)
	}
	return true, nil
}

// openServiceLogFile gives the service somewhere to log to: a service
// launched by the SCM has no console, so the stdout logging the plain
// console entry point uses would otherwise go nowhere useful.
func openServiceLogFile() (*os.File, error) {
	dir := programDataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}

type agentService struct {
	configPath string
	logger     *log.Logger
}

func (a *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, a.configPath, a.logger) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			if err != nil {
				a.logger.Printf("agent stopped with error: %v", err)
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func controlService(action, configPath, uninstallCode string, force bool) error {
	switch action {
	case "install":
		return installService(configPath)
	case "uninstall":
		return uninstallService(configPath, uninstallCode, force)
	case "start":
		return startService()
	case "stop":
		return stopService()
	default:
		return fmt.Errorf("unknown -service action %q (want install, uninstall, start, or stop)", action)
	}
}

func installService(configPath string) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	targetExe := installedExePath()
	if !samePath(currentExe, targetExe) {
		data, err := os.ReadFile(currentExe)
		if err != nil {
			return fmt.Errorf("read %s: %w", currentExe, err)
		}
		// Strip any personalized-installer trailer (see
		// internal/selfinstall) before installing: the copy that ends up
		// running as the actual Windows service must be an ordinary
		// binary, or the SCM-started service process would detect its
		// own leftover trailer on every future start and try to
		// self-install a second time against itself instead of ever
		// reaching svc.Run -- a no-op for a plain binary that never had
		// a trailer to begin with (the "-service install" CLI flag's own
		// normal path).
		data = selfinstall.StripTrailer(data)
		if err := os.MkdirAll(installDir(), 0755); err != nil {
			return fmt.Errorf("create %s: %w", installDir(), err)
		}
		if err := os.WriteFile(targetExe, data, 0755); err != nil {
			return fmt.Errorf("install to %s: %w", targetExe, err)
		}
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager (run this elevated): %w", err)
	}
	defer manager.Disconnect()
	if existing, openErr := manager.OpenService(serviceName); openErr == nil {
		existing.Close()
		return fmt.Errorf("service %q is already installed; run \"-service uninstall\" first to reinstall", serviceName)
	}

	service, err := manager.CreateService(serviceName, targetExe, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: "FleetView Management Agent",
		Description: "Reports inventory, patch status, and vulnerability findings to the FleetView management server.",
	}, "-config", configPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer service.Close()
	if err := configureRecoveryActions(service); err != nil {
		return fmt.Errorf("service installed but failed to configure restart-on-failure: %w", err)
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("service installed but failed to start: %w", err)
	}
	fmt.Printf("Service %q installed and started (%s).\n", serviceName, targetExe)
	return nil
}

func uninstallService(configPath, uninstallCode string, force bool) error {
	cfg, cfgErr := config.Load(configPath)
	var state model.State
	var stateErr error
	if cfgErr == nil {
		state, stateErr = client.LoadState(cfg.StatePath)
	}
	if cfgErr == nil && stateErr == nil && state.DeviceID != "" && state.AgentToken != "" {
		code := uninstallCode
		if code == "" {
			code = promptUninstallCode()
		}
		api, apiErr := client.New(cfg, state)
		if apiErr != nil {
			return fmt.Errorf("configure server connection: %w", apiErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
		verifyErr := api.VerifyUninstall(ctx, code)
		cancel()
		if verifyErr != nil {
			// A device that genuinely can't reach the server (down link,
			// stale/revoked credentials after a migration, DNS broken) can
			// never satisfy this check through no fault of the admin
			// running this command -- without -Force that otherwise
			// permanently strands the agent installed with no supported
			// way to remove it. A code the server actively rejected is a
			// different failure (errors.Is false here, since that comes
			// back as a plain "server returned ..." error, not wrapped in
			// ErrServerUnreachable) and -Force must not paper over it.
			if force && errors.Is(verifyErr, client.ErrServerUnreachable) {
				fmt.Printf("Could not reach the server to verify the uninstall code (%v); removing locally anyway because -Force was given. The server will still show this device as enrolled until its record is cleaned up there.\n", verifyErr)
			} else {
				return fmt.Errorf("uninstall authorization failed: %w", verifyErr)
			}
		}
	} else {
		fmt.Println("No active enrollment found to verify; removing the service anyway.")
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager (run this elevated): %w", err)
	}
	defer manager.Disconnect()
	if service, openErr := manager.OpenService(serviceName); openErr == nil {
		_, _ = service.Control(svc.Stop)
		waitForStopped(service)
		if err := service.Delete(); err != nil {
			service.Close()
			return fmt.Errorf("delete service: %w", err)
		}
		service.Close()
	}

	_ = os.Remove(installedExePath())
	_ = os.RemoveAll(programDataDir())
	fmt.Println("FleetView agent removed from this device. Its historical server record was retained.")
	return nil
}

func promptUninstallCode() string {
	fmt.Print("Uninstall code (press Enter if protection is disabled): ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func waitForStopped(service *mgr.Service) {
	for i := 0; i < 30; i++ {
		status, err := service.Query()
		if err != nil || status.State == svc.Stopped {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func startService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager (run this elevated): %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %q: %w", serviceName, err)
	}
	defer service.Close()
	// Idempotent, and cheap enough to just always re-apply here: this is
	// also how an agent installed before configureRecoveryActions existed
	// (so its already-registered service has no restart-on-failure policy
	// at all) ends up with one -- the next UPGRADE_AGENT's finishUpgrade
	// calls this same startService after swapping the binary, self-healing
	// existing fleets without requiring a full uninstall/reinstall.
	if err := configureRecoveryActions(service); err != nil {
		return fmt.Errorf("failed to configure restart-on-failure: %w", err)
	}
	return service.Start()
}

// configureRecoveryActions tells the service control manager to restart
// this service automatically when its process exits unexpectedly --
// unlike systemd/rc.d (which restart on failure by default, relied on by
// MIGRATE_SERVER and UPGRADE_AGENT's os.Exit(1)-then-get-restarted pattern,
// see handleNextJob in main.go), Windows does nothing on its own: a
// service whose process exits is simply left Stopped until something else
// starts it again. Without this, a MIGRATE_SERVER job would exit the
// process to pick up the new server URL and never come back, leaving the
// agent offline on both the old and new server.
func configureRecoveryActions(service *mgr.Service) error {
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := service.SetRecoveryActions(recoveryActions, uint32((24 * time.Hour).Seconds())); err != nil {
		return err
	}
	// A MIGRATE_SERVER/UPGRADE_AGENT os.Exit(1) never reports SERVICE_STOPPED
	// to the SCM first, so it already counts as a "crash" and would trigger
	// the recovery actions above without this -- but setting it explicitly
	// means any future clean-exit-with-nonzero-code path is covered too,
	// not just ones that happen to look like a crash to the SCM.
	return service.SetRecoveryActionsOnNonCrashFailures(true)
}

func stopService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager (run this elevated): %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %q: %w", serviceName, err)
	}
	defer service.Close()
	_, err = service.Control(svc.Stop)
	return err
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(absA, absB)
}

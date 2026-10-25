package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"fleetview-agent/internal/client"
	"fleetview-agent/internal/config"
	"fleetview-agent/internal/containers"
	"fleetview-agent/internal/inventory"
	"fleetview-agent/internal/live"
	"fleetview-agent/internal/model"
	"fleetview-agent/internal/packages"
	"fleetview-agent/internal/telemetry"
	"fleetview-agent/internal/vulnerability"
)

// version is overridable at build time via -ldflags "-X main.version=...",
// which the server's Docker image build uses so published agent binaries
// self-report the exact version they were built as.
var version = "0.31.1"

const serviceName = "fleetview-agent"

func main() {
	// Checked before any flag parsing: a personalized installer (see
	// selfinstall_windows.go) is run by double-clicking it from the
	// dashboard's download, with zero arguments, so this has to be the
	// very first thing main does -- not a flag, since there's no command
	// line to put one on.
	if runSelfInstallIfPersonalized() {
		return
	}
	// Also checked before flag parsing, for the same reason: this process
	// invocation is the screen-capture helper the service spawns into a
	// user's session for remote control (see screenhelper_windows.go), not
	// a normal agent run, and its arguments aren't normal flags either.
	if runScreenHelperIfRequested() {
		return
	}

	configPath := flag.String("config", defaultConfigPath(), "path to agent configuration")
	serviceAction := flag.String("service", "", "service control action: install, uninstall, start, stop (Windows only)")
	uninstallCode := flag.String("uninstall-code", "", "managed-uninstall code for -service uninstall; prompted for if omitted and one is configured")
	force := flag.Bool("force", false, "for -service uninstall: remove the agent locally even if the server can't be reached to verify the uninstall code (does not bypass a code the server actually rejects)")
	finishUpgradeTarget := flag.String("finish-upgrade", "", "internal: complete a staged agent upgrade by replacing the binary at this path (Windows only; invoked by the agent itself, not meant to be run by hand)")
	flag.Parse()
	logger := log.New(os.Stdout, "fleetview-agent: ", log.LstdFlags|log.LUTC)

	if *finishUpgradeTarget != "" {
		if err := finishUpgrade(*finishUpgradeTarget); err != nil {
			logger.Fatal(err)
		}
		return
	}

	if *serviceAction != "" {
		if err := controlService(*serviceAction, *configPath, *uninstallCode, *force); err != nil {
			logger.Fatal(err)
		}
		return
	}

	if handled, err := runAsServiceIfHosted(logger, *configPath); handled {
		if err != nil {
			logger.Fatal(err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runAgent(ctx, *configPath, logger); err != nil {
		logger.Fatal(err)
	}
}

// runAgent loads configuration, enrolls if needed, and runs the scan/metrics/
// job loop until ctx is cancelled. It's shared by the plain console entry
// point above and the Windows service Handler (service_windows.go), which
// supplies a ctx that's cancelled when the service control manager asks the
// service to stop.
func runAgent(ctx context.Context, configPath string, logger *log.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	state, err := client.LoadState(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	api, err := client.New(cfg, state)
	if err != nil {
		return fmt.Errorf("configure server connection: %w", err)
	}

	if state.DeviceID == "" || state.AgentToken == "" {
		if cfg.EnrollmentToken == "" {
			return fmt.Errorf("agent is not enrolled and FLEETVIEW_ENROLLMENT_TOKEN is empty")
		}
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		enrollCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
		state, err = api.Enroll(enrollCtx, cfg.EnrollmentToken, hostname, version)
		cancel()
		if err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		if err := client.SaveState(cfg.StatePath, state); err != nil {
			return fmt.Errorf("save enrollment: %w", err)
		}
		logger.Printf("enrolled device %s", state.DeviceID)
	}

	manager, err := packages.Detect()
	if err != nil {
		// A missing package manager (e.g. winget not present -- common on
		// a fresh Windows install/VM, and Windows Server doesn't ship it
		// at all) shouldn't take down the whole agent: enrollment,
		// metrics, inventory, the live terminal, and Wake-on-LAN are all
		// fully independent of it. The device just reports no installed-
		// package/update data and clearly rejects a package-deployment
		// job if one is ever sent to it instead.
		logger.Printf("package manager unavailable, continuing without it: %v", err)
		manager = packages.NullManager{Reason: err.Error()}
	}
	// Runs on every startup, including the restart a self-upgrade
	// (UPGRADE_AGENT) triggers, so remote control is fully self-contained:
	// no separate manual package install step on any Linux box (see
	// remotecontrol_linux.go; a no-op on Windows).
	ensureRemoteControlDependencies(logger)
	settings := model.AgentSettings{
		MetricsIntervalSeconds:   int(cfg.MetricsInterval.Seconds()),
		InventoryIntervalSeconds: int(cfg.ScanInterval.Seconds()),
		GPUMonitoringEnabled:     true,
		DockerInventoryEnabled:   true,
	}
	settingsContext, settingsCancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	if remoteSettings, settingsErr := api.AgentSettings(settingsContext); settingsErr != nil {
		logger.Printf("initial agent settings fetch failed; using local defaults: %v", settingsErr)
	} else {
		settings = remoteSettings
	}
	settingsCancel()
	metricsCollector := telemetry.NewCollector()
	if err := metricsCollector.Prime(); err != nil {
		logger.Printf("metrics initialization failed: %v", err)
	}
	if err := scanAndReport(ctx, api, manager, settings.DockerInventoryEnabled); err != nil {
		logger.Printf("initial scan failed: %v", err)
	}

	// The live WebSocket channel (fast metrics push + an admin-opened
	// interactive terminal) runs alongside the poll loop below, not instead
	// of it: a device with no live connection is still fully manageable
	// through queued jobs exactly as before this existed.
	var gpuLiveEnabled, dockerLiveEnabled atomic.Bool
	gpuLiveEnabled.Store(settings.GPUMonitoringEnabled)
	dockerLiveEnabled.Store(settings.DockerInventoryEnabled)
	processSampler := telemetry.NewProcessSampler()
	go live.Run(ctx, api, metricsCollector, processSampler, &gpuLiveEnabled, &dockerLiveEnabled, logger)

	scanTicker := time.NewTicker(time.Duration(settings.InventoryIntervalSeconds) * time.Second)
	jobTicker := time.NewTicker(cfg.JobPollInterval)
	metricsTicker := time.NewTicker(time.Duration(settings.MetricsIntervalSeconds) * time.Second)
	settingsTicker := time.NewTicker(60 * time.Second)
	defer scanTicker.Stop()
	defer jobTicker.Stop()
	defer metricsTicker.Stop()
	defer settingsTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Print("stopping")
			return nil
		case <-scanTicker.C:
			if err := scanAndReport(ctx, api, manager, settings.DockerInventoryEnabled); err != nil {
				logger.Printf("scheduled scan failed: %v", err)
			}
		case <-metricsTicker.C:
			report, metricsErr := metricsCollector.Collect(settings.GPUMonitoringEnabled)
			if metricsErr != nil {
				logger.Printf("metrics collection failed: %v", metricsErr)
			} else {
				// Mirrors the live WS metrics tick (internal/live/live.go):
				// without this, TopConsumers stays a nil slice, which the
				// server's JSON schema rejects as invalid (it requires a
				// list, not null) -- every periodic report would 422.
				report.TopConsumers = telemetry.TopConsumers(live.GatherConsumers(ctx, processSampler, dockerLiveEnabled.Load()), live.TopConsumersLimit)
				if metricsErr = api.ReportMetrics(ctx, report); metricsErr != nil {
					logger.Printf("metrics report failed: %v", metricsErr)
				}
			}
		case <-jobTicker.C:
			stagedUpgrade, restartNeeded, err := handleNextJob(ctx, api, manager, logger, settings.DockerInventoryEnabled, configPath)
			if err != nil {
				logger.Printf("job poll failed: %v", err)
			}
			if len(stagedUpgrade) > 0 {
				logger.Print("applying staged agent upgrade")
				if applyErr := applyUpgrade(stagedUpgrade); applyErr != nil {
					// A Linux success never reaches here (the process image is
					// replaced in place); a Windows success also doesn't, since
					// the detached helper takes over and this process exits.
					logger.Printf("apply upgrade failed: %v", applyErr)
				}
			}
			if restartNeeded {
				// The config file on disk now points at the new server, but
				// this process's in-memory api client still points at the
				// old one -- exit non-zero so systemd/rc.d's restart-on-
				// failure policy brings the agent back up reading the new
				// FLEETVIEW_SERVER_URL (see handleNextJob's MIGRATE_SERVER
				// case and the Restart= line in agent/packaging).
				logger.Print("migrating to a new management server; restarting to reconnect")
				os.Exit(1)
			}
		case <-settingsTicker.C:
			remoteSettings, settingsErr := api.AgentSettings(ctx)
			if settingsErr != nil {
				logger.Printf("agent settings refresh failed: %v", settingsErr)
				continue
			}
			if remoteSettings.MetricsIntervalSeconds != settings.MetricsIntervalSeconds {
				metricsTicker.Reset(time.Duration(remoteSettings.MetricsIntervalSeconds) * time.Second)
			}
			if remoteSettings.InventoryIntervalSeconds != settings.InventoryIntervalSeconds {
				scanTicker.Reset(time.Duration(remoteSettings.InventoryIntervalSeconds) * time.Second)
			}
			gpuLiveEnabled.Store(remoteSettings.GPUMonitoringEnabled)
			dockerLiveEnabled.Store(remoteSettings.DockerInventoryEnabled)
			settings = remoteSettings
		}
	}
}

func buildReport(ctx context.Context, manager packages.Manager, dockerInventoryEnabled bool) (model.Report, error) {
	system, err := inventory.Collect(dockerInventoryEnabled)
	if err != nil {
		return model.Report{}, err
	}
	installed, err := manager.Installed(ctx)
	if err != nil {
		return model.Report{}, err
	}
	updates, err := manager.Updates(ctx)
	if err != nil {
		return model.Report{}, err
	}
	return model.Report{Hostname: system.Hostname, Platform: runtime.GOOS, OSName: system.OSName, OSVersion: system.OSVersion, Architecture: system.Architecture, PackageManager: manager.Name(), AgentVersion: version, Inventory: system.Details, InstalledPackages: installed, AvailableUpdates: updates, ScannedAt: time.Now().UTC()}, nil
}

func scanAndReport(ctx context.Context, api *client.Client, manager packages.Manager, dockerInventoryEnabled bool) error {
	report, err := buildReport(ctx, manager, dockerInventoryEnabled)
	if err != nil {
		return err
	}
	return api.Report(ctx, report)
}

// handleNextJob returns a non-nil stagedUpgrade when an UPGRADE_AGENT job
// was verified and reported successfully; the caller then applies it
// (replacing/restarting the running agent) once this function has
// returned, so the job-completion report is never at risk of being lost
// to the process replacement it triggers. restartNeeded is the same idea
// for a MIGRATE_SERVER job: the config file on disk has a new
// FLEETVIEW_SERVER_URL by the time this returns, but the in-memory api
// client still points at the old server, so the caller exits the process
// (letting systemd/rc.d's restart-on-failure policy bring it back up
// reading the new URL) only after this job's own completion report has
// gone to the server it was actually received from.
func handleNextJob(ctx context.Context, api *client.Client, manager packages.Manager, logger *log.Logger, dockerInventoryEnabled bool, configPath string) (stagedUpgrade []byte, restartNeeded bool, err error) {
	job, err := api.NextJob(ctx)
	if err != nil || job == nil {
		return nil, false, err
	}
	logger.Printf("running job %s (%s)", job.ID, job.Type)
	result := model.JobResult{Status: "succeeded", Output: "Job completed"}
	var stageErr error
	switch job.Type {
	case "SCAN_DEVICE":
		err = scanAndReport(ctx, api, manager, dockerInventoryEnabled)
		result.Output = "Inventory and update scan completed"
	case "DOCKER_CONTAINER_ACTION":
		if !dockerInventoryEnabled {
			err = fmt.Errorf("Docker inventory and management are disabled for this device")
			break
		}
		confirmed, _ := job.Options["confirmed"].(bool)
		action, _ := job.Options["action"].(string)
		id, _ := job.Options["container_id"].(string)
		if !confirmed {
			err = fmt.Errorf("Docker action requires confirmation")
			break
		}
		err = containers.Action(ctx, action, id)
		if err == nil {
			result.Output = fmt.Sprintf("Docker container %s: %s", id, action)
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-Docker-action scan failed: %v", scanErr)
			}
		}
	case "DOCKER_COMPOSE_UP":
		if !dockerInventoryEnabled {
			err = fmt.Errorf("Docker inventory and management are disabled for this device")
			break
		}
		project, _ := job.Options["project"].(string)
		compose, _ := job.Options["compose"].(string)
		var composeOutput string
		composeOutput, err = containers.ComposeUp(ctx, project, compose)
		if err == nil {
			result.Output = composeOutput
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-compose-up scan failed: %v", scanErr)
			}
		}
	case "DOCKER_VOLUME_REMOVE":
		if !dockerInventoryEnabled {
			err = fmt.Errorf("Docker inventory and management are disabled for this device")
			break
		}
		confirmed, _ := job.Options["confirmed"].(bool)
		name, _ := job.Options["name"].(string)
		if !confirmed {
			err = fmt.Errorf("Docker volume removal requires confirmation")
			break
		}
		err = containers.RemoveVolume(ctx, name)
		if err == nil {
			result.Output = fmt.Sprintf("Removed Docker volume %s", name)
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-volume-remove scan failed: %v", scanErr)
			}
		}
	case "DOCKER_VOLUME_PRUNE":
		if !dockerInventoryEnabled {
			err = fmt.Errorf("Docker inventory and management are disabled for this device")
			break
		}
		confirmed, _ := job.Options["confirmed"].(bool)
		if !confirmed {
			err = fmt.Errorf("Docker volume prune requires confirmation")
			break
		}
		var deleted []string
		var reclaimed uint64
		deleted, reclaimed, err = containers.PruneVolumes(ctx)
		if err == nil {
			result.Output = fmt.Sprintf("Removed %d unused volume(s), reclaimed %d bytes: %s", len(deleted), reclaimed, strings.Join(deleted, ", "))
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-volume-prune scan failed: %v", scanErr)
			}
		}
	case "SCAN_VULNERABILITIES":
		var report model.VulnerabilityReport
		var scanner vulnerability.Scanner
		scanner, err = vulnerability.Detect(manager.Name())
		if err == nil {
			var installed []model.Package
			installed, err = manager.Installed(ctx)
			if err == nil {
				report, err = scanner.Scan(ctx, installed)
			}
		}
		if err == nil {
			report.ListeningPorts = vulnerability.ListeningPorts(ctx)
			err = api.ReportVulnerabilities(ctx, report)
		}
		if err == nil {
			result.Output = fmt.Sprintf("Vulnerability scan completed: %d findings", len(report.Vulnerabilities))
		}
	case "INSTALL_UPDATES":
		confirmed, _ := job.Options["confirmed"].(bool)
		if !confirmed {
			err = fmt.Errorf("server job did not include confirmed=true")
			break
		}
		var output string
		var exitCode int
		output, exitCode, err = manager.InstallUpdates()
		result.Output = output
		result.ExitCode = &exitCode
		if err == nil {
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-update scan failed: %v", scanErr)
			}
		}
	case "INSTALL_APPROVED_UPDATES":
		items, ok := job.Options["updates"].([]interface{})
		if !ok || len(items) == 0 {
			err = fmt.Errorf("approved update list missing")
			break
		}
		approved := make([]model.ApprovedUpdate, 0, len(items))
		for _, raw := range items {
			entry, valid := raw.(map[string]interface{})
			if !valid {
				err = fmt.Errorf("invalid approved update")
				break
			}
			name, nameOK := entry["package"].(string)
			version, versionOK := entry["version"].(string)
			if !nameOK || !versionOK {
				err = fmt.Errorf("invalid approved update")
				break
			}
			approved = append(approved, model.ApprovedUpdate{Package: name, Version: version})
		}
		if err != nil {
			break
		}
		output, code, installErr := packages.InstallApproved(ctx, manager, approved)
		err = installErr
		result.Output, result.ExitCode = output, &code
		if err == nil {
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-update scan failed: %v", scanErr)
			}
		}
	case "INSTALL_CUSTOM_PACKAGE":
		output, code, installErr := runCustomInstall(ctx, api, job.ID)
		err = installErr
		result.Output, result.ExitCode = output, &code
		if err == nil {
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-install scan failed: %v", scanErr)
			}
		}
	case "UNINSTALL_PACKAGE":
		if confirmed, _ := job.Options["confirmed"].(bool); !confirmed {
			err = fmt.Errorf("uninstall requires explicit confirmation")
			break
		}
		name, _ := job.Options["package"].(string)
		output, code, removeErr := packages.Uninstall(ctx, manager.Name(), name)
		err = removeErr
		result.Output, result.ExitCode = output, &code
		if err == nil {
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-uninstall scan failed: %v", scanErr)
			}
		}
	case "RUN_COMMAND":
		if confirmed, _ := job.Options["confirmed"].(bool); !confirmed {
			err = fmt.Errorf("command execution requires explicit confirmation")
			break
		}
		command, _ := job.Options["command"].(string)
		if strings.TrimSpace(command) == "" {
			err = fmt.Errorf("server job did not include a command")
			break
		}
		var output string
		var exitCode int
		output, exitCode, err = runCommand(ctx, command)
		result.Output = output
		result.ExitCode = &exitCode
	case "NETWORK_DIAGNOSTIC":
		tool, _ := job.Options["tool"].(string)
		target, _ := job.Options["target"].(string)
		portFloat, _ := job.Options["port"].(float64) // JSON numbers decode as float64
		var output string
		var exitCode int
		output, exitCode, err = runNetworkDiagnostic(ctx, tool, target, int(portFloat))
		result.Output = output
		result.ExitCode = &exitCode
	case "WAKE_ON_LAN":
		mac, _ := job.Options["mac"].(string)
		if strings.TrimSpace(mac) == "" {
			err = fmt.Errorf("server job did not include a MAC address")
			break
		}
		err = sendWakeOnLAN(mac)
		if err == nil {
			result.Output = fmt.Sprintf("Magic packet broadcast for %s", mac)
		}
	case "UPGRADE_AGENT":
		downloadURL, _ := job.Options["url"].(string)
		expectedSHA, _ := job.Options["sha256"].(string)
		newVersion, _ := job.Options["version"].(string)
		if downloadURL == "" || expectedSHA == "" || newVersion == "" {
			err = fmt.Errorf("server job did not include a valid upgrade manifest")
			break
		}
		stagedUpgrade, stageErr = stageUpgrade(ctx, api, downloadURL, expectedSHA)
		err = stageErr
		if err == nil {
			result.Output = fmt.Sprintf("Downloaded and verified agent %s; applying now", newVersion)
		}
	case "INSTALL_PACKAGE":
		packageName, _ := job.Options["package"].(string)
		if strings.TrimSpace(packageName) == "" {
			err = fmt.Errorf("server job did not include a package name")
			break
		}
		var output string
		var exitCode int
		output, exitCode, err = manager.Install(ctx, packageName)
		result.Output = output
		result.ExitCode = &exitCode
		if err == nil {
			result.Output = fmt.Sprintf("Installed %s\n\n%s", packageName, output)
			if scanErr := scanAndReport(ctx, api, manager, dockerInventoryEnabled); scanErr != nil {
				logger.Printf("post-install scan failed: %v", scanErr)
			}
		}
	case "MIGRATE_SERVER":
		newURL, _ := job.Options["server_url"].(string)
		newURL = strings.TrimRight(strings.TrimSpace(newURL), "/")
		if !strings.HasPrefix(newURL, "http://") && !strings.HasPrefix(newURL, "https://") {
			err = fmt.Errorf("server job did not include a valid target server URL")
			break
		}
		if updateErr := config.UpdateServerURL(configPath, newURL); updateErr != nil {
			err = fmt.Errorf("update server URL in config: %w", updateErr)
			break
		}
		restartNeeded = true
		result.Output = fmt.Sprintf("Re-pointed this agent at %s; restarting to reconnect", newURL)
	default:
		err = fmt.Errorf("unsupported job type %q", job.Type)
	}
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		restartNeeded = false
	}
	completeErr := api.CompleteJob(ctx, job.ID, result)
	if completeErr != nil || err != nil {
		return nil, false, completeErr
	}
	if len(stagedUpgrade) == 0 && !restartNeeded {
		return nil, false, nil
	}
	return stagedUpgrade, restartNeeded, nil
}

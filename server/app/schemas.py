from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class EnrollRequest(BaseModel):
    enrollment_token: str = Field(min_length=16)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = "linux"
    agent_version: str = Field(max_length=50)


class EnrollResponse(BaseModel):
    device_id: str
    agent_token: str


class EnrollmentTokenCreate(BaseModel):
    label: str | None = Field(default=None, max_length=255)
    ttl_minutes: int = Field(default=60, ge=1, le=10080)


class DeviceReport(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = "linux"
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    package_manager: str | None = None
    agent_version: str
    inventory: dict[str, Any] = Field(default_factory=dict)
    installed_packages: list[dict[str, Any]] = Field(default_factory=list)
    available_updates: list[dict[str, Any]] = Field(default_factory=list)
    scanned_at: datetime


class VulnerabilityFinding(BaseModel):
    vulnerability_id: str = Field(min_length=1, max_length=100)
    package: str = Field(min_length=1, max_length=255)
    installed_version: str = Field(default="", max_length=255)
    fixed_version: str = Field(default="", max_length=255)
    severity: str = Field(default="UNKNOWN", max_length=20)
    status: str = Field(default="unknown", max_length=50)
    title: str = Field(default="", max_length=1000)
    primary_url: str = Field(default="", max_length=2048)
    references: list[str] = Field(default_factory=list, max_length=50)
    target: str = Field(default="", max_length=255)


class VulnerabilityReport(BaseModel):
    scanner: str = Field(default="unknown", max_length=50)
    scanner_version: str = Field(default="unknown", max_length=100)
    scanned_at: datetime
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)


class MetricsReport(BaseModel):
    recorded_at: datetime
    cpu_percent: float = Field(ge=0, le=100)
    memory_used_bytes: int = Field(ge=0)
    memory_total_bytes: int = Field(ge=0)
    swap_used_bytes: int = Field(ge=0)
    swap_total_bytes: int = Field(ge=0)
    disk_used_bytes: int = Field(ge=0)
    disk_total_bytes: int = Field(ge=0)
    load_1: float = Field(ge=0)
    load_5: float = Field(ge=0)
    load_15: float = Field(ge=0)
    network_receive_bps: float = Field(ge=0)
    network_transmit_bps: float = Field(ge=0)
    network_receive_bytes: int = Field(ge=0)
    network_transmit_bytes: int = Field(ge=0)
    process_count: int = Field(ge=0)
    temperature_celsius: float | None = Field(default=None, ge=-100, le=250)
    uptime_seconds: int = Field(ge=0)
    gpus: list[dict[str, Any]] = Field(default_factory=list, max_length=16)


class PackageUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    version: str = Field(default="", max_length=100)
    category: str = Field(default="", max_length=100)
    pacman_name: str = Field(default="", max_length=255)
    apt_name: str = Field(default="", max_length=255)
    winget_id: str = Field(default="", max_length=255)


class FleetSettingsUpdate(BaseModel):
    default_metrics_interval_seconds: int = Field(default=60, ge=15, le=3600)
    default_inventory_interval_seconds: int = Field(default=900, ge=300, le=86400)


class AgentSettingsUpdate(BaseModel):
    metrics_interval_seconds: int = Field(default=60, ge=15, le=3600)
    inventory_interval_seconds: int = Field(default=900, ge=300, le=86400)
    gpu_monitoring_enabled: bool = True
    docker_inventory_enabled: bool = True
    uninstall_code_required: bool = False
    uninstall_code: str | None = Field(default=None, min_length=4, max_length=128)


class UninstallVerifyRequest(BaseModel):
    code: str = Field(default="", max_length=128)


class JobCreate(BaseModel):
    type: Literal["SCAN_DEVICE", "SCAN_VULNERABILITIES", "INSTALL_UPDATES", "INSTALL_PACKAGE", "UNINSTALL_PACKAGE", "DOCKER_CONTAINER_ACTION"]
    options: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityScheduleUpdate(BaseModel):
    interval_hours: int = Field(default=0, ge=0, le=8760)


class JobResult(BaseModel):
    status: Literal["succeeded", "failed"]
    exit_code: int | None = None
    output: str = Field(default="", max_length=1_048_576)
    error: str = Field(default="", max_length=65_536)

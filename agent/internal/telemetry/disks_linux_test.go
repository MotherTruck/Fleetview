package telemetry

import "testing"

func TestIsManagedMountExcludesKubeletAndRuntimePaths(t *testing.T) {
	managed := []string{
		"/var/lib/kubelet/pods/abc-123/volumes/kubernetes.io~empty-dir/data",
		"/var/lib/docker/overlay2/abcdef/merged",
		"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs",
		"/var/lib/containers/storage/overlay/xyz/merged",
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs",
		"/run/docker/netns/abcdef123456",
	}
	for _, mountPoint := range managed {
		if !isManagedMount(mountPoint) {
			t.Errorf("expected %q to be treated as a managed mount", mountPoint)
		}
	}
}

func TestIsManagedMountKeepsRealDrives(t *testing.T) {
	real := []string{"/", "/home", "/mnt/data", "/srv", "/var/lib/postgresql"}
	for _, mountPoint := range real {
		if isManagedMount(mountPoint) {
			t.Errorf("expected %q to NOT be treated as a managed mount", mountPoint)
		}
	}
}

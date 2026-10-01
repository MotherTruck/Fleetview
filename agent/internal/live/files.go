package live

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// filesHandler serves on-demand directory listings and file reads over the
// live channel. Unlike terminalHandler/screenHandler, it holds no
// per-session OS resource (no process, no capture loop) -- every request is
// independent and stateless here, so there's nothing to claim or release on
// the agent side. The server enforces "one browser viewer per device at a
// time" on its own side (see live.rs's claim_files), purely to keep the UX
// simple; the agent itself would behave correctly even serving several
// concurrent sessions, since it just echoes back whatever session id a
// request carried.
//
// This deliberately does not sandbox paths to some "safe" subtree: an admin
// who can open this already has unrestricted shell access to the same
// machine via the Terminal feature, so a full-filesystem read here grants
// no privilege a Terminal session doesn't already have.
type filesHandler struct {
	send func(payload any)
}

type filesEntry struct {
	Name       string `json:"name"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modified_at"`
}

type filesListResult struct {
	Type      string       `json:"type"`
	Session   string       `json:"session"`
	Path      string       `json:"path"`
	Entries   []filesEntry `json:"entries,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type filesReadResult struct {
	Type      string `json:"type"`
	Session   string `json:"session"`
	Path      string `json:"path"`
	Data      string `json:"data,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// maxListEntries caps a single directory listing so a pathological
// directory (e.g. a huge cache or /proc) can't blow up the live channel's
// write queue or the dashboard's rendering.
const maxListEntries = 2000

// maxReadBytes caps a single file read, matching the custom-package-upload
// limit elsewhere in this project -- large enough for configs/logs, small
// enough to never stall the connection.
const maxReadBytes = 8 * 1024 * 1024

func (f *filesHandler) list(session, path string) {
	target := path
	if target == "" {
		target = defaultRoot()
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		f.send(filesListResult{Type: "files_list_result", Session: session, Path: target, Error: err.Error()})
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	truncated := len(entries) > maxListEntries
	if truncated {
		entries = entries[:maxListEntries]
	}
	result := make([]filesEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// A broken symlink or a file removed between ReadDir and Info:
			// skip rather than fail the whole listing.
			continue
		}
		result = append(result, filesEntry{
			Name:       entry.Name(),
			IsDir:      entry.IsDir(),
			Size:       info.Size(),
			ModifiedAt: info.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	f.send(filesListResult{Type: "files_list_result", Session: session, Path: target, Entries: result, Truncated: truncated})
}

func (f *filesHandler) read(session, path string) {
	if path == "" {
		f.send(filesReadResult{Type: "files_read_result", Session: session, Path: path, Error: "no path given"})
		return
	}
	file, err := os.Open(path)
	if err != nil {
		f.send(filesReadResult{Type: "files_read_result", Session: session, Path: path, Error: err.Error()})
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		f.send(filesReadResult{Type: "files_read_result", Session: session, Path: path, Error: err.Error()})
		return
	}
	if info.IsDir() {
		f.send(filesReadResult{Type: "files_read_result", Session: session, Path: path, Error: "is a directory"})
		return
	}
	limited := io.LimitReader(file, maxReadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		f.send(filesReadResult{Type: "files_read_result", Session: session, Path: path, Error: err.Error()})
		return
	}
	truncated := len(data) > maxReadBytes
	if truncated {
		data = data[:maxReadBytes]
	}
	f.send(filesReadResult{
		Type:      "files_read_result",
		Session:   session,
		Path:      path,
		Data:      base64.StdEncoding.EncodeToString(data),
		Size:      int64(len(data)),
		Truncated: truncated,
	})
}

// defaultRoot is used when the dashboard asks for an empty path (the
// initial listing on opening the Files tab): "/" on Linux/macOS, and the
// system drive root on Windows, where "/" isn't a meaningful path.
func defaultRoot() string {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("SystemDrive"); root != "" {
			return root + `\`
		}
		return `C:\`
	}
	return string(filepath.Separator)
}

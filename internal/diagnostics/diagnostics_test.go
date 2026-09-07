package diagnostics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scotthaleen/px/internal/apphome"
)

func TestReportStatusAndDeterministicSort(t *testing.T) {
	checks := []Check{
		{ID: "z", Layer: "peer", Status: Pass, Summary: "ok"},
		{ID: "b", Layer: "local", Status: Skipped, Summary: "skip"},
		{ID: "a", Layer: "local", Status: Warn, Summary: "warn"},
	}
	Sort(checks)
	if checks[0].ID != "a" || checks[1].ID != "b" || checks[2].ID != "z" {
		t.Fatalf("checks = %+v", checks)
	}
	if report := New(checks); report.Version != Version || report.Status != Warn {
		t.Fatalf("report = %+v", report)
	}
	checks = append(checks, Check{ID: "failed", Layer: "context", Status: Fail})
	if report := New(checks); report.Status != Fail {
		t.Fatalf("report = %+v", report)
	}
}

func TestPeerRouteJSONIncludesRelayAndSelectedPair(t *testing.T) {
	relayUsed := false
	check := Check{ID: "peer.direct", Layer: "peer", Status: Pass, LocalAddress: "10.0.0.1:1", RemoteAddress: "203.0.113.1:2", LocalCandidateType: "host", RemoteCandidateType: "srflx", RelayUsed: &relayUsed}
	data, err := json.Marshal(check)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"local_address":"10.0.0.1:1"`, `"remote_address":"203.0.113.1:2"`, `"local_candidate_type":"host"`, `"remote_candidate_type":"srflx"`, `"relay_used":false`} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("route JSON missing %s: %s", expected, data)
		}
	}
}

func TestLocalChecksDoNotCreateStateOrExposePaths(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing-home")
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	checks := Local(paths, false, nil)
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("local checks mutated home: %v", err)
	}
	for _, check := range checks {
		if check.Summary == "" || containsPath(check.Summary, home) {
			t.Fatalf("check exposes path: %+v", check)
		}
	}
}

func TestLocalChecksIncludeRootsAndFreeSpace(t *testing.T) {
	paths, err := apphome.Resolve(filepath.Join(t.TempDir(), "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.AgentDatabase, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	offeredRoot := t.TempDir()
	checks := Local(paths, false, []Root{{Context: "home", Kind: "offered", Path: offeredRoot}})
	found := false
	for _, check := range checks {
		if check.ID == "local.offered_root" && check.Context == "home" && check.Status == Pass {
			found = true
		}
		if containsPath(check.Summary, paths.Root) {
			t.Fatalf("check exposes path: %+v", check)
		}
	}
	if !found {
		t.Fatalf("checks = %+v", checks)
	}
}

func TestFormatBytes(t *testing.T) {
	for _, test := range []struct {
		value uint64
		want  string
	}{
		{value: 1023, want: "1023 B"},
		{value: 1024, want: "1.0 KiB"},
		{value: 1024*1024 - 1, want: "1.0 MiB"},
		{value: 5 * 1024 * 1024, want: "5.0 MiB"},
		{value: 8 * 1024 * 1024 * 1024, want: "8.0 GiB"},
		{value: 1203180978176, want: "1.1 TiB"},
		{value: 1 << 50, want: "1.0 PiB"},
		{value: 1 << 60, want: "1.0 EiB"},
	} {
		if got := formatBytes(test.value); got != test.want {
			t.Errorf("formatBytes(%d) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestLocalRootCheckRejectsSymlinkRoot(t *testing.T) {
	paths, err := apphome.Resolve(filepath.Join(t.TempDir(), "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	checks := Local(paths, true, []Root{{Context: "home", Kind: "offered", Path: link}})
	for _, check := range checks {
		if check.ID == "local.offered_root" && check.Context == "home" {
			if check.Status != Fail || strings.Contains(check.Summary, link) {
				t.Fatalf("symlink root check = %+v", check)
			}
			return
		}
	}
	t.Fatal("offered root check missing")
}

func TestLocalChecksRejectInsecureHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode policy")
	}
	paths, err := apphome.Resolve(filepath.Join(t.TempDir(), "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, check := range Local(paths, false, nil) {
		if check.ID == "local.home" {
			if check.Status != Fail {
				t.Fatalf("home check = %+v", check)
			}
			return
		}
	}
	t.Fatal("home check missing")
}

func containsPath(value, path string) bool {
	return path != "" && strings.Contains(value, path)
}

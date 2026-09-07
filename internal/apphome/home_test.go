package apphome

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scotthaleen/go-toolbelt/privatedir"
)

func TestResolvePrecedence(t *testing.T) {
	t.Setenv(EnvHome, filepath.Join(t.TempDir(), "environment"))
	override := filepath.Join(t.TempDir(), "override")

	paths, err := Resolve(override)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(override)
	if err != nil {
		t.Fatal(err)
	}
	if paths.Root != want {
		t.Fatalf("Root = %q, want %q", paths.Root, want)
	}
}

func TestLongUnixHomeUsesShortStableEndpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses named pipes")
	}
	home := filepath.Join(t.TempDir(), strings.Repeat("long-home-", 20))
	first, err := Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	for name, endpoints := range map[string][2]string{
		"agent":   {first.AgentEndpoint, second.AgentEndpoint},
		"admin":   {first.ServerAdminEndpoint, second.ServerAdminEndpoint},
		"adapter": {first.ServerAdapterEndpoint, second.ServerAdapterEndpoint},
	} {
		if endpoints[0] != endpoints[1] {
			t.Fatalf("%s endpoint is not stable: %q != %q", name, endpoints[0], endpoints[1])
		}
		if len(endpoints[0]) > 90 {
			t.Fatalf("%s endpoint remains too long: %q", name, endpoints[0])
		}
		if filepath.Dir(endpoints[0]) == os.TempDir() {
			t.Fatalf("%s endpoint uses the shared temporary directory directly: %q", name, endpoints[0])
		}
	}
	if filepath.Dir(first.AgentEndpoint) != filepath.Dir(first.ServerAdminEndpoint) || filepath.Dir(first.AgentEndpoint) != filepath.Dir(first.ServerAdapterEndpoint) {
		t.Fatal("long-home endpoints do not share one stable private runtime directory")
	}
	if err := first.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(first.AgentEndpoint))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("fallback runtime directory mode=%v err=%v", info, err)
	}
}

func TestLongUnixHomeRejectsSymlinkEndpointDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses named pipes")
	}
	home := filepath.Join(t.TempDir(), strings.Repeat("long-home-", 20))
	paths, err := Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	endpointDir := filepath.Dir(paths.AgentEndpoint)
	target := t.TempDir()
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, endpointDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(endpointDir) })
	if err := paths.EnsureAgent(); err == nil {
		t.Fatal("EnsureAgent accepted a symlink endpoint directory")
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != targetInfo.Mode().Perm() {
		t.Fatalf("symlink target mode=%v err=%v", info, err)
	}
}

func TestResolveEnvironment(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(EnvHome, home)

	paths, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	if paths.Root != want {
		t.Fatalf("Root = %q, want %q", paths.Root, want)
	}
	if paths.AgentDatabase != filepath.Join(want, "agent", "state.db") {
		t.Fatalf("AgentDatabase = %q", paths.AgentDatabase)
	}
	if paths.ServerDatabase != filepath.Join(want, "server", "state.db") {
		t.Fatalf("ServerDatabase = %q", paths.ServerDatabase)
	}
	endpoints := map[string]bool{}
	for _, endpoint := range []string{paths.AgentEndpoint, paths.ServerAdminEndpoint, paths.ServerAdapterEndpoint} {
		if endpoints[endpoint] {
			t.Fatal("agent, server admin, and server adapter endpoints must differ")
		}
		endpoints[endpoint] = true
	}
	if runtime.GOOS != "windows" && len(paths.ServerAdapterEndpoint) > 90 {
		t.Fatalf("adapter endpoint remains too long: %q", paths.ServerAdapterEndpoint)
	}
}

func TestEnsureDirectories(t *testing.T) {
	paths, err := Resolve(filepath.Join(t.TempDir(), "nested", "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureServer(); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{paths.Root, paths.AgentDir, paths.AgentKeys, paths.AgentTransfers, paths.ServerDir, paths.ServerAuthority, paths.RunDir} {
		if err := privatedir.Validate(path); err != nil {
			t.Errorf("validate %q: %v", path, err)
		}
	}
}

func TestEnsurePrivateDirectoryAcceptsSafeCreationParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode policy")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "nested", "px")
	if err := EnsurePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	for current := filepath.Join(parent, "nested"); ; current = filepath.Join(current, "px") {
		if err := privatedir.Validate(current); err != nil {
			t.Fatalf("validate %q: %v", current, err)
		}
		if current == path {
			break
		}
	}
}

func TestEnsurePrivateDirectoryRejectsUnsafeExistingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode policy")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(path); !errors.Is(err, privatedir.ErrUnsafe) {
		t.Fatalf("EnsurePrivateDirectory error = %v, want ErrUnsafe", err)
	}
}

func TestEnsurePrivateDirectoryRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "private-link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(link); !errors.Is(err, privatedir.ErrUnsafe) {
		t.Fatalf("EnsurePrivateDirectory error = %v, want ErrUnsafe", err)
	}
}

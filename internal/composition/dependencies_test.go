package composition_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scotthaleen/px/internal/adapterapi"
	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/serveradmin"
)

func TestProtectedIPCVersionsRemainIndependent(t *testing.T) {
	if agentapi.Version != 13 || serveradmin.Version != 5 || adapterapi.Version != 1 {
		t.Fatalf("IPC versions: agent=%d serveradmin=%d adapter=%d, want 13, 5, 1", agentapi.Version, serveradmin.Version, adapterapi.Version)
	}
}

func TestBinaryDependencyBoundaries(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	tests := []struct {
		binary    string
		forbidden []string
	}{
		{"./cmd/px", []string{"servercli", "serverhost", "serveradmin", "rendezvousapi", "stunserver"}},
		{"./cmd/px-server", []string{"cli", "apphost", "agentapi", "contexts", "direct", "transfer", "offered", "probe"}},
	}
	for _, test := range tests {
		t.Run(filepath.Base(test.binary), func(t *testing.T) {
			command := exec.Command("go", "list", "-deps", test.binary)
			command.Dir = root
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps: %v\n%s", err, output)
			}
			dependencies := "\n" + string(output)
			for _, name := range test.forbidden {
				if strings.Contains(dependencies, "github.com/scotthaleen/px/internal/"+name+"\n") {
					t.Errorf("%s unexpectedly depends on internal/%s", test.binary, name)
				}
			}
		})
	}
}

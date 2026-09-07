package diagnostics

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"

	"github.com/scotthaleen/go-toolbelt/privatedir"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/versioninfo"
)

type Root struct {
	Context                    string
	Kind                       string
	Path                       string
	Scope                      string
	Revision                   int64
	FilesystemRootAcknowledged bool
	AuthorityValid             bool
}

func Local(paths apphome.Paths, agentReachable bool, roots []Root) []Check {
	checks := []Check{{ID: "local.build", Layer: "local", Status: Pass, Summary: fmt.Sprintf("build %s commit %s", versioninfo.Version, versioninfo.Commit)}}
	homeOK := directoryCheck(paths.Root)
	checks = append(checks, Check{ID: "local.home", Layer: "local", Status: status(homeOK), Summary: summary(homeOK, "PX home directory is accessible", "PX home directory is unavailable or insecure")})
	if !homeOK {
		checks = append(checks,
			Check{ID: "local.state", Layer: "local", Status: Skipped, Summary: "PX home prerequisite failed"},
			Check{ID: "local.keystore", Layer: "local", Status: Skipped, Summary: "PX home prerequisite failed"},
		)
	} else {
		stateOK := regularPrivateFile(paths.AgentDatabase)
		checks = append(checks, Check{ID: "local.state", Layer: "local", Status: status(stateOK), Summary: summary(stateOK, "agent state database is accessible", "agent state database is unavailable or insecure")})
		keyOK := directoryCheck(paths.AgentKeys)
		if keyOK {
			_, keyErr := os.ReadDir(paths.AgentKeys)
			keyOK = keyErr == nil
		}
		checks = append(checks, Check{ID: "local.keystore", Layer: "local", Status: status(keyOK), Summary: summary(keyOK, "context key store is accessible", "context key store is unavailable or insecure")})
	}
	checks = append(checks, Check{ID: "local.config", Layer: "local", Status: Skipped, Summary: "agent config file is not used by this build"})
	if agentReachable {
		checks = append(checks,
			Check{ID: "local.agent", Layer: "local", Status: Pass, Summary: "agent is reachable through protected IPC"},
			Check{ID: "local.ipc", Layer: "local", Status: status(ipcSecure(paths.AgentEndpoint)), Summary: summary(ipcSecure(paths.AgentEndpoint), "IPC endpoint security is active", "IPC endpoint permissions are insecure")},
			Check{ID: "local.lock", Layer: "local", Status: Pass, Summary: "agent process lock is active"},
		)
	} else {
		checks = append(checks,
			Check{ID: "local.agent", Layer: "local", Status: Fail, Summary: "PX agent is not reachable; run px agent run or px startup install"},
			Check{ID: "local.ipc", Layer: "local", Status: Skipped, Summary: "agent reachability prerequisite failed"},
			Check{ID: "local.lock", Layer: "local", Status: Skipped, Summary: "agent reachability prerequisite failed"},
		)
	}
	if len(roots) == 0 {
		checks = append(checks, Check{ID: "local.roots", Layer: "local", Status: Skipped, Summary: "no context roots are available from the agent"})
	}
	for _, root := range roots {
		ok := rootDirectoryCheck(root.Path)
		check := Check{ID: "local." + root.Kind + "_root", Layer: "local", Context: root.Context, Status: status(ok), Summary: root.Kind + " root is accessible"}
		if !ok {
			check.Summary = root.Kind + " root is unavailable or insecure"
		} else if available, err := availableSpace(root.Path); err == nil {
			check.Summary = fmt.Sprintf("%s root is accessible with %s available", root.Kind, formatBytes(available))
		}
		checks = append(checks, check)
		if root.Kind == "offered" && root.Revision != 0 {
			broad := root.Scope == "filesystem-root"
			valid := root.AuthorityValid
			authority := Check{ID: "local.offered_root_authority", Layer: "local", Context: root.Context, Status: Pass, Summary: "offered-root authority is narrow and consistent"}
			if !valid {
				authority.Status, authority.Summary = Fail, "offered-root authority is inconsistent; offered-root and incoming-send service is blocked until explicit repair"
			} else if broad {
				authority.Status, authority.Summary = Warn, "DANGER: every authenticated member can browse and retrieve every reachable regular file beneath the filesystem root"
			}
			checks = append(checks, authority)
		}
	}
	return checks
}

func formatBytes(value uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	number := float64(value)
	unit := 0
	for number >= 1024 && unit < len(units)-1 {
		number /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", value)
	}
	if math.Round(number*10)/10 >= 1024 && unit < len(units)-1 {
		number /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", number, units[unit])
}

func rootDirectoryCheck(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false
	}
	directory, err := os.Open(path)
	if err != nil {
		return false
	}
	_, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	return (readErr == nil || errors.Is(readErr, io.EOF)) && closeErr == nil
}

func directoryCheck(path string) bool {
	return privatedir.Validate(path) == nil
}

func regularPrivateFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0 || directoryCheck(filepath.Dir(path))
}

func ipcSecure(path string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm() == 0o600
}

func status(ok bool) string {
	if ok {
		return Pass
	}
	return Fail
}

func summary(ok bool, success, failure string) string {
	if ok {
		return success
	}
	return failure
}

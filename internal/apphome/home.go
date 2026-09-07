package apphome

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/scotthaleen/go-toolbelt/privatedir"
)

const EnvHome = "PX_HOME"

type Paths struct {
	Root                  string
	AgentDir              string
	AgentConfig           string
	AgentDatabase         string
	AgentKeys             string
	AgentTransfers        string
	AgentLock             string
	ServerDir             string
	ServerConfig          string
	ServerDatabase        string
	ServerAuthority       string
	ServerAuthorityKey    string
	ServerIdentity        string
	ServerLock            string
	RunDir                string
	AgentEndpoint         string
	ServerAdminEndpoint   string
	ServerAdapterEndpoint string
}

func Resolve(override string) (Paths, error) {
	root := override
	if root == "" {
		root = os.Getenv(EnvHome)
	}
	if root == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		root = filepath.Join(configDir, "px")
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve PX home %q: %w", root, err)
	}
	root = filepath.Clean(root)
	agentDir := filepath.Join(root, "agent")
	serverDir := filepath.Join(root, "server")
	runDir := filepath.Join(root, "run")

	return Paths{
		Root:                  root,
		AgentDir:              agentDir,
		AgentConfig:           filepath.Join(agentDir, "config.yaml"),
		AgentDatabase:         filepath.Join(agentDir, "state.db"),
		AgentKeys:             filepath.Join(agentDir, "keys"),
		AgentTransfers:        filepath.Join(agentDir, "transfers"),
		AgentLock:             filepath.Join(agentDir, "agent.lock"),
		ServerDir:             serverDir,
		ServerConfig:          filepath.Join(serverDir, "config.yaml"),
		ServerDatabase:        filepath.Join(serverDir, "state.db"),
		ServerAuthority:       filepath.Join(serverDir, "authority"),
		ServerAuthorityKey:    filepath.Join(serverDir, "authority", "authority.key"),
		ServerIdentity:        filepath.Join(serverDir, "authority", "server.pub"),
		ServerLock:            filepath.Join(serverDir, "server.lock"),
		RunDir:                runDir,
		AgentEndpoint:         localEndpoint(root, runDir, "agent"),
		ServerAdminEndpoint:   localEndpoint(root, runDir, "server-admin"),
		ServerAdapterEndpoint: localEndpoint(root, runDir, "server-adapter"),
	}, nil
}

func (p Paths) EnsureAgent() error {
	if err := makePrivateDirs(p.Root, p.AgentDir, p.AgentKeys, p.AgentTransfers, p.RunDir); err != nil {
		return err
	}
	return ensurePrivateEndpointDir(filepath.Dir(p.AgentEndpoint))
}

func (p Paths) EnsureServer() error {
	if err := makePrivateDirs(p.Root, p.ServerDir, p.ServerAuthority, p.RunDir); err != nil {
		return err
	}
	if err := ensurePrivateEndpointDir(filepath.Dir(p.ServerAdminEndpoint)); err != nil {
		return err
	}
	return ensurePrivateEndpointDir(filepath.Dir(p.ServerAdapterEndpoint))
}

func makePrivateDirs(paths ...string) error {
	for _, path := range paths {
		if err := EnsurePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

// EnsurePrivateDirectory creates missing path components as private directories
// without requiring the nearest existing creation parent to be confidential.
func EnsurePrivateDirectory(path string) error {
	missing := make([]string, 0, 4)
	current := path
	for {
		_, err := os.Lstat(current)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect private directory %q: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("locate existing parent for private directory %q", path)
		}
		current = parent
	}

	if len(missing) == 0 {
		if err := privatedir.Ensure(path); err != nil {
			return fmt.Errorf("ensure private directory %q: %w", path, err)
		}
		return nil
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := privatedir.Ensure(missing[i]); err != nil {
			return fmt.Errorf("ensure private directory %q: %w", missing[i], err)
		}
	}
	return nil
}

func localEndpoint(root, runDir, name string) string {
	if runtime.GOOS != "windows" {
		endpoint := filepath.Join(runDir, name+".sock")
		if len(endpoint) <= 90 {
			return endpoint
		}
		sum := sha256.Sum256([]byte(filepath.Clean(root)))
		return filepath.Join(os.TempDir(), "px-"+hex.EncodeToString(sum[:8]), name+".sock")
	}
	sum := sha256.Sum256([]byte(filepath.Clean(root) + "\x00" + name))
	return `\\.\pipe\px-` + name + "-" + hex.EncodeToString(sum[:8])
}

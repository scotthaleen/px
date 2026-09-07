package startup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestBuildPlan(t *testing.T) {
	for _, test := range []struct {
		goos       string
		userHome   string
		executable string
		pxHome     string
		wantHome   string
	}{
		{goos: "linux", userHome: "/home/alice", executable: "/opt/PX App/px", pxHome: "/state/px", wantHome: "/state/px"},
		{goos: "darwin", userHome: "/Users/alice", executable: "/Applications/PX App/px", pxHome: "/state/px", wantHome: "/state/px"},
		{goos: "windows", userHome: `C:\Users\alice`, executable: `C:\Program Files\PX\px.exe`, pxHome: `D:\state\px`, wantHome: `D:\state\px`},
	} {
		t.Run(test.goos, func(t *testing.T) {
			plan, err := BuildPlan(test.goos, test.userHome, test.executable, test.pxHome, 501)
			if err != nil {
				t.Fatal(err)
			}
			for action, commands := range map[string][]Command{"install": plan.Install, "upgrade": plan.Upgrade, "start": plan.Start, "stop": plan.Stop, "restart": plan.Restart, "status": plan.Status, "uninstall": plan.Uninstall} {
				if len(commands) == 0 {
					t.Fatalf("%s plan is empty", action)
				}
				for _, command := range commands {
					if strings.ContainsAny(command.Name, " \t") || slices.Contains(command.Args, "") {
						t.Fatalf("command must not use a shell: %#v", command)
					}
				}
			}
			if test.goos == "windows" {
				wantStatus := []string{"-NoProfile", "-NonInteractive", "-Command", windowsTaskStateScript()}
				if plan.Artifact != nil || !slices.Contains(plan.Install[0].Args, "LIMITED") || len(plan.Status) != 1 || plan.Status[0].Name != "powershell.exe" || !slices.Equal(plan.Status[0].Args, wantStatus) {
					t.Fatalf("unexpected Windows plan: %#v", plan)
				}
				if !slices.Contains(plan.Arguments, test.wantHome) || !strings.Contains(plan.Directories[0], `AppData\Local\PX\Logs`) {
					t.Fatalf("unexpected Windows paths: %#v", plan)
				}
				return
			}
			if plan.Artifact == nil || plan.Artifact.Mode != 0o600 {
				t.Fatalf("unexpected artifact: %#v", plan.Artifact)
			}
			content := string(plan.Artifact.Data)
			for _, value := range []string{"PX App", "agent", "run", test.wantHome} {
				if !strings.Contains(content, value) {
					t.Fatalf("artifact does not contain %q:\n%s", value, content)
				}
			}
		})
	}
}

func TestBuildPlanRejectsUnsafePaths(t *testing.T) {
	for _, value := range []string{"relative", "/absolute\noption"} {
		if _, err := BuildPlan("linux", "/home/alice", value, "/state", 1000); err == nil {
			t.Fatalf("unsafe path %q succeeded", value)
		}
	}
	if _, err := BuildPlan("plan9", "/home/alice", "/bin/px", "/state", 1000); err == nil {
		t.Fatal("unsupported platform succeeded")
	}
	if _, err := BuildPlan("windows", `\Users\alice`, `C:\PX\px.exe`, `C:\state`, 0); err == nil {
		t.Fatal("drive-relative Windows path succeeded")
	}
}

func TestActivateReloadsVerifiedDefinitionWithoutRewriting(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			userHome, executable, pxHome := "/home/alice", "/opt/px", "/state/px"
			if goos == "darwin" {
				userHome = "/Users/alice"
			}
			if goos == "windows" {
				userHome, executable, pxHome = `C:\Users\alice`, `C:\PX\px.exe`, `C:\state\px`
			}
			plan, err := BuildPlan(goos, userHome, executable, pxHome, 501)
			if err != nil {
				t.Fatal(err)
			}
			runner := &recordingRunner{}
			if _, err := Activate(t.Context(), plan, runner); err != nil {
				t.Fatal(err)
			}
			want := plan.Start
			if goos == "linux" {
				want = append([]Command{{Name: "systemctl", Args: []string{"--user", "daemon-reload"}}}, plan.Start...)
			} else if goos == "darwin" {
				want = plan.Upgrade
			}
			if !slices.EqualFunc(runner.commands, want, func(a, b Command) bool {
				return a.Name == b.Name && slices.Equal(a.Args, b.Args) && a.IgnoreFailure == b.IgnoreFailure
			}) {
				t.Fatalf("activation commands = %#v, want %#v", runner.commands, want)
			}
		})
	}
}

func TestExecuteLifecycleAndInspect(t *testing.T) {
	root := t.TempDir()
	plan := Plan{
		OS:          "test",
		Artifact:    &Artifact{Path: filepath.Join(root, "startup.conf"), Data: []byte("startup"), Mode: 0o600},
		Directories: []string{filepath.Join(root, "logs")},
		Install:     []Command{{Name: "manager", Args: []string{"install"}}},
		Upgrade:     []Command{{Name: "manager", Args: []string{"upgrade"}}},
		Uninstall:   []Command{{Name: "manager", Args: []string{"uninstall"}}},
	}
	runner := &recordingRunner{}
	if _, err := Execute(context.Background(), plan, "install", runner); err != nil {
		t.Fatal(err)
	}
	if got, want := len(runner.commands), len(plan.Install); got != want {
		t.Fatalf("commands = %d, want %d", got, want)
	}
	if status, detail := Inspect(plan); status != "pass" {
		t.Fatalf("inspection = %s: %s", status, detail)
	}
	info, err := os.Stat(plan.Artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode = %v", info.Mode())
	}
	for _, directory := range plan.Directories {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("directory mode = %v", info.Mode())
		}
	}
	if err := os.WriteFile(plan.Artifact.Path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, _ := Inspect(plan); status != "fail" {
		t.Fatalf("stale inspection = %s", status)
	}
	if _, err := Execute(context.Background(), plan, "upgrade", runner); err != nil {
		t.Fatal(err)
	}
	if status, _ := Inspect(plan); status != "pass" {
		t.Fatalf("upgraded inspection = %s", status)
	}
	if _, err := Execute(context.Background(), plan, "uninstall", runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plan.Artifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact remains after uninstall: %v", err)
	}
	if status, _ := Inspect(plan); status != "skipped" {
		t.Fatalf("uninstalled inspection = %s", status)
	}
}

func TestExecuteStopsOnRequiredCommandFailure(t *testing.T) {
	plan := Plan{Install: []Command{{Name: "manager", Args: []string{"prepare"}}, {Name: "manager", Args: []string{"install"}}}}
	runner := &recordingRunner{errAt: 2}
	if _, err := Execute(context.Background(), plan, "install", runner); err == nil {
		t.Fatal("required command failure succeeded")
	}
	if _, err := Execute(context.Background(), plan, "invalid", runner); err == nil {
		t.Fatal("invalid action succeeded")
	}
}

func TestExecuteDarwinStatusRequiresRunningJob(t *testing.T) {
	plan := Plan{OS: "darwin", Status: []Command{{Name: "launchctl", Args: []string{"print", "gui/501/com.scotthaleen.px.agent"}}}}
	for _, test := range []struct {
		name      string
		output    string
		wantError string
	}{
		{name: "running", output: "\tstate = running\n"},
		{name: "stopped", output: "\tstate = not running\n", wantError: "not running"},
		{name: "nested running", output: "\tstate = not running\n\tchild = {\n\t\tstate = running\n\t}\n", wantError: "not running"},
		{name: "missing state", output: "\tactive count = 0\n", wantError: "unable to determine"},
		{name: "duplicate state", output: "\tstate = running\n\tstate = not running\n", wantError: "unable to determine"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingRunner{output: []byte(test.output)}
			_, err := Execute(context.Background(), plan, "status", runner)
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("status error = %v", err)
			}
		})
	}
}

func TestInspectWindowsTask(t *testing.T) {
	plan, err := BuildPlan("windows", `C:\Users\alice`, `C:\Program Files\PX\px.exe`, `C:\Users\alice\PX`, 0)
	if err != nil {
		t.Fatal(err)
	}
	plan.UserIDs = []string{`S-1-5-21-1000`, `WORKSTATION\alice`}
	definition := windowsTaskXML(plan, `S-1-5-21-1000`)
	runner := &recordingRunner{output: []byte(definition)}
	if status, detail := InspectRuntime(context.Background(), plan, runner); status != "pass" {
		t.Fatalf("inspection = %s: %s", status, detail)
	}
	runner = &recordingRunner{output: []byte(strings.Replace(definition, "<RunLevel>LeastPrivilege</RunLevel>", "", 1))}
	if status, detail := InspectRuntime(context.Background(), plan, runner); status != "pass" {
		t.Fatalf("default run-level inspection = %s: %s", status, detail)
	}
	runner = &recordingRunner{output: utf16XML(strings.Replace(definition, `encoding="UTF-8"`, `encoding="UTF-16"`, 1))}
	if status, detail := InspectRuntime(context.Background(), plan, runner); status != "pass" {
		t.Fatalf("UTF-16 inspection = %s: %s", status, detail)
	}
	nativeDefinition := strings.Replace(definition, `encoding="UTF-8"`, `encoding="UTF-16"`, 1)
	nativeDefinition = strings.Replace(nativeDefinition, "<RunLevel>LeastPrivilege</RunLevel>", "", 1)
	runner = &recordingRunner{output: []byte(nativeDefinition)}
	if status, detail := InspectRuntime(context.Background(), plan, runner); status != "pass" {
		t.Fatalf("native declaration inspection = %s: %s", status, detail)
	}
	runner = &recordingRunner{output: append([]byte{0xef, 0xbb, 0xbf}, []byte(definition)...)}
	if status, detail := InspectRuntime(context.Background(), plan, runner); status != "pass" {
		t.Fatalf("UTF-8 BOM inspection = %s: %s", status, detail)
	}
	for _, raw := range []string{
		strings.Replace(definition, `<?xml version="1.0" encoding="UTF-8"?>`, `<?xml version="1.1"?>`, 1),
		strings.Replace(definition, `<?xml version="1.0" encoding="UTF-8"?>`, `<?xml garbage?>`, 1),
		" \n<?xml garbage?>" + strings.Replace(definition, `<?xml version="1.0" encoding="UTF-8"?>`, "", 1),
		strings.Replace(definition, `<?xml version="1.0" encoding="UTF-8"?>`, `<?XML garbage?>`, 1),
		definition + "<Other/>",
		definition + "broken trailing content",
		"\v" + definition,
		definition + "\f",
	} {
		runner = &recordingRunner{output: []byte(raw)}
		if status, _ := InspectRuntime(context.Background(), plan, runner); status != "fail" {
			t.Fatalf("unsupported declaration inspection = %s", status)
		}
	}
	runner = &recordingRunner{output: utf16XML(definition)}
	if status, _ := InspectRuntime(context.Background(), plan, runner); status != "fail" {
		t.Fatalf("mismatched UTF-16 declaration inspection = %s", status)
	}
	for name, changed := range map[string]string{
		"elevated":           strings.Replace(definition, "LeastPrivilege", "HighestAvailable", 1),
		"wrong trigger":      strings.ReplaceAll(definition, "LogonTrigger", "BootTrigger"),
		"wrong command":      strings.Replace(definition, html.EscapeString(plan.Arguments[0]), `C:\Other\px.exe`, 1),
		"wrong user":         strings.ReplaceAll(definition, `S-1-5-21-1000`, `S-1-5-21-2000`),
		"wrong trigger user": strings.Replace(definition, `<UserId>S-1-5-21-1000</UserId>`, `<UserId>S-1-5-21-2000</UserId>`, 1),
		"malformed XML":      "not XML",
	} {
		t.Run(name, func(t *testing.T) {
			runner := &recordingRunner{output: []byte(changed)}
			if status, _ := InspectRuntime(context.Background(), plan, runner); status != "fail" {
				t.Fatalf("mismatched inspection = %s", status)
			}
		})
	}
	for name, changed := range map[string]string{
		"disabled trigger":  strings.Replace(definition, "<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 1),
		"disabled settings": strings.Replace(definition, "<Settings><Enabled>true</Enabled>", "<Settings><Enabled>false</Enabled>", 1),
	} {
		t.Run(name, func(t *testing.T) {
			runner := &recordingRunner{output: []byte(changed)}
			if status, detail := InspectRuntime(t.Context(), plan, runner); status != "fail" || detail != errWindowsTaskDisabled.Error() {
				t.Fatalf("disabled inspection = %s: %s", status, detail)
			}
		})
	}
	runner = &recordingRunner{output: []byte("ERROR: The system cannot find the file specified."), err: errors.New("exit status 1")}
	if status, _ := InspectRuntime(context.Background(), plan, runner); status != "skipped" {
		t.Fatalf("missing inspection = %s", status)
	}
	runner = &recordingRunner{output: utf16XML("ERROR: The specified task name does not exist in the system."), err: errors.New("exit status 1")}
	if status, _ := InspectRuntime(context.Background(), plan, runner); status != "skipped" {
		t.Fatalf("UTF-16 missing inspection = %s", status)
	}
	runner = &recordingRunner{output: []byte("ERROR: Access is denied."), err: errors.New("exit status 1")}
	if status, _ := InspectRuntime(context.Background(), plan, runner); status != "fail" {
		t.Fatalf("unreadable inspection = %s", status)
	}
}

func TestExecuteWindowsStatusRequiresRunningTask(t *testing.T) {
	plan, err := BuildPlan("windows", `C:\Users\alice`, `C:\Program Files\PX\px.exe`, `C:\Users\alice\PX`, 0)
	if err != nil {
		t.Fatal(err)
	}
	plan.UserIDs = []string{`S-1-5-21-1000`}
	definition := windowsTaskXML(plan, plan.UserIDs[0])
	for _, test := range []struct {
		name, state, wantError string
	}{
		{name: "running", state: "4"},
		{name: "ready", state: "3", wantError: "installed but not running"},
		{name: "queued", state: "2", wantError: "queued but not running"},
		{name: "disabled", state: "1", wantError: "disabled"},
		{name: "unknown", state: "0", wantError: "unable to determine"},
		{name: "unrecognized", state: "5", wantError: "unable to determine"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{responses: []runnerResponse{{output: []byte(definition)}, {output: []byte(test.state)}}}
			_, err := Execute(t.Context(), plan, "status", runner)
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("status error = %v", err)
			}
			if len(runner.commands) != 2 || runner.commands[1].Name != "powershell.exe" {
				t.Fatalf("status commands = %#v", runner.commands)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		runner := &scriptedRunner{responses: []runnerResponse{{output: []byte("ERROR: The system cannot find the file specified."), err: errors.New("exit status 1")}}}
		if _, err := Execute(t.Context(), plan, "status", runner); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Fatalf("status error = %v", err)
		}
	})
	t.Run("stale", func(t *testing.T) {
		runner := &scriptedRunner{responses: []runnerResponse{{output: []byte(strings.Replace(definition, "LeastPrivilege", "HighestAvailable", 1))}}}
		if _, err := Execute(t.Context(), plan, "status", runner); err == nil || !strings.Contains(err.Error(), "stale or mismatched") {
			t.Fatalf("status error = %v", err)
		}
	})
	t.Run("inaccessible", func(t *testing.T) {
		runner := &scriptedRunner{responses: []runnerResponse{{output: []byte("ERROR: Access is denied."), err: errors.New("exit status 1")}}}
		if _, err := Execute(t.Context(), plan, "status", runner); err == nil || !strings.Contains(err.Error(), "could not be inspected") {
			t.Fatalf("status error = %v", err)
		}
	})
	t.Run("state inaccessible", func(t *testing.T) {
		runner := &scriptedRunner{responses: []runnerResponse{{output: []byte(definition)}, {output: []byte("redacted failure"), err: errors.New("exit status 1")}}}
		if _, err := Execute(t.Context(), plan, "status", runner); err == nil || !strings.Contains(err.Error(), "state could not be inspected") {
			t.Fatalf("status error = %v", err)
		}
	})
}

func TestWindowsCommandRoundTrip(t *testing.T) {
	want := []string{`C:\Program Files\PX\px.exe`, "--home", `C:\state with spaces\`, `quote"value`}
	got, err := splitWindowsCommandLine(windowsCommand(want))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("arguments = %#v, want %#v", got, want)
	}
}

func windowsTaskXML(plan Plan, userID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="%s">
  <Triggers><LogonTrigger><UserId>%s</UserId><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions>
</Task>`, taskSchedulerNamespace, html.EscapeString(userID), html.EscapeString(userID), html.EscapeString(plan.Arguments[0]), html.EscapeString(windowsCommand(plan.Arguments[1:])))
}

func utf16XML(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	result := make([]byte, 2+len(encoded)*2)
	result[0], result[1] = 0xff, 0xfe
	for index, character := range encoded {
		binary.LittleEndian.PutUint16(result[2+index*2:], character)
	}
	return result
}

type recordingRunner struct {
	commands []Command
	errAt    int
	output   []byte
	err      error
}

type runnerResponse struct {
	output []byte
	err    error
}

type scriptedRunner struct {
	commands  []Command
	responses []runnerResponse
}

func (runner *scriptedRunner) Run(_ context.Context, command Command) ([]byte, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.responses) == 0 {
		return nil, errors.New("unexpected command")
	}
	response := runner.responses[0]
	runner.responses = runner.responses[1:]
	return response.output, response.err
}

func (runner *recordingRunner) Run(_ context.Context, command Command) ([]byte, error) {
	runner.commands = append(runner.commands, command)
	if runner.err != nil {
		return runner.output, runner.err
	}
	if runner.errAt > 0 && len(runner.commands) == runner.errAt {
		return []byte("redacted failure"), errors.New("failed")
	}
	if runner.output != nil {
		return runner.output, nil
	}
	return []byte("ok"), nil
}

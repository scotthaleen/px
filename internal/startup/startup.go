package startup

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	Label    = "com.scotthaleen.px.agent"
	TaskName = "PX Agent"
)

var errWindowsTaskDisabled = errors.New("startup task is disabled")

type Command struct {
	Name          string
	Args          []string
	IgnoreFailure bool
}

type Artifact struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type Plan struct {
	OS          string
	Arguments   []string
	UserIDs     []string
	Artifact    *Artifact
	Directories []string
	Install     []Command
	Upgrade     []Command
	Start       []Command
	Stop        []Command
	Restart     []Command
	Status      []Command
	Uninstall   []Command
	Cleanup     []Command
}

type Runner interface {
	Run(context.Context, Command) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	return exec.CommandContext(ctx, command.Name, command.Args...).CombinedOutput()
}

func BuildPlan(goos, userHome, executable, pxHome string, uid int) (Plan, error) {
	return buildPlan(goos, userHome, executable, pxHome, targetJoin(goos, userHome, "AppData", "Local"), uid)
}

func buildPlan(goos, userHome, executable, pxHome, localData string, uid int) (Plan, error) {
	if goos != "linux" && goos != "darwin" && goos != "windows" {
		return Plan{}, fmt.Errorf("unsupported startup platform %q", goos)
	}
	for label, value := range map[string]string{"user home": userHome, "executable": executable, "PX home": pxHome} {
		if !targetIsAbs(goos, value) || strings.ContainsAny(value, "\r\n\x00") {
			return Plan{}, fmt.Errorf("%s must be an absolute single-line path", label)
		}
	}
	arguments := []string{executable, "--home", pxHome, "agent", "run"}
	switch goos {
	case "linux":
		path := targetJoin(goos, userHome, ".config", "systemd", "user", "px-agent.service")
		data := []byte("[Unit]\nDescription=PX per-user agent\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=" + systemdCommand(arguments) + "\nRestart=on-failure\nRestartSec=5s\nUMask=0077\n\n[Install]\nWantedBy=default.target\n")
		return Plan{
			OS: goos, Arguments: arguments, Artifact: &Artifact{Path: path, Data: data, Mode: 0o600},
			Install:   []Command{{Name: "systemctl", Args: []string{"--user", "daemon-reload"}}, {Name: "systemctl", Args: []string{"--user", "enable", "--now", "px-agent.service"}}},
			Upgrade:   []Command{{Name: "systemctl", Args: []string{"--user", "daemon-reload"}}, {Name: "systemctl", Args: []string{"--user", "enable", "px-agent.service"}}, {Name: "systemctl", Args: []string{"--user", "restart", "px-agent.service"}}},
			Start:     []Command{{Name: "systemctl", Args: []string{"--user", "start", "px-agent.service"}}},
			Stop:      []Command{{Name: "systemctl", Args: []string{"--user", "stop", "px-agent.service"}}},
			Restart:   []Command{{Name: "systemctl", Args: []string{"--user", "restart", "px-agent.service"}}},
			Status:    []Command{{Name: "systemctl", Args: []string{"--user", "is-active", "px-agent.service"}}},
			Uninstall: []Command{{Name: "systemctl", Args: []string{"--user", "disable", "--now", "px-agent.service"}}},
			Cleanup:   []Command{{Name: "systemctl", Args: []string{"--user", "daemon-reload"}}},
		}, nil
	case "darwin":
		path := targetJoin(goos, userHome, "Library", "LaunchAgents", Label+".plist")
		logs := targetJoin(goos, userHome, "Library", "Logs", "PX")
		data := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>" + Label + "</string>\n<key>ProgramArguments</key><array>" + plistArguments(arguments) + "</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ProcessType</key><string>Background</string>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>" + html.EscapeString(targetJoin(goos, logs, "agent.log")) + "</string>\n<key>StandardErrorPath</key><string>" + html.EscapeString(targetJoin(goos, logs, "agent.log")) + "</string>\n</dict></plist>\n")
		target := "gui/" + strconv.Itoa(uid)
		service := target + "/" + Label
		return Plan{
			OS: goos, Arguments: arguments, Artifact: &Artifact{Path: path, Data: data, Mode: 0o600}, Directories: []string{logs},
			Install:   []Command{{Name: "launchctl", Args: []string{"bootout", target, path}, IgnoreFailure: true}, {Name: "launchctl", Args: []string{"bootstrap", target, path}}},
			Upgrade:   []Command{{Name: "launchctl", Args: []string{"bootout", target, path}, IgnoreFailure: true}, {Name: "launchctl", Args: []string{"bootstrap", target, path}}},
			Start:     []Command{{Name: "launchctl", Args: []string{"kickstart", service}}},
			Stop:      []Command{{Name: "launchctl", Args: []string{"kill", "SIGTERM", service}}},
			Restart:   []Command{{Name: "launchctl", Args: []string{"kickstart", "-k", service}}},
			Status:    []Command{{Name: "launchctl", Args: []string{"print", service}}},
			Uninstall: []Command{{Name: "launchctl", Args: []string{"bootout", target, path}}},
		}, nil
	case "windows":
		if !targetIsAbs(goos, localData) || strings.ContainsAny(localData, "\r\n\x00") {
			return Plan{}, errors.New("local application data must be an absolute single-line path")
		}
		logs := targetJoin(goos, localData, "PX", "Logs")
		arguments = append(arguments, "--log-file", targetJoin(goos, logs, "agent.log"))
		commandLine := windowsCommand(arguments)
		base := []string{"/TN", TaskName}
		return Plan{
			OS:          goos,
			Arguments:   arguments,
			Directories: []string{logs},
			Install:     []Command{{Name: "schtasks.exe", Args: append([]string{"/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", commandLine}, base...)}, {Name: "schtasks.exe", Args: append([]string{"/End"}, base...), IgnoreFailure: true}, {Name: "schtasks.exe", Args: append([]string{"/Run"}, base...)}},
			Upgrade:     []Command{{Name: "schtasks.exe", Args: append([]string{"/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", commandLine}, base...)}, {Name: "schtasks.exe", Args: append([]string{"/End"}, base...), IgnoreFailure: true}, {Name: "schtasks.exe", Args: append([]string{"/Run"}, base...)}},
			Start:       []Command{{Name: "schtasks.exe", Args: append([]string{"/Run"}, base...)}},
			Stop:        []Command{{Name: "schtasks.exe", Args: append([]string{"/End"}, base...)}},
			Restart:     []Command{{Name: "schtasks.exe", Args: append([]string{"/End"}, base...), IgnoreFailure: true}, {Name: "schtasks.exe", Args: append([]string{"/Run"}, base...)}},
			Status:      []Command{{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command", windowsTaskStateScript()}}},
			Uninstall:   []Command{{Name: "schtasks.exe", Args: append([]string{"/End"}, base...), IgnoreFailure: true}, {Name: "schtasks.exe", Args: append([]string{"/Delete", "/F"}, base...)}},
		}, nil
	}
	panic("unreachable")
}

func CurrentPlan(pxHome string) (Plan, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return Plan{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return Plan{}, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return Plan{}, err
	}
	localData := filepath.Join(userHome, "AppData", "Local")
	if runtime.GOOS == "windows" {
		localData, err = os.UserCacheDir()
		if err != nil {
			return Plan{}, err
		}
	}
	plan, err := buildPlan(runtime.GOOS, userHome, executable, pxHome, localData, currentUID())
	if err != nil {
		return Plan{}, err
	}
	if runtime.GOOS == "windows" {
		current, userErr := user.Current()
		if userErr != nil {
			return Plan{}, fmt.Errorf("resolve current user: %w", userErr)
		}
		plan.UserIDs = compactStrings(current.Uid, current.Username)
	}
	return plan, nil
}

func Execute(ctx context.Context, plan Plan, action string, runner Runner) (string, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	if action == "status" && plan.OS == "windows" {
		return executeWindowsStatus(ctx, plan, runner)
	}
	if action == "install" || action == "upgrade" {
		for _, directory := range plan.Directories {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				return "", err
			}
			if err := os.Chmod(directory, 0o700); err != nil {
				return "", err
			}
		}
		if plan.Artifact != nil {
			if err := writeArtifact(*plan.Artifact); err != nil {
				return "", err
			}
		}
	}
	commands, err := commandsFor(plan, action)
	if err != nil {
		return "", err
	}
	var output []byte
	for _, command := range commands {
		value, runErr := runner.Run(ctx, command)
		output = value
		if runErr != nil && !command.IgnoreFailure {
			return string(value), fmt.Errorf("%s startup command failed: %w", action, runErr)
		}
	}
	if action == "status" && plan.OS == "darwin" {
		state, ok := launchdState(string(output))
		if !ok {
			return string(output), errors.New("unable to determine per-user startup state")
		}
		if state != "running" {
			return string(output), errors.New("per-user startup is loaded but not running")
		}
	}
	if action == "uninstall" && plan.Artifact != nil {
		if err := os.Remove(plan.Artifact.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return string(output), err
		}
	}
	if action == "uninstall" {
		for _, command := range plan.Cleanup {
			value, runErr := runner.Run(ctx, command)
			output = value
			if runErr != nil && !command.IgnoreFailure {
				return string(value), fmt.Errorf("%s startup cleanup failed: %w", action, runErr)
			}
		}
	}
	return strings.TrimSpace(string(output)), nil
}

// Activate reloads an already verified definition and starts it without
// rewriting the startup artifact.
func Activate(ctx context.Context, plan Plan, runner Runner) (string, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	commands := plan.Start
	switch plan.OS {
	case "linux":
		commands = append([]Command{{Name: "systemctl", Args: []string{"--user", "daemon-reload"}}}, plan.Start...)
	case "darwin":
		if plan.Artifact == nil || len(plan.Upgrade) < 2 {
			return "", errors.New("macOS startup activation plan is incomplete")
		}
		commands = plan.Upgrade
	case "windows":
	default:
		return "", fmt.Errorf("unsupported startup platform %q", plan.OS)
	}
	var output []byte
	for _, command := range commands {
		value, err := runner.Run(ctx, command)
		output = value
		if err != nil && !command.IgnoreFailure {
			return string(value), fmt.Errorf("start startup command failed: %w", err)
		}
	}
	return strings.TrimSpace(string(output)), nil
}

func launchdState(output string) (string, bool) {
	state := ""
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "\tstate = ") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		if state != "" {
			return "", false
		}
		state = strings.TrimPrefix(line, "\tstate = ")
	}
	return state, state != ""
}

func executeWindowsStatus(ctx context.Context, plan Plan, runner Runner) (string, error) {
	status, detail := InspectRuntime(ctx, plan, runner)
	if status != "pass" {
		return "", errors.New(detail)
	}
	if len(plan.Status) != 1 {
		return "", errors.New("Windows startup status plan is incomplete")
	}
	output, err := runner.Run(ctx, plan.Status[0])
	if err != nil {
		return string(output), errors.New("startup task state could not be inspected")
	}
	decoded, err := decodeWindowsText(output)
	if err != nil {
		return string(output), errors.New("unable to determine per-user startup state")
	}
	switch strings.TrimSpace(string(decoded)) {
	case "1":
		return string(output), errWindowsTaskDisabled
	case "2":
		return string(output), errors.New("per-user startup is queued but not running")
	case "3":
		return string(output), errors.New("per-user startup is installed but not running")
	case "4":
		return strings.TrimSpace(string(decoded)), nil
	default:
		return string(output), errors.New("unable to determine per-user startup state")
	}
}

func windowsTaskStateScript() string {
	return "$ErrorActionPreference='Stop';$service=New-Object -ComObject 'Schedule.Service';$service.Connect();$task=$service.GetFolder('\\').GetTask('" + TaskName + "');[Console]::Out.Write([int]$task.State)"
}

func Inspect(plan Plan) (string, string) {
	if plan.Artifact == nil {
		return "skipped", "startup task is not inspected without the Windows task scheduler"
	}
	data, err := os.ReadFile(plan.Artifact.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "skipped", "per-user startup is not installed"
	}
	if err != nil {
		return "fail", "startup configuration is unreadable"
	}
	info, err := os.Stat(plan.Artifact.Path)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "fail", "startup configuration permissions are insecure"
	}
	if !bytes.Equal(data, plan.Artifact.Data) {
		return "fail", "startup configuration is stale or mismatched"
	}
	return "pass", "startup configuration matches this executable and PX home"
}

func InspectRuntime(ctx context.Context, plan Plan, runner Runner) (string, string) {
	if plan.OS != "windows" {
		return Inspect(plan)
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	output, err := runner.Run(ctx, Command{Name: "schtasks.exe", Args: []string{"/Query", "/TN", TaskName, "/XML"}})
	if err != nil {
		if taskNotFound(output) {
			return "skipped", "per-user startup is not installed"
		}
		return "fail", "startup task could not be inspected"
	}
	if err := validateWindowsTask(output, plan); err != nil {
		if errors.Is(err, errWindowsTaskDisabled) {
			return "fail", errWindowsTaskDisabled.Error()
		}
		return "fail", "startup task is stale or mismatched"
	}
	return "pass", "startup task matches this executable and PX home"
}

const taskSchedulerNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"

type scheduledTask struct {
	XMLName    xml.Name       `xml:"Task"`
	Principals taskPrincipals `xml:"Principals"`
	Triggers   taskTriggers   `xml:"Triggers"`
	Actions    taskActions    `xml:"Actions"`
	Settings   taskSettings   `xml:"Settings"`
}

type taskPrincipals struct {
	Principal []taskPrincipal `xml:"Principal"`
}

type taskPrincipal struct {
	ID        string `xml:"id,attr"`
	UserID    string `xml:"UserId"`
	GroupID   string `xml:"GroupId"`
	LogonType string `xml:"LogonType"`
	RunLevel  string `xml:"RunLevel"`
}

type taskTriggers struct {
	Logon []taskTrigger  `xml:"LogonTrigger"`
	Other []otherElement `xml:",any"`
}

type taskTrigger struct {
	Enabled *bool  `xml:"Enabled"`
	UserID  string `xml:"UserId"`
}

type taskActions struct {
	Context string         `xml:"Context,attr"`
	Exec    []taskExec     `xml:"Exec"`
	Other   []otherElement `xml:",any"`
}

type taskExec struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

type taskSettings struct {
	Enabled *bool `xml:"Enabled"`
}

type otherElement struct {
	XMLName xml.Name
}

func validateWindowsTask(data []byte, plan Plan) error {
	data, err := decodeWindowsText(data)
	if err != nil {
		return err
	}
	data = trimXMLSpace(data)
	if !bytes.HasPrefix(data, []byte("<Task")) {
		return errors.New("unexpected task document")
	}
	var task scheduledTask
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&task); err != nil {
		return err
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if content, ok := token.(xml.CharData); !ok || len(trimXMLSpace(content)) != 0 {
			return errors.New("unexpected trailing task document content")
		}
	}
	if task.XMLName.Space != taskSchedulerNamespace || len(task.Principals.Principal) != 1 || len(task.Triggers.Logon) != 1 || len(task.Triggers.Other) != 0 || len(task.Actions.Exec) != 1 || len(task.Actions.Other) != 0 {
		return errors.New("unexpected task structure")
	}
	principal := task.Principals.Principal[0]
	if principal.UserID == "" || principal.GroupID != "" || !strings.EqualFold(principal.LogonType, "InteractiveToken") || principal.RunLevel != "" && !strings.EqualFold(principal.RunLevel, "LeastPrivilege") {
		return errors.New("unexpected task principal")
	}
	if len(plan.UserIDs) > 0 && !containsFold(plan.UserIDs, principal.UserID) {
		return errors.New("task belongs to another user")
	}
	if task.Actions.Context != "" && principal.ID != "" && task.Actions.Context != principal.ID {
		return errors.New("action uses another principal")
	}
	if task.Triggers.Logon[0].Enabled != nil && !*task.Triggers.Logon[0].Enabled {
		return errWindowsTaskDisabled
	}
	if triggerUser := task.Triggers.Logon[0].UserID; triggerUser != "" && !strings.EqualFold(triggerUser, principal.UserID) {
		if len(plan.UserIDs) == 0 || !containsFold(plan.UserIDs, triggerUser) {
			return errors.New("logon trigger belongs to another user")
		}
	}
	if task.Settings.Enabled != nil && !*task.Settings.Enabled {
		return errWindowsTaskDisabled
	}
	action := task.Actions.Exec[0]
	command := strings.TrimSpace(action.Command)
	if len(command) >= 2 && command[0] == '"' && command[len(command)-1] == '"' {
		command = command[1 : len(command)-1]
	}
	if len(plan.Arguments) == 0 || !windowsPathEqual(command, plan.Arguments[0]) {
		return errors.New("task command is mismatched")
	}
	arguments, err := splitWindowsCommandLine(action.Arguments)
	if err != nil || !slicesEqual(arguments, plan.Arguments[1:]) {
		return errors.New("task arguments are mismatched")
	}
	return nil
}

func taskNotFound(output []byte) bool {
	decoded, err := decodeWindowsText(output)
	if err != nil {
		return false
	}
	message := strings.ToLower(string(decoded))
	return strings.Contains(message, "the system cannot find the file specified") || strings.Contains(message, "the specified task name") && strings.Contains(message, "does not exist")
}

func decodeWindowsText(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return stripXMLDeclaration(data[3:], true)
	}
	offset := 0
	var order binary.ByteOrder
	switch {
	case len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe:
		offset, order = 2, binary.LittleEndian
	case len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff:
		offset, order = 2, binary.BigEndian
	case len(data) >= 4 && data[0] == '<' && data[1] == 0 && data[2] == '?' && data[3] == 0:
		order = binary.LittleEndian
	case len(data) >= 4 && data[0] == 0 && data[1] == '<' && data[2] == 0 && data[3] == '?':
		order = binary.BigEndian
	default:
		return stripXMLDeclaration(data, true)
	}
	if (len(data)-offset)%2 != 0 {
		return nil, errors.New("odd-length UTF-16 output")
	}
	units := make([]uint16, (len(data)-offset)/2)
	for index := range units {
		units[index] = order.Uint16(data[offset+index*2:])
	}
	for index := 0; index < len(units); index++ {
		switch {
		case units[index] >= 0xd800 && units[index] <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return nil, errors.New("malformed UTF-16 output")
			}
			index++
		case units[index] >= 0xdc00 && units[index] <= 0xdfff:
			return nil, errors.New("malformed UTF-16 output")
		}
	}
	return stripXMLDeclaration([]byte(string(utf16.Decode(units))), false)
}

func stripXMLDeclaration(data []byte, utf8Bytes bool) ([]byte, error) {
	declarations := [][]byte{[]byte(`<?xml version="1.0" encoding="UTF-16"?>`)}
	if utf8Bytes {
		declarations = append(declarations, []byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	}
	for _, declaration := range declarations {
		if bytes.HasPrefix(data, declaration) {
			return data[len(declaration):], nil
		}
	}
	if bytes.HasPrefix(data, []byte("<?xml")) {
		return nil, errors.New("unsupported XML declaration")
	}
	return data, nil
}

func trimXMLSpace(data []byte) []byte {
	start, end := 0, len(data)
	for start < end && isXMLSpace(data[start]) {
		start++
	}
	for end > start && isXMLSpace(data[end-1]) {
		end--
	}
	return data[start:end]
}

func isXMLSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func targetIsAbs(goos, value string) bool {
	if goos != "windows" {
		return strings.HasPrefix(value, "/")
	}
	if len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && isPathSeparator(value[2]) {
		return true
	}
	return len(value) >= 5 && isPathSeparator(value[0]) && isPathSeparator(value[1]) && !isPathSeparator(value[2])
}

func targetJoin(goos string, elements ...string) string {
	if goos != "windows" {
		return path.Join(elements...)
	}
	if len(elements) == 0 {
		return ""
	}
	result := strings.TrimRight(elements[0], `\/`)
	for _, element := range elements[1:] {
		value := strings.Trim(element, `\/`)
		if value != "" {
			result += `\` + value
		}
	}
	return result
}

func isPathSeparator(value byte) bool { return value == '\\' || value == '/' }

func windowsPathEqual(a, b string) bool {
	normalize := func(value string) string { return strings.ReplaceAll(value, "/", `\`) }
	return strings.EqualFold(normalize(a), normalize(b))
}

func compactStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !containsFold(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func splitWindowsCommandLine(value string) ([]string, error) {
	var result []string
	for index := 0; index < len(value); {
		for index < len(value) && (value[index] == ' ' || value[index] == '\t') {
			index++
		}
		if index == len(value) {
			break
		}
		var argument strings.Builder
		quoted := false
		for index < len(value) {
			if !quoted && (value[index] == ' ' || value[index] == '\t') {
				break
			}
			backslashes := 0
			for index < len(value) && value[index] == '\\' {
				backslashes++
				index++
			}
			if index < len(value) && value[index] == '"' {
				argument.WriteString(strings.Repeat(`\`, backslashes/2))
				if backslashes%2 == 0 {
					quoted = !quoted
				} else {
					argument.WriteByte('"')
				}
				index++
				continue
			}
			argument.WriteString(strings.Repeat(`\`, backslashes))
			if index < len(value) {
				argument.WriteByte(value[index])
				index++
			}
		}
		if quoted {
			return nil, errors.New("unterminated quoted argument")
		}
		result = append(result, argument.String())
	}
	return result, nil
}

func commandsFor(plan Plan, action string) ([]Command, error) {
	switch action {
	case "install":
		return plan.Install, nil
	case "upgrade":
		return plan.Upgrade, nil
	case "start":
		return plan.Start, nil
	case "stop":
		return plan.Stop, nil
	case "restart":
		return plan.Restart, nil
	case "status":
		return plan.Status, nil
	case "uninstall":
		return plan.Uninstall, nil
	default:
		return nil, fmt.Errorf("unsupported startup action %q", action)
	}
}

func writeArtifact(artifact Artifact) error {
	if err := os.MkdirAll(filepath.Dir(artifact.Path), 0o700); err != nil {
		return err
	}
	temporary := artifact.Path + ".tmp"
	if err := os.WriteFile(temporary, artifact.Data, artifact.Mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, artifact.Mode); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, artifact.Path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func systemdCommand(arguments []string) string {
	values := make([]string, len(arguments))
	for index, value := range arguments {
		values[index] = "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%").Replace(value) + "\""
	}
	return strings.Join(values, " ")
}

func plistArguments(arguments []string) string {
	var result strings.Builder
	for _, value := range arguments {
		result.WriteString("<string>")
		result.WriteString(html.EscapeString(value))
		result.WriteString("</string>")
	}
	return result.String()
}

func windowsCommand(arguments []string) string {
	values := make([]string, len(arguments))
	for index, value := range arguments {
		values[index] = windowsQuote(value)
	}
	return strings.Join(values, " ")
}

func windowsQuote(value string) string {
	var result strings.Builder
	result.WriteByte('"')
	backslashes := 0
	for _, character := range value {
		if character == '\\' {
			backslashes++
			continue
		}
		if character == '"' {
			result.WriteString(strings.Repeat(`\`, backslashes*2+1))
			result.WriteByte('"')
			backslashes = 0
			continue
		}
		result.WriteString(strings.Repeat(`\`, backslashes))
		backslashes = 0
		result.WriteRune(character)
	}
	result.WriteString(strings.Repeat(`\`, backslashes*2))
	result.WriteByte('"')
	return result.String()
}

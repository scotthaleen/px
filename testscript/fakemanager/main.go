package main

import (
	"fmt"
	"html"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func main() {
	path := os.Getenv("PX_MANAGER_LOG")
	if path == "" {
		os.Exit(2)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, strings.Join(os.Args[1:], " ")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	manager := filepath.Base(os.Args[0])
	if manager == "launchctl" && len(os.Args) > 1 && os.Args[1] == "print" {
		fmt.Println("\tstate = running")
	}
	if strings.EqualFold(manager, "powershell.exe") {
		const stateScript = "$ErrorActionPreference='Stop';$service=New-Object -ComObject 'Schedule.Service';$service.Connect();$task=$service.GetFolder('\\').GetTask('PX Agent');[Console]::Out.Write([int]$task.State)"
		if len(os.Args) != 5 || os.Args[1] != "-NoProfile" || os.Args[2] != "-NonInteractive" || os.Args[3] != "-Command" || os.Args[4] != stateScript {
			os.Exit(2)
		}
		state, err := os.ReadFile(path + ".task-state")
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(string(state))
		return
	}
	if !strings.EqualFold(manager, "schtasks.exe") {
		return
	}
	taskPath := path + ".task"
	statePath := path + ".task-state"
	switch {
	case hasArg("/Create"):
		commandLine, ok := argValue("/TR")
		if !ok || os.WriteFile(taskPath, []byte(commandLine), 0o600) != nil || os.WriteFile(statePath, []byte("3"), 0o600) != nil {
			os.Exit(1)
		}
	case hasArg("/Run"):
		if _, err := os.Stat(taskPath); err != nil || os.WriteFile(statePath, []byte("4"), 0o600) != nil {
			os.Exit(1)
		}
	case hasArg("/End"):
		if _, err := os.Stat(taskPath); err == nil {
			if err := os.WriteFile(statePath, []byte("3"), 0o600); err != nil {
				os.Exit(1)
			}
		}
	case hasArg("/Delete"):
		_ = os.Remove(taskPath)
		_ = os.Remove(statePath)
	case hasArg("/Query") && hasArg("/XML"):
		commandLine, err := os.ReadFile(taskPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: The system cannot find the file specified.")
			os.Exit(1)
		}
		arguments, err := splitWindowsCommandLine(string(commandLine))
		if err != nil || len(arguments) == 0 {
			os.Exit(1)
		}
		current, err := user.Current()
		if err != nil {
			os.Exit(1)
		}
		userID := current.Uid
		if userID == "" {
			userID = current.Username
		}
		fmt.Printf(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><UserId>%s</UserId><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions>
</Task>`, html.EscapeString(userID), html.EscapeString(userID), html.EscapeString(arguments[0]), html.EscapeString(joinWindowsCommandLine(arguments[1:])))
	}
}

func hasArg(target string) bool {
	for _, argument := range os.Args[1:] {
		if strings.EqualFold(argument, target) {
			return true
		}
	}
	return false
}

func argValue(target string) (string, bool) {
	for index, argument := range os.Args[1:] {
		if strings.EqualFold(argument, target) && index+2 <= len(os.Args[1:]) {
			return os.Args[index+2], true
		}
	}
	return "", false
}

func joinWindowsCommandLine(arguments []string) string {
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		if argument != "" && !strings.ContainsAny(argument, " \t\"") {
			quoted[index] = argument
			continue
		}
		var value strings.Builder
		value.WriteByte('"')
		backslashes := 0
		for _, character := range argument {
			if character == '\\' {
				backslashes++
				continue
			}
			if character == '"' {
				value.WriteString(strings.Repeat(`\`, backslashes*2+1))
				value.WriteByte('"')
				backslashes = 0
				continue
			}
			value.WriteString(strings.Repeat(`\`, backslashes))
			backslashes = 0
			value.WriteRune(character)
		}
		value.WriteString(strings.Repeat(`\`, backslashes*2))
		value.WriteByte('"')
		quoted[index] = value.String()
	}
	return strings.Join(quoted, " ")
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
			return nil, fmt.Errorf("unterminated quoted argument")
		}
		result = append(result, argument.String())
	}
	return result, nil
}

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/scotthaleen/px/internal/membership"
	"github.com/spf13/cobra"
)

var peerCommands = []string{"ls", "get", "put", "send", "text", "recent", "ping", "benchmark", "doctor"}

const peerFirstGuidance = `valid forms: px "@PEER" COMMAND; supported commands: ls, get, put, send, text, recent, ping, benchmark, and doctor`

// RewritePXArgs translates peer-first syntax to the canonical command grammar.
// Keeping the translation at the process boundary lets all command handlers use
// the same context, alias, validation, and output paths.
func RewritePXArgs(args []string) ([]string, error) {
	if len(args) > 0 && (args[0] == cobra.ShellCompRequestCmd || args[0] == cobra.ShellCompNoDescRequestCmd) {
		rewritten, err := rewritePeerArgs(args[1:], true)
		if err != nil {
			return nil, err
		}
		return append([]string{args[0]}, rewritten...), nil
	}
	return rewritePeerArgs(args, false)
}

func rewritePeerArgs(args []string, completion bool) ([]string, error) {
	targetIndex, found, err := peerTargetIndex(args)
	if err != nil || !found {
		return append([]string(nil), args...), err
	}
	target := strings.TrimPrefix(args[targetIndex], "@")
	if target == "" && !completion {
		return nil, errors.New("peer target must be @LABEL")
	}
	if err := membership.ValidateLabel(target); err != nil && !completion {
		return nil, fmt.Errorf("peer target: %w", err)
	}
	prefix := append([]string(nil), args[:targetIndex]...)
	remainder := args[targetIndex+1:]
	if completion && len(remainder) == 0 {
		return append(append(prefix, "__peer_first"), args[targetIndex]), nil
	}
	if len(remainder) == 0 || completion && !isPeerCommand(remainder[0]) {
		if !completion {
			return nil, fmt.Errorf("command required after @PEER; %s", peerFirstGuidance)
		}
		if len(remainder) > 0 && strings.HasPrefix(remainder[0], "-") {
			return append(append(prefix, "__peer_first", "--"), remainder...), nil
		}
		return append(append(prefix, "__peer_first"), remainder...), nil
	}
	command := remainder[0]
	if !isPeerCommand(command) {
		return nil, fmt.Errorf("command %q does not support peer-first syntax; %s", command, peerFirstGuidance)
	}
	rest := remainder[1:]
	if command == "doctor" {
		for _, arg := range rest {
			if arg == "--peer" || strings.HasPrefix(arg, "--peer=") {
				return nil, errors.New("peer-first doctor cannot be combined with --peer")
			}
		}
		return append(append(prefix, command, "--peer", target), rest...), nil
	}
	if command == "recent" {
		filtered := make([]string, 0, len(rest))
		for _, arg := range rest {
			if arg != "--yes" {
				filtered = append(filtered, arg)
			}
		}
		return append(append(prefix, command, "--peer-target", target), filtered...), nil
	}
	return append(append(prefix, command, target), rest...), nil
}

func peerTargetIndex(args []string) (int, bool, error) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			if index+1 < len(args) && strings.HasPrefix(args[index+1], "@") {
				return 0, false, errors.New("peer-first target must appear before --")
			}
			return 0, false, nil
		}
		if takesGlobalValue(arg) {
			index++
			continue
		}
		if clusteredContextFlag(arg) == "separate" {
			index++
			continue
		}
		if isInlineGlobalValue(arg) || clusteredContextFlag(arg) == "inline" || isVerbosityFlag(arg) {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return 0, false, nil
		}
		return index, strings.HasPrefix(arg, "@"), nil
	}
	return 0, false, nil
}

func takesGlobalValue(arg string) bool {
	switch arg {
	case "--home", "--context", "-c", "--log-format":
		return true
	default:
		return false
	}
}

func isInlineGlobalValue(arg string) bool {
	return strings.HasPrefix(arg, "--home=") || strings.HasPrefix(arg, "--context=") || strings.HasPrefix(arg, "--log-format=") || strings.HasPrefix(arg, "-c=") || strings.HasPrefix(arg, "-c") && len(arg) > 2
}

func isVerbosityFlag(arg string) bool {
	if arg == "--verbose" || strings.HasPrefix(arg, "--verbose=") || strings.HasPrefix(arg, "-v=") {
		return true
	}
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	for _, value := range arg[1:] {
		if value != 'v' {
			return false
		}
	}
	return true
}

func clusteredContextFlag(arg string) string {
	if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' {
		return ""
	}
	for index := 1; index < len(arg); index++ {
		switch arg[index] {
		case 'v':
			continue
		case 'c':
			if index == len(arg)-1 {
				return "separate"
			}
			return "inline"
		default:
			return ""
		}
	}
	return ""
}

func isPeerCommand(value string) bool {
	for _, command := range peerCommands {
		if command == value {
			return true
		}
	}
	return false
}

func newPeerCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__peer_first",
		Hidden: true,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("internal peer completion command cannot be run directly")
		},
		ValidArgsFunction: func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			values := make([]string, 0, len(peerCommands))
			for _, name := range peerCommands {
				if strings.HasPrefix(name, toComplete) {
					values = append(values, name)
				}
			}
			return values, cobra.ShellCompDirectiveNoFileComp
		},
	}
}

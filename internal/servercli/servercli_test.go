package servercli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/serveradmin"
	"github.com/scotthaleen/px/internal/versioninfo"
)

func TestCommandConstruction(t *testing.T) {
	command := NewCommand(t.Context(), IOStreams{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard})
	if command.Use != "px-server" {
		t.Fatalf("Use = %q", command.Use)
	}
	want := []string{"adapters", "audit", "debug", "devices", "init", "invite", "serve", "status", "stop", "version"}
	for _, name := range want {
		if child, _, err := command.Find([]string{name}); err != nil || child.Name() != name {
			t.Fatalf("command %q missing: %v", name, err)
		}
	}
}

func TestRootHelpDoesNotAdvertiseAgentContextFlag(t *testing.T) {
	var output bytes.Buffer
	command := NewCommand(t.Context(), IOStreams{In: strings.NewReader(""), Out: &output, Err: &output})
	command.SetArgs([]string{"--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "--context") || !strings.Contains(output.String(), "--home") {
		t.Fatalf("unexpected px-server root help:\n%s", output.String())
	}
}

func TestVersionCommand(t *testing.T) {
	var stdout bytes.Buffer
	command := NewCommand(context.Background(), IOStreams{Out: &stdout, Err: io.Discard})
	command.SetArgs([]string{"version"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "px-server dev") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestAdapterEndpointDiscovery(t *testing.T) {
	home := filepath.Join(t.TempDir(), strings.Repeat("long-home-", 20))
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	command := NewCommand(t.Context(), IOStreams{In: strings.NewReader(""), Out: &stdout, Err: io.Discard})
	command.SetArgs([]string{"--home", home, "adapters", "endpoint", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version  int    `json:"version"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Version != serveradmin.Version || result.Endpoint != paths.ServerAdapterEndpoint {
		t.Fatalf("endpoint discovery = %+v, %v, want %q", result, err, paths.ServerAdapterEndpoint)
	}
}

func TestPlainStatusKeepsBuildMetadataOnOneLine(t *testing.T) {
	status := serveradmin.Status{Build: serveradmin.BuildStatus{Version: "version\ninjected", Commit: strings.Repeat("c", versioninfo.MaxBuildMetadataBytes+10), Date: `C:\\secret\\build`}}
	var output bytes.Buffer
	if err := writeStatus(&output, status); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 19 || lines[0] != "build_version\tinvalid" || len(strings.TrimPrefix(lines[1], "build_commit\t")) != versioninfo.MaxBuildMetadataBytes || lines[2] != "build_date\tinvalid" || strings.Contains(output.String(), "injected") || strings.Contains(output.String(), "secret") {
		t.Fatalf("unsafe plain status = %q", output.String())
	}
}

type failingCredentialOutput struct{ failAt string }

func (f *failingCredentialOutput) Write(data []byte) (int, error) {
	if f.failAt == "write" {
		return 0, errors.New("contains-sensitive-value")
	}
	return len(data), nil
}

func (f *failingCredentialOutput) Sync() error {
	if f.failAt == "sync" {
		return errors.New("contains-sensitive-value")
	}
	return nil
}

func (f *failingCredentialOutput) Close() error {
	if f.failAt == "close" {
		return errors.New("contains-sensitive-value")
	}
	return nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("contains-sensitive-value") }

func TestCredentialStdoutFailuresRequireRotationWithoutLeakage(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		result := serveradmin.AdapterProvisioning{AdapterStatus: serveradmin.AdapterStatus{Version: serveradmin.Version, AdapterID: "fixture", Active: true}, Credential: "sensitive-adapter-credential"}
		recovery := writeOneTimeCredential(failingWriter{}, result, jsonOutput, "rotate", result.AdapterID)
		if !strings.Contains(recovery.Error(), "rotate again") || strings.Contains(recovery.Error(), "sensitive") {
			t.Fatalf("unsafe recovery = %q", recovery)
		}
	}
}

func TestAdapterCredentialFailuresRequireRotationWithoutLeakage(t *testing.T) {
	for _, stage := range []string{"write", "sync", "close"} {
		if err := writeCredential(&failingCredentialOutput{failAt: stage}, "sensitive-adapter-credential"); err == nil {
			t.Fatalf("%s unexpectedly succeeded", stage)
		}
		err := credentialOutcomeUnknown("rotate", "fixture")
		if !strings.Contains(err.Error(), "rotate again") || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("unsafe recovery = %q", err)
		}
	}
	typed := &localipc.Error{Status: 409, Code: "adapter_capacity", Message: "capacity reached"}
	if got := classifyCredentialError("provision", "fixture", typed); got != typed {
		t.Fatalf("deterministic 4xx changed to %v", got)
	}
}

func TestRevocationConfirmation(t *testing.T) {
	member := membership.Member{DeviceID: "complete-device-id", Label: "build-vm", Revision: 7, CreatedAt: time.Unix(1, 0)}
	var output bytes.Buffer
	confirmed, err := confirmRevocation(bufio.NewReader(strings.NewReader("yes\n")), &output, member)
	if err != nil || !confirmed {
		t.Fatalf("confirmation = %v, %v", confirmed, err)
	}
	for _, want := range []string{"build-vm", "complete-device-id", "revision 7", "closes current presence", "[y/N]"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("confirmation missing %q: %q", want, output.String())
		}
	}
}

func TestInviteResponseValidationConfirmationAndUnknownOutcome(t *testing.T) {
	invite := serveradmin.Invite{
		InviteID: "000102030405060708090a0b0c0d0e0f", Label: "build-vm", IssuerType: "local",
		CreatedAt: "2026-07-31T10:00:00Z", ExpiresAt: "2026-07-31T11:00:00Z",
	}
	if err := validateInviteDTO(invite); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*serveradmin.Invite){
		"ID":     func(value *serveradmin.Invite) { value.InviteID = strings.ToUpper(value.InviteID) },
		"label":  func(value *serveradmin.Invite) { value.Label = "bad label" },
		"issuer": func(value *serveradmin.Invite) { value.IssuerDeviceID = "unexpected" },
		"time":   func(value *serveradmin.Invite) { value.CreatedAt = "2026-07-31T10:00:00+00:00" },
		"short":  func(value *serveradmin.Invite) { value.ExpiresAt = "2026-07-31T10:00:59Z" },
	} {
		invalid := invite
		mutate(&invalid)
		if err := validateInviteDTO(invalid); err == nil {
			t.Fatalf("invalid %s response accepted", name)
		}
	}
	var output bytes.Buffer
	confirmed, err := confirmInviteRevocation(bufio.NewReader(strings.NewReader("yes\n")), &output, invite)
	if err != nil || !confirmed || !strings.Contains(output.String(), invite.InviteID) || !strings.Contains(output.String(), "cannot be recovered") || !strings.Contains(output.String(), "[y/N]") {
		t.Fatalf("confirmation = %v, %v, %q", confirmed, err, output.String())
	}
	for _, action := range []string{"create", "revoke"} {
		err := inviteOutcomeUnknown(action, invite.InviteID)
		if !strings.Contains(err.Error(), "outcome_unknown") || strings.Contains(err.Error(), "PXI1") {
			t.Fatalf("unsafe unknown outcome = %q", err)
		}
	}
	for _, typed := range []*localipc.Error{
		{Status: 400, Code: "invalid_request", Message: "invalid invite request"},
		{Status: 409, Code: "invite_label_unavailable", Message: "invite label is unavailable"},
		{Status: 429, Code: "invite_capacity", Message: "invite capacity reached"},
	} {
		if got := classifyInviteMutationError("create", "", typed); got != typed {
			t.Fatalf("deterministic create error changed to %v", got)
		}
	}
	for _, typed := range []*localipc.Error{
		{Status: 400, Code: "invalid_request", Message: "invalid invite request"},
		{Status: 404, Code: "invite_unavailable", Message: "invite is unavailable"},
	} {
		if got := classifyInviteMutationError("revoke", invite.InviteID, typed); got != typed {
			t.Fatalf("deterministic revoke error changed to %v", got)
		}
	}
	for _, test := range []struct {
		action string
		err    *localipc.Error
	}{
		{"create", &localipc.Error{Status: 404, Code: "invite_unavailable", Message: "cross-operation"}},
		{"revoke", &localipc.Error{Status: 409, Code: "invite_label_unavailable", Message: "cross-operation"}},
		{"revoke", &localipc.Error{Status: 429, Code: "invite_capacity", Message: "cross-operation"}},
		{"revoke", &localipc.Error{Status: 408, Code: "invalid_request", Message: "timeout"}},
		{"revoke", &localipc.Error{Status: 400, Code: "unknown", Message: "unknown"}},
		{"revoke", &localipc.Error{Status: 400, Message: "malformed error body"}},
		{"revoke", &localipc.Error{Status: 409, Code: "invite_capacity", Message: "wrong status"}},
		{"revoke", &localipc.Error{Status: 418, Code: "invite_unavailable", Message: "unexpected status"}},
	} {
		got := classifyInviteMutationError(test.action, invite.InviteID, test.err)
		if got == test.err || !strings.Contains(got.Error(), "outcome_unknown") {
			t.Fatalf("uncertain invite error classified as deterministic: %v", got)
		}
	}
	mismatch := fmt.Errorf("request failed: %w", localipc.ErrServerAdminVersionMismatch)
	if got := classifyInviteMutationError("create", "", mismatch); got != mismatch || !errors.Is(got, localipc.ErrServerAdminVersionMismatch) || strings.Contains(got.Error(), "outcome_unknown") {
		t.Fatalf("protocol mismatch classification = %v", got)
	}
}

func TestInviteCreationValidationBindsLocalServerIdentityWithoutLeakage(t *testing.T) {
	const token = "PXI1.rh6byqCJAHY_6BGAarjaNA.000102030405060708090a0b0c0d0e0f.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
	result := serveradmin.InviteCreation{
		Version: serveradmin.InviteVersion,
		Invite: serveradmin.Invite{
			InviteID: "000102030405060708090a0b0c0d0e0f", Label: "Hal", IssuerType: "local",
			CreatedAt: "2026-07-31T10:00:00Z", ExpiresAt: "2026-07-31T11:00:00Z",
		},
		Token: token,
	}
	if err := validateInviteCreation(result, "server-id", "Hal", time.Hour); err != nil {
		t.Fatal(err)
	}
	for name, validate := range map[string]func() error{
		"server tag": func() error { return validateInviteCreation(result, "other-server", "Hal", time.Hour) },
		"label":      func() error { return validateInviteCreation(result, "server-id", "hal", time.Hour) },
		"lifetime":   func() error { return validateInviteCreation(result, "server-id", "Hal", 2*time.Hour) },
	} {
		if err := validate(); err == nil || strings.Contains(err.Error(), token) {
			t.Fatalf("%s validation error = %v", name, err)
		}
	}
}

func TestSuccessfulInviteRevocationOutputFailureIsPresentationOnly(t *testing.T) {
	result := serveradmin.InviteRevocation{
		Version: serveradmin.InviteVersion,
		State:   "revoked",
		Invite: serveradmin.Invite{
			InviteID: "000102030405060708090a0b0c0d0e0f", Label: "build-vm", IssuerType: "local",
			CreatedAt: "2026-07-31T10:00:00Z", ExpiresAt: "2026-07-31T11:00:00Z",
		},
	}
	for _, jsonOutput := range []bool{false, true} {
		err := writeInviteRevocationResult(failingWriter{}, result, jsonOutput)
		if err == nil || !strings.Contains(err.Error(), "write invite revocation result") || strings.Contains(err.Error(), "outcome_unknown") {
			t.Fatalf("json=%t presentation error = %v", jsonOutput, err)
		}
	}
}

func TestRevocationAndListAutomationGuards(t *testing.T) {
	command := newDevicesCommand(t.Context(), IOStreams{In: &bytes.Buffer{}, Out: io.Discard, Err: io.Discard}, &rootOptions{})
	command.SetArgs([]string{"revoke", "device-id", "--json"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("revocation error = %v", err)
	}
	command = newDevicesCommand(t.Context(), IOStreams{In: &bytes.Buffer{}, Out: io.Discard, Err: io.Discard}, &rootOptions{})
	command.SetArgs([]string{"list", "--all"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--all requires --active") {
		t.Fatalf("list error = %v", err)
	}
}

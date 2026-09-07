//go:build process

package testscript_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/stun/v3"
	"github.com/rogpeppe/go-internal/testscript"
	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/benchmark"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/offered"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/probe"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/rendezvous"
	"github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/serveradmin"
	"github.com/scotthaleen/px/internal/transfer"
)

var binaryDir string

func TestContextWatchProcessLifecycleAndCancellation(t *testing.T) {
	dir := t.TempDir()
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)

	homes := []string{filepath.Join(dir, "observer"), filepath.Join(dir, "peer")}
	labels := []string{"observer", "peer"}
	agents := make([]*exec.Cmd, 2)
	for index := range homes {
		offered, inbox := filepath.Join(homes[index], "offered"), filepath.Join(homes[index], "inbox")
		if err := os.MkdirAll(offered, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(inbox, 0o700); err != nil {
			t.Fatal(err)
		}
		agents[index] = startAgentProcess(t, ctx, homes[index])
		defer stopAgentProcess(agents[index])
		paths, err := apphome.Resolve(homes[index])
		if err != nil {
			t.Fatal(err)
		}
		waitAgentStatus(t, ctx, paths.AgentEndpoint)
	}
	joinAndApprove := func(index int) {
		t.Helper()
		output := runPXOutput(t, ctx, homes[index], "--context", "home", "join", "http://"+address, "--name", labels[index], "--offered-root", filepath.Join(homes[index], "offered"), "--inbox-root", filepath.Join(homes[index], "inbox"), "--no-stun", "--json")
		var joined contextstate.State
		if err := json.Unmarshal(output, &joined); err != nil || joined.PendingCode == "" {
			t.Fatalf("join %s = %+v, %v\n%s", labels[index], joined, err, output)
		}
		if approval, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", joined.PendingCode, "--json").CombinedOutput(); err != nil {
			t.Fatalf("approve %s: %v\n%s", labels[index], err, approval)
		}
		waitContextStates(t, ctx, homes[index], map[string]string{"home": "connected"})
	}
	joinAndApprove(0)

	watch, scanner, watchErrors := startWatchProcess(t, ctx, homes[0])
	initial := readWatchProcessEvent(t, scanner)
	if initial.Type != contextwatch.ContextConnected || !initial.Snapshot || len(initial.Peers) != 0 {
		t.Fatalf("initial watch = %+v", initial)
	}
	joinAndApprove(1)
	online := readWatchProcessEvent(t, scanner)
	if online.Type != contextwatch.PeerOnline || online.Peer == nil || online.Peer.Label != "peer" {
		t.Fatalf("online watch = %+v", online)
	}
	stopAgentProcess(agents[1])
	offline := readWatchProcessEvent(t, scanner)
	if offline.Type != contextwatch.PeerOffline || offline.Peer == nil || offline.Peer.DeviceID != online.Peer.DeviceID {
		t.Fatalf("offline watch = %+v", offline)
	}
	stopServerCommand(t, ctx, serverHome)
	disconnected := readWatchProcessEvent(t, scanner)
	if disconnected.Type != contextwatch.ContextDisconnected {
		t.Fatalf("disconnected watch = %+v", disconnected)
	}
	server = startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	reconnected := readWatchProcessEvent(t, scanner)
	if reconnected.Type != contextwatch.ContextConnected || len(reconnected.Peers) != 0 {
		t.Fatalf("reconnected watch = %+v", reconnected)
	}
	if runtime.GOOS != "windows" {
		if err := watch.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		if err := watch.Wait(); err != nil {
			t.Fatalf("watch Ctrl-C = %v, stderr=%s", err, watchErrors.String())
		}
	} else {
		stopAgentProcess(watch)
	}

	shutdownWatch, shutdownScanner, shutdownErrors := startWatchProcess(t, ctx, homes[0])
	if event := readWatchProcessEvent(t, shutdownScanner); event.Type != contextwatch.ContextConnected || !event.Snapshot {
		t.Fatalf("shutdown watch initial = %+v", event)
	}
	stopAgentCommand(t, ctx, homes[0])
	if err := shutdownWatch.Wait(); err == nil || !strings.Contains(shutdownErrors.String(), "ended unexpectedly") {
		t.Fatalf("watch after agent shutdown = %v, stderr=%s", err, shutdownErrors.String())
	}
}

func startWatchProcess(t *testing.T, ctx context.Context, home string) (*exec.Cmd, *bufio.Scanner, *bytes.Buffer) {
	t.Helper()
	command := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "home", "watch", "--json")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), localipc.MaxResponseBytes)
	return command, scanner, stderr
}

func readWatchProcessEvent(t *testing.T, scanner *bufio.Scanner) contextwatch.Event {
	t.Helper()
	if !scanner.Scan() {
		t.Fatalf("read watch event: %v", scanner.Err())
	}
	event, err := contextwatch.DecodeStrict(scanner.Bytes())
	if err != nil {
		t.Fatalf("decode watch event %q: %v", scanner.Bytes(), err)
	}
	return event
}

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "px-testscript-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for binary, source := range map[string]string{"px": "../cmd/px", "px-server": "../cmd/px-server", "fake-manager": "./fakemanager", "adapter-fixture": "./adapterfixture"} {
		output := filepath.Join(tmp, binary)
		if runtime.GOOS == "windows" {
			output += ".exe"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", output, source)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", binary, err)
			os.Exit(1)
		}
	}

	binaryDir = tmp
	code := m.Run()
	if err := os.RemoveAll(tmp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func TestEnrollmentAdapterProcessConformance(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, home, address, "--trusted-proxy", "127.0.0.1/32")
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)

	credentialFile := filepath.Join(t.TempDir(), "fixture.credential")
	provision := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "provision", "fixture", "--credential-file", credentialFile, "--json")
	if output, err := provision.CombinedOutput(); err != nil {
		t.Fatalf("provision adapter: %v\n%s", err, output)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(credentialFile)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("credential file mode = %v, %v", info, err)
		}
	}
	stateFile := filepath.Join(t.TempDir(), "fixture-state.json")
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentRequest := rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: "adapter-process"}
	var enrollment membership.Enrollment
	postHTTPJSON(t, ctx, "http://"+address+"/v1/enrollments", enrollmentRequest, &enrollment)
	if enrollment.State != "pending" {
		t.Fatalf("enrollment = %+v", enrollment)
	}

	state := runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", credentialFile, stateFile, "sync")
	if len(state.Pending) != 1 || len(state.AppliedFactIDs) != 1 || state.Cursor == 0 {
		t.Fatalf("initial fixture state = %+v", state)
	}
	var enrollmentID string
	for id := range state.Pending {
		enrollmentID = id
	}
	dropped := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", credentialFile, "--state", stateFile, "--enrollment", enrollmentID, "approve-drop")
	if output, err := dropped.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("outcome unknown")) {
		t.Fatalf("genuine dropped approval = %v\n%s", err, output)
	}
	state = runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", credentialFile, stateFile, "approve", "--enrollment", enrollmentID)
	if len(state.ProviderEffects) != 1 || state.LastCommandID == "" || state.PendingCommand != nil {
		t.Fatalf("dropped approval recovery = %+v", state)
	}
	exactCommandID := state.LastCommandID
	runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", credentialFile, stateFile, "conflict", "--command-id", exactCommandID, "--enrollment", strings.Repeat("0", 32))
	state = runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", credentialFile, stateFile, "sync")
	if len(state.Pending) != 0 || len(state.AppliedFactIDs) != 2 {
		t.Fatalf("restart catch-up state = %+v", state)
	}
	duplicateHighWater := state.Cursor
	state.Cursor, state.HighWater = 0, duplicateHighWater
	duplicateState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, append(duplicateState, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	state = runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", credentialFile, stateFile, "sync")
	if len(state.AppliedFactIDs) != 2 || len(state.ProviderEffects) != 1 {
		t.Fatalf("duplicate page changed effects = %+v", state)
	}
	postHTTPJSON(t, ctx, "http://"+address+"/v1/enrollments", enrollmentRequest, &enrollment)
	if enrollment.State != "enrolled" {
		t.Fatalf("adapter approval was not authoritative: %+v", enrollment)
	}

	firstDoorbellReady := filepath.Join(t.TempDir(), "first-doorbell.ready")
	firstDoorbell := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", credentialFile, "--state", stateFile, "--ready-file", firstDoorbellReady, "doorbell")
	var firstDoorbellOutput bytes.Buffer
	firstDoorbell.Stdout, firstDoorbell.Stderr = &firstDoorbellOutput, &firstDoorbellOutput
	if err := firstDoorbell.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, firstDoorbellReady)
	secondDoorbellReady := filepath.Join(t.TempDir(), "second-doorbell.ready")
	secondDoorbell := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", credentialFile, "--state", stateFile, "--ready-file", secondDoorbellReady, "doorbell")
	var secondDoorbellOutput bytes.Buffer
	secondDoorbell.Stdout, secondDoorbell.Stderr = &secondDoorbellOutput, &secondDoorbellOutput
	if err := secondDoorbell.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, secondDoorbellReady)
	if err := firstDoorbell.Wait(); err == nil || !bytes.Contains(firstDoorbellOutput.Bytes(), []byte("disconnected")) {
		t.Fatalf("replaced doorbell = %v\n%s", err, firstDoorbellOutput.Bytes())
	}
	replacementKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postHTTPJSON(t, ctx, "http://"+address+"/v1/enrollments", rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(replacementKey), Label: "replacement-marker"}, &enrollment)
	if err := secondDoorbell.Wait(); err != nil {
		t.Fatalf("replacement doorbell missed marker: %v\n%s", err, secondDoorbellOutput.Bytes())
	}

	staleDoorbellReady := filepath.Join(t.TempDir(), "stale-doorbell.ready")
	staleDoorbell := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", credentialFile, "--state", stateFile, "--ready-file", staleDoorbellReady, "doorbell")
	var staleDoorbellOutput bytes.Buffer
	staleDoorbell.Stdout, staleDoorbell.Stderr = &staleDoorbellOutput, &staleDoorbellOutput
	if err := staleDoorbell.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, staleDoorbellReady)
	rotatedFile := filepath.Join(t.TempDir(), "rotated.credential")
	rotate := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "rotate", "fixture", "--credential-file", rotatedFile)
	if output, err := rotate.CombinedOutput(); err != nil {
		t.Fatalf("rotate adapter: %v\n%s", err, output)
	}
	staleMarkerKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postHTTPJSON(t, ctx, "http://"+address+"/v1/enrollments", rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(staleMarkerKey), Label: "stale-marker"}, &enrollment)
	if err := staleDoorbell.Wait(); err == nil || !bytes.Contains(staleDoorbellOutput.Bytes(), []byte("disconnected")) || bytes.Contains(staleDoorbellOutput.Bytes(), []byte(`"version":1`)) {
		t.Fatalf("rotated stale doorbell = %v\n%s", err, staleDoorbellOutput.Bytes())
	}
	failed := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", credentialFile, "--state", stateFile, "sync")
	if output, err := failed.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("adapter authorization failed")) {
		t.Fatalf("old credential after rotation = %v\n%s", err, output)
	}
	runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "sync")
	idleDoorbellReady := filepath.Join(t.TempDir(), "idle-doorbell.ready")
	idleDoorbell := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", rotatedFile, "--state", stateFile, "--ready-file", idleDoorbellReady, "doorbell")
	var idleDoorbellOutput bytes.Buffer
	idleDoorbell.Stdout, idleDoorbell.Stderr = &idleDoorbellOutput, &idleDoorbellOutput
	if err := idleDoorbell.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, idleDoorbellReady)
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "deactivate", "fixture").CombinedOutput(); err != nil {
		t.Fatalf("deactivate adapter: %v\n%s", err, output)
	}
	if err := idleDoorbell.Wait(); err == nil || !bytes.Contains(idleDoorbellOutput.Bytes(), []byte("disconnected")) {
		t.Fatalf("deactivated idle doorbell = %v\n%s", err, idleDoorbellOutput.Bytes())
	}
	failed = exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", rotatedFile, "--state", stateFile, "sync")
	if output, err := failed.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("adapter authorization failed")) {
		t.Fatalf("inactive adapter = %v\n%s", err, output)
	}
	inactiveFile := filepath.Join(t.TempDir(), "inactive-rotate.credential")
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "rotate", "fixture", "--credential-file", inactiveFile).CombinedOutput(); err != nil || !bytes.Contains(output, []byte("fixture\tactive=false")) || bytes.Contains(output, []byte("outcome_unknown")) {
		t.Fatalf("inactive file rotation: %v\n%s", err, output)
	}
	var plainCredential, plainError bytes.Buffer
	plainRotate := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "rotate", "fixture")
	plainRotate.Stdout, plainRotate.Stderr = &plainCredential, &plainError
	if err := plainRotate.Run(); err != nil || bytes.Contains(plainError.Bytes(), []byte("outcome_unknown")) {
		t.Fatalf("inactive plain rotation: %v\nstdout=%s\nstderr=%s", err, plainCredential.Bytes(), plainError.Bytes())
	}
	plainValue := strings.TrimSpace(plainCredential.String())
	if decoded, err := base64.RawURLEncoding.DecodeString(plainValue); err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != plainValue {
		t.Fatalf("inactive plain credential is not canonical: %q, %v", plainValue, err)
	}
	var jsonCredential, jsonError bytes.Buffer
	jsonRotate := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "rotate", "fixture", "--json")
	jsonRotate.Stdout, jsonRotate.Stderr = &jsonCredential, &jsonError
	if err := jsonRotate.Run(); err != nil || bytes.Contains(jsonError.Bytes(), []byte("outcome_unknown")) {
		t.Fatalf("inactive JSON rotation: %v\nstdout=%s\nstderr=%s", err, jsonCredential.Bytes(), jsonError.Bytes())
	}
	var inactiveRotation serveradmin.AdapterProvisioning
	if err := json.Unmarshal(jsonCredential.Bytes(), &inactiveRotation); err != nil || inactiveRotation.AdapterID != "fixture" || inactiveRotation.Active || inactiveRotation.Credential == "" {
		t.Fatalf("inactive JSON rotation response = %+v, %v\n%s", inactiveRotation, err, jsonCredential.Bytes())
	}
	rotatedFile = filepath.Join(t.TempDir(), "inactive-recovered.credential")
	if err := os.WriteFile(rotatedFile, []byte(inactiveRotation.Credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "activate", "fixture").CombinedOutput(); err != nil {
		t.Fatalf("activate adapter: %v\n%s", err, output)
	}
	state = runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "sync")
	var concurrentEnrollments []string
	for id := range state.Pending {
		concurrentEnrollments = append(concurrentEnrollments, id)
		if len(concurrentEnrollments) == 2 {
			break
		}
	}
	if len(concurrentEnrollments) != 2 {
		t.Fatalf("need two pending enrollments for process lock test: %+v", state.Pending)
	}
	commands := make([]*exec.Cmd, 2)
	outputs := make([]bytes.Buffer, 2)
	for index, enrollmentID := range concurrentEnrollments {
		commands[index] = exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", rotatedFile, "--state", stateFile, "--enrollment", enrollmentID, "approve")
		commands[index].Stdout, commands[index].Stderr = &outputs[index], &outputs[index]
		if err := commands[index].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("concurrent adapter approval %d: %v\n%s", index, err, outputs[index].Bytes())
		}
	}
	stateData, err := os.ReadFile(stateFile)
	if err != nil || json.Unmarshal(stateData, &state) != nil {
		t.Fatalf("read concurrent adapter state: %v\n%s", err, stateData)
	}
	if len(state.ProviderEffects) != 3 || state.LastCommandID <= exactCommandID || state.PendingCommand != nil {
		t.Fatalf("locked monotonic concurrent approvals = %+v", state)
	}
	skippedID := state.LastCommandID[:24] + "000000000000"
	runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "expect-expired", "--command-id", skippedID, "--enrollment", strings.Repeat("f", 32))
	auditOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "audit", "list", "--limit", "10", "--json").Output()
	if err != nil || !bytes.Contains(auditOutput, []byte(`"actor_type":"adapter"`)) || !bytes.Contains(auditOutput, []byte(`"actor_id":"fixture"`)) {
		t.Fatalf("adapter audit attribution: %v\n%s", err, auditOutput)
	}

	fastCredential := filepath.Join(t.TempDir(), "fast.credential")
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "adapters", "provision", "fast", "--credential-file", fastCredential).CombinedOutput(); err != nil {
		t.Fatalf("provision fast adapter: %v\n%s", err, output)
	}
	fastState := filepath.Join(t.TempDir(), "fast-state.json")
	fastDoorbellReady := filepath.Join(t.TempDir(), "fast-doorbell.ready")
	fastDoorbell := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fast", "--credential-file", fastCredential, "--state", fastState, "--ready-file", fastDoorbellReady, "doorbell")
	var fastDoorbellOutput bytes.Buffer
	fastDoorbell.Stdout, fastDoorbell.Stderr = &fastDoorbellOutput, &fastDoorbellOutput
	if err := fastDoorbell.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, fastDoorbellReady)
	stallPendingKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postHTTPJSON(t, ctx, "http://"+address+"/v1/enrollments", rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(stallPendingKey), Label: "stall-existing"}, &enrollment)
	stallReady := filepath.Join(t.TempDir(), "stall-doorbell.ready")
	stalled := exec.CommandContext(ctx, binaryPath("adapter-fixture"), "--endpoint", paths.ServerAdapterEndpoint, "--adapter", "fixture", "--credential-file", rotatedFile, "--state", stateFile, "--duration", "8s", "--ready-file", stallReady, "stall-doorbell")
	var stalledOutput bytes.Buffer
	stalled.Stdout, stalled.Stderr = &stalledOutput, &stalledOutput
	if err := stalled.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, stallReady)
	pendingOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "pending", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var existingPending []membership.Pending
	if err := json.Unmarshal(pendingOutput, &existingPending); err != nil || len(existingPending) != 1 {
		t.Fatalf("existing pending before stall pressure = %+v, %v", existingPending, err)
	}
	for _, item := range existingPending {
		if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "approve", item.Code).CombinedOutput(); err != nil {
			t.Fatalf("settle existing pending: %v\n%s", err, output)
		}
	}
	// Linux ignores SO_RCVBUF on Unix sockets. Exceed its default send queue
	// (roughly 278 small writes), rather than relying on the fixture's read buffer.
	// Each enrollment/approval pair produces two separately flushed markers.
	for index := range 192 {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		postHTTPJSONFromIP(t, ctx, "http://"+address+"/v1/enrollments", fmt.Sprintf("203.0.113.%d", index+1), rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(key), Label: fmt.Sprintf("pressure-%03d", index)}, &enrollment)
		if enrollment.State != "pending" || enrollment.Code == "" || time.Since(started) > time.Second {
			t.Fatalf("stalled doorbell delayed pressure enrollment %d (%s): %+v", index, time.Since(started), enrollment)
		}
		started = time.Now()
		if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "approve", enrollment.Code).CombinedOutput(); err != nil || time.Since(started) > time.Second {
			t.Fatalf("stalled doorbell delayed pressure approval %d (%s): %v\n%s", index, time.Since(started), err, output)
		}
	}
	for index := range membership.DefaultMaxPending {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		postHTTPJSONFromIP(t, ctx, "http://"+address+"/v1/enrollments", fmt.Sprintf("198.51.100.%d", index+1), rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(key), Label: fmt.Sprintf("stall-%02d", index)}, &enrollment)
		if enrollment.State != "pending" || time.Since(started) > time.Second {
			t.Fatalf("stalled doorbell delayed enrollment %d (%s): %+v", index, time.Since(started), enrollment)
		}
	}
	if err := fastDoorbell.Wait(); err != nil {
		t.Fatalf("fast doorbell missed marker: %v\n%s", err, fastDoorbellOutput.Bytes())
	}
	if err := stalled.Wait(); err != nil {
		t.Fatalf("stalled doorbell was not isolated: %v\n%s", err, stalledOutput.Bytes())
	}
	fast := runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fast", fastCredential, fastState, "sync")
	if len(fast.Pending) != membership.DefaultMaxPending {
		t.Fatalf("fast consumer pending replay = %d, want %d", len(fast.Pending), membership.DefaultMaxPending)
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
	databaseState, err := sql.Open("sqlite", database.DSN(paths.ServerDatabase))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := databaseState.BeginTx(ctx, nil)
	if err != nil {
		databaseState.Close()
		t.Fatal(err)
	}
	var firstProtected int64
	if err := transaction.QueryRow(`select min(f.seq) from enrollment_facts f join pending_enrollments p on p.enrollment_id = f.enrollment_id where f.kind = ?`, membership.FactPendingAdmitted).Scan(&firstProtected); err != nil {
		transaction.Rollback()
		databaseState.Close()
		t.Fatal(err)
	}
	floor := firstProtected - 1
	var protectedPrefix int
	if err := transaction.QueryRow(`select count(*) from enrollment_facts f join pending_enrollments p on p.enrollment_id = f.enrollment_id where f.kind = ? and f.seq <= ?`, membership.FactPendingAdmitted, floor).Scan(&protectedPrefix); err != nil || protectedPrefix != 0 {
		transaction.Rollback()
		databaseState.Close()
		t.Fatalf("protected facts in prune prefix = %d, %v", protectedPrefix, err)
	}
	if _, err := transaction.Exec(`delete from enrollment_facts where seq <= ?`, floor); err != nil {
		transaction.Rollback()
		databaseState.Close()
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`update enrollment_fact_metadata set replay_floor = ? where singleton = 1`, floor); err != nil {
		transaction.Rollback()
		databaseState.Close()
		t.Fatal(err)
	}
	if result, err := transaction.Exec(`delete from enrollment_command_receipts where adapter_id = ? and command_id = ? and state = ?`, "fixture", exactCommandID, membership.ReceiptCommitted); err != nil {
		transaction.Rollback()
		databaseState.Close()
		t.Fatal(err)
	} else if changed, _ := result.RowsAffected(); changed != 1 {
		transaction.Rollback()
		databaseState.Close()
		t.Fatalf("pruned settled receipt rows = %d", changed)
	}
	if err := transaction.Commit(); err != nil {
		databaseState.Close()
		t.Fatal(err)
	}
	if err := databaseState.Close(); err != nil {
		t.Fatal(err)
	}
	server = startServerProcess(t, ctx, home, address, "--trusted-proxy", "127.0.0.1/32")
	waitServerReady(t, ctx, "http://"+address)
	state = runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "sync")
	if state.Cursor < firstProtected || len(state.Pending) != membership.DefaultMaxPending {
		t.Fatalf("cursor-gap rebuild = %+v, floor %d", state, floor)
	}
	runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "expect-expired", "--command-id", exactCommandID, "--enrollment", enrollmentID)
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
	server = startServerProcess(t, ctx, home, address, "--trusted-proxy", "127.0.0.1/32")
	waitServerReady(t, ctx, "http://"+address)
	runAdapterFixture(t, ctx, paths.ServerAdapterEndpoint, "fixture", rotatedFile, stateFile, "sync")
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

type adapterFixtureState struct {
	Version         int                     `json:"version"`
	Cursor          int64                   `json:"cursor"`
	HighWater       int64                   `json:"high_water"`
	LastCommandID   string                  `json:"last_command_id"`
	AppliedFactIDs  map[string]bool         `json:"applied_fact_ids"`
	Pending         map[string]any          `json:"pending"`
	ProviderEffects map[string]string       `json:"provider_effects"`
	PendingCommand  *fixtureApprovalRequest `json:"pending_command,omitempty"`
}

type fixtureApprovalRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	CommandID     string `json:"command_id"`
	EnrollmentID  string `json:"enrollment_id"`
}

func runAdapterFixture(t *testing.T, ctx context.Context, endpoint, adapterID, credentialFile, stateFile, action string, extra ...string) adapterFixtureState {
	t.Helper()
	args := []string{"--endpoint", endpoint, "--adapter", adapterID, "--credential-file", credentialFile, "--state", stateFile}
	args = append(args, extra...)
	args = append(args, action)
	output, err := exec.CommandContext(ctx, binaryPath("adapter-fixture"), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("adapter fixture %s: %v\n%s", action, err, output)
	}
	var result adapterFixtureState
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode adapter fixture %s: %v\n%s", action, err, output)
	}
	return result
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata",
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			env.Setenv("PATH", binaryDir+string(os.PathListSeparator)+env.Getenv("PATH"))
			env.Setenv("PX_HOME", filepath.Join(env.WorkDir, "home"))
			return nil
		},
	})
}

func TestCaddyExampleAdapts(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, caddy, "adapt", "--config", filepath.Join("..", "docs", "examples", "Caddyfile"), "--adapter", "caddyfile")
	command.Env = append(os.Environ(), "HOME="+t.TempDir())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("adapt example Caddyfile: %v\n%s", err, output)
	}
}

func TestAgentRejectsInvalidCAFileProcess(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "invalid-ca.pem")
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath("px"), "--home", filepath.Join(dir, "home"), "agent", "run")
	command.Env = append(os.Environ(), contextstate.EnvCAFile+"="+caFile)
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte(contextstate.EnvCAFile)) {
		t.Fatalf("invalid CA startup = %v\n%s", err, output)
	}
}

func TestPerUserStartupLifecycle(t *testing.T) {
	root := t.TempDir()
	userHome := filepath.Join(root, "user")
	pxHome := filepath.Join(root, "state")
	managerBin := filepath.Join(root, "bin")
	for _, directory := range []string{userHome, pxHome, managerBin} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateMarker := filepath.Join(pxHome, "preserve-state")
	if err := os.WriteFile(stateMarker, []byte("identity and transfer state"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := "launchctl"
	if runtime.GOOS == "linux" {
		manager = "systemctl"
	} else if runtime.GOOS == "windows" {
		manager = "schtasks.exe"
	}
	managerPath := filepath.Join(managerBin, manager)
	fakeManager, err := os.ReadFile(binaryPath("fake-manager"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managerPath, fakeManager, 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(managerBin, "powershell.exe"), fakeManager, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	managerLog := filepath.Join(root, "manager.log")
	environment := append(os.Environ(),
		"HOME="+userHome,
		"USERPROFILE="+userHome,
		"LOCALAPPDATA="+filepath.Join(userHome, "AppData", "Local"),
		"PX_MANAGER_LOG="+managerLog,
		"PATH="+managerBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	var artifact string
	switch runtime.GOOS {
	case "linux":
		artifact = filepath.Join(userHome, ".config", "systemd", "user", "px-agent.service")
	case "darwin":
		artifact = filepath.Join(userHome, "Library", "LaunchAgents", "com.scotthaleen.px.agent.plist")
	}
	for _, action := range []string{"install", "status", "upgrade", "restart", "stop", "start", "uninstall"} {
		command := exec.Command(binaryPath("px"), "--home", pxHome, "startup", action)
		command.Env = environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("startup %s: %v\n%s", action, err, output)
		}
		if action == "stop" && runtime.GOOS == "windows" {
			status := exec.Command(binaryPath("px"), "--home", pxHome, "startup", "status")
			status.Env = environment
			output, err := status.CombinedOutput()
			if err == nil || !bytes.Contains(output, []byte("installed but not running")) {
				t.Fatalf("stopped startup status: %v\n%s", err, output)
			}
		}
		if action == "install" && artifact != "" {
			content, err := os.ReadFile(artifact)
			if err != nil || !bytes.Contains(content, []byte(pxHome)) || !bytes.Contains(content, []byte(binaryPath("px"))) {
				t.Fatalf("startup artifact = %q, %v", content, err)
			}
			info, err := os.Stat(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("startup artifact mode = %v", info.Mode())
			}
		}
	}
	if content, err := os.ReadFile(stateMarker); err != nil || string(content) != "identity and transfer state" {
		t.Fatalf("state marker = %q, %v", content, err)
	}
	managerCalls, err := os.ReadFile(managerLog)
	if err != nil || len(managerCalls) == 0 {
		t.Fatalf("manager calls = %q, %v", managerCalls, err)
	}
	if runtime.GOOS == "windows" && (!bytes.Contains(managerCalls, []byte("ONLOGON")) || !bytes.Contains(managerCalls, []byte("LIMITED"))) {
		t.Fatalf("Windows task is not per-user limited: %s", managerCalls)
	}
	if artifact != "" {
		if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("startup artifact remains after uninstall: %v", err)
		}
	}
}

func TestProbeProcesses(t *testing.T) {
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + server.URL[len("http"):] + "/signal"
	dir := t.TempDir()
	privateA, publicA := filepath.Join(dir, "a.key"), filepath.Join(dir, "a.pub")
	privateB, publicB := filepath.Join(dir, "b.key"), filepath.Join(dir, "b.pub")
	runBinary(t, "px", "debug", "keygen", "--private", privateA, "--public", publicA)
	runBinary(t, "px", "debug", "keygen", "--private", privateB, "--public", publicB)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type processResult struct {
		output []byte
		err    error
	}
	results := make(chan processResult, 2)
	start := func(home, privateKey, peerKey string, offer bool) {
		args := []string{"debug", "probe", "--signal", signalURL, "--session", "process-test", "--private", privateKey, "--peer-public", peerKey, "--allow-loopback", "--json"}
		if offer {
			args = append(args, "--offer")
		}
		cmd := exec.CommandContext(ctx, binaryPath("px"), args...)
		cmd.Env = append(os.Environ(), "PX_HOME="+home)
		output, err := cmd.CombinedOutput()
		results <- processResult{output: output, err: err}
	}
	go start(filepath.Join(dir, "home-a"), privateA, publicB, true)
	go start(filepath.Join(dir, "home-b"), privateB, publicA, false)

	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("probe process failed: %v\n%s", result.err, result.output)
		}
		var outcome probe.Result
		if err := json.Unmarshal(result.output, &outcome); err != nil {
			t.Fatalf("decode probe output: %v\n%s", err, result.output)
		}
		if outcome.CandidateType != "host" {
			t.Fatalf("candidate type = %q, want host", outcome.CandidateType)
		}
	}
}

func TestTransferProcesses(t *testing.T) {
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + server.URL[len("http"):] + "/signal"
	dir := t.TempDir()
	privateA, publicA := filepath.Join(dir, "a.key"), filepath.Join(dir, "a.pub")
	privateB, publicB := filepath.Join(dir, "b.key"), filepath.Join(dir, "b.pub")
	runBinary(t, "px", "debug", "keygen", "--private", privateA, "--public", publicA)
	runBinary(t, "px", "debug", "keygen", "--private", privateB, "--public", publicB)
	source := filepath.Join(dir, "representative-large.bin")
	content := bytes.Repeat([]byte("px-direct-transfer\n"), 1<<19)
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(dir, "inbox")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	type processResult struct {
		output []byte
		err    error
	}
	receiverResult := make(chan processResult, 1)
	go func() {
		args := []string{
			"debug", "receive-file",
			"--signal", signalURL,
			"--session", "transfer-process-test",
			"--private", privateB,
			"--peer-public", publicA,
			"--inbox", inbox,
			"--context-name", "home",
			"--sender", "builder",
			"--json",
		}
		if os.Getenv("PX_TEST_REAL_LAN") == "" {
			args = append(args, "--allow-loopback")
		}
		cmd := exec.CommandContext(ctx, binaryPath("px"), args...)
		cmd.Env = append(os.Environ(), "PX_HOME="+filepath.Join(dir, "home-b"))
		output, err := cmd.CombinedOutput()
		receiverResult <- processResult{output: output, err: err}
	}()
	senderArgs := []string{
		"debug", "send-file",
		"--signal", signalURL,
		"--session", "transfer-process-test",
		"--private", privateA,
		"--peer-public", publicB,
		"--source", source,
		"--name", "release.bin",
		"--json",
	}
	if os.Getenv("PX_TEST_REAL_LAN") == "" {
		senderArgs = append(senderArgs, "--allow-loopback")
	}
	sender := exec.CommandContext(ctx, binaryPath("px"), senderArgs...)
	sender.Env = append(os.Environ(), "PX_HOME="+filepath.Join(dir, "home-a"))
	senderOutput, senderErr := sender.CombinedOutput()
	receiver := <-receiverResult
	if senderErr != nil {
		t.Fatalf("sender failed: %v\n%s", senderErr, senderOutput)
	}
	if receiver.err != nil {
		t.Fatalf("receiver failed: %v\n%s", receiver.err, receiver.output)
	}
	for role, output := range map[string][]byte{"sender": senderOutput, "receiver": receiver.output} {
		var outcome struct {
			transfer.Result
			CandidateType string `json:"candidate_type"`
		}
		if err := json.Unmarshal(output, &outcome); err != nil {
			t.Fatalf("decode %s output: %v\n%s", role, err, output)
		}
		if outcome.Bytes != int64(len(content)) || outcome.CandidateType != "host" {
			t.Fatalf("%s outcome = %+v", role, outcome)
		}
	}
	destination := filepath.Join(inbox, "home", "builder", "release.bin")
	received, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, content) {
		t.Fatal("transferred file differs")
	}
}

func TestAgentIPCLifecycle(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	unavailable := exec.Command(binaryPath("px"), "--home", home, "agent", "status", "--json")
	if output, err := unavailable.CombinedOutput(); err == nil {
		t.Fatalf("status unexpectedly succeeded without agent: %s", output)
	}
	if runtime.GOOS != "windows" {
		if err := paths.EnsureAgent(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths.AgentEndpoint, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		blockedContext, cancelBlocked := context.WithTimeout(context.Background(), 2*time.Second)
		blocked := exec.CommandContext(blockedContext, binaryPath("px"), "--home", home, "agent", "run")
		output, blockedErr := blocked.CombinedOutput()
		cancelBlocked()
		if errors.Is(blockedContext.Err(), context.DeadlineExceeded) {
			t.Fatalf("agent removed unsafe endpoint file and remained running: %s", output)
		}
		if blockedErr == nil {
			t.Fatalf("agent removed unsafe endpoint file and started: %s", output)
		}
		data, err := os.ReadFile(paths.AgentEndpoint)
		if err != nil || string(data) != "stale" {
			t.Fatalf("unsafe endpoint file changed: data=%q err=%v", data, err)
		}
		if err := os.Remove(paths.AgentEndpoint); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	agent := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "run")
	agent.Stdout = io.Discard
	var agentLogs bytes.Buffer
	agent.Stderr = &agentLogs
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if agent.ProcessState == nil || !agent.ProcessState.Exited() {
			_ = agent.Process.Kill()
			_ = agent.Wait()
		}
	}()

	var status agentapi.Status
	for attempt := 0; attempt < 100; attempt++ {
		statusCommand := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "status", "--json")
		output, statusErr := statusCommand.Output()
		if statusErr == nil && json.Unmarshal(output, &status) == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if status.Version != agentapi.Version || status.PID != agent.Process.Pid {
		t.Fatalf("status = %+v, agent pid = %d", status, agent.Process.Pid)
	}
	summaryCommand := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "status", "--json")
	summaryOutput, err := summaryCommand.Output()
	if err != nil {
		t.Fatalf("daily status: %v\n%s", err, summaryOutput)
	}
	var summary agentapi.Summary
	if err := json.Unmarshal(summaryOutput, &summary); err != nil || summary.Version != agentapi.SummaryVersion || summary.Status != "degraded" || summary.Next != "px doctor" || summary.Context != nil || summary.Transfers != nil {
		t.Fatalf("daily status = %+v, %v", summary, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(paths.AgentEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("agent socket mode = %o, want 600", info.Mode().Perm())
		}
	}
	malformedErr := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/probe", map[string]bool{"unknown": true}, nil)
	var responseError *localipc.Error
	if !errors.As(malformedErr, &responseError) || responseError.Status != 400 {
		t.Fatalf("malformed request error = %v", malformedErr)
	}

	secondContext, secondCancel := context.WithTimeout(ctx, 5*time.Second)
	defer secondCancel()
	second := exec.CommandContext(secondContext, binaryPath("px"), "--home", home, "agent", "run")
	secondOutput, secondErr := second.CombinedOutput()
	if secondErr == nil || !bytes.Contains(secondOutput, []byte("already running")) {
		t.Fatalf("second agent error = %v\n%s", secondErr, secondOutput)
	}

	stop := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "stop")
	if output, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop agent: %v\n%s", err, output)
	}
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	if logs := agentLogs.String(); !strings.Contains(logs, "agent.ready") || !strings.Contains(logs, "agent.stopping") || strings.Contains(logs, "agent IPC listening") {
		t.Fatalf("agent operational logs = %q", logs)
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(paths.AgentEndpoint); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("agent socket remains after shutdown: %v", err)
		}
	}
}

func TestDailyStatusAndEntityCompletionProcess(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindAgent, paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := databaseStore.DB().Exec(`insert into contexts (name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values ('home','https://px.example','server','local','private','public','local','enrolled',0,'/private/offered','/private/inbox',?,?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into contexts (name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values ('work','https://work.example','server','local-work','private-work','public-work','local-work','enrolled',0,'/private/work-offered','/private/work-inbox',?,?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	largeRoot := "/" + strings.Repeat("x", localipc.MaxResponseBytes/2)
	if _, err := databaseStore.DB().Exec(`insert into contexts (name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values ('oversized','https://oversized.example','server','local-oversized','private-oversized','public-oversized','local-oversized','enrolled',0,?,?,?,?)`, largeRoot, largeRoot, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`update context_settings set default_context='home' where singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into context_aliases(context_name,alias,target_label) values ('home','offline','old-vm')`); err != nil {
		t.Fatal(err)
	}
	retryID := strings.Repeat("9", 64)
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('send',?,'home','peer-id','private-peer','private-name',1,'sha',1,1,'private-token',0,'transferring',?,?,?)`, retryID, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	unavailableCompletion, err := exec.Command(binaryPath("px"), "--home", home, "__complete", "--context", "h").CombinedOutput()
	if err != nil || !bytes.Contains(unavailableCompletion, []byte(":4\n")) || bytes.Contains(unavailableCompletion, []byte("local transport")) {
		t.Fatalf("unavailable completion = %q, %v", unavailableCompletion, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	agent := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "run")
	agent.Stdout = io.Discard
	agent.Stderr = io.Discard
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if agent.ProcessState == nil || !agent.ProcessState.Exited() {
			_ = agent.Process.Kill()
			_ = agent.Wait()
		}
	}()
	for attempt := 0; attempt < 100; attempt++ {
		if exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "status").Run() == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	oversizedList := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "list", "--json")
	oversizedOutput, oversizedErr := oversizedList.CombinedOutput()
	if oversizedErr == nil || !bytes.Contains(oversizedOutput, []byte("agent response exceeds size limit")) {
		t.Fatalf("oversized context projection = %v\n%s", oversizedErr, oversizedOutput)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "remove", "oversized", "--yes").CombinedOutput(); err != nil {
		t.Fatalf("remove oversized context: %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "list", "--json").CombinedOutput(); err != nil {
		t.Fatalf("list contexts after recovery: %v\n%s", err, output)
	}

	jsonOutput, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "status", "--json").Output()
	if err != nil {
		t.Fatalf("JSON status: %v\n%s", err, jsonOutput)
	}
	var summary agentapi.Summary
	if err := json.Unmarshal(jsonOutput, &summary); err != nil || summary.Version != agentapi.SummaryVersion || summary.Build.Version == "" || summary.Build.Commit == "" || summary.Build.Date == "" || summary.StartedAt.IsZero() || summary.Context == nil || summary.Context.Name != "home" || summary.Context.Enabled || summary.Context.OnlinePeers != nil || summary.Transfers == nil || summary.Transfers.Active != 0 || summary.Transfers.Retryable != 1 || summary.Status != "degraded" || summary.Next != "px doctor" {
		t.Fatalf("summary = %+v, %v", summary, err)
	}
	environmentStatus := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "status", "--json")
	environmentStatus.Env = append(os.Environ(), "PX_CONTEXT=work")
	environmentOutput, err := environmentStatus.Output()
	if err != nil || json.Unmarshal(environmentOutput, &summary) != nil || summary.Context == nil || summary.Context.Name != "work" {
		t.Fatalf("environment status = %+v, %v\n%s", summary, err, environmentOutput)
	}
	explicitStatus := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "home", "status", "--json")
	explicitStatus.Env = append(os.Environ(), "PX_CONTEXT=work")
	explicitOutput, err := explicitStatus.Output()
	if err != nil || json.Unmarshal(explicitOutput, &summary) != nil || summary.Context == nil || summary.Context.Name != "home" {
		t.Fatalf("explicit status = %+v, %v\n%s", summary, err, explicitOutput)
	}
	missingStatus := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "missing", "status")
	missingOutput, missingErr := missingStatus.CombinedOutput()
	if missingErr == nil || !bytes.Contains(missingOutput, []byte("context not found")) || bytes.Contains(missingOutput, []byte("restart it")) {
		t.Fatalf("missing context status = %q, %v", missingOutput, missingErr)
	}
	plain, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "status").Output()
	if err != nil || !bytes.Contains(plain, []byte("Context    home | disabled\n")) || !bytes.Contains(plain, []byte("Transfers  0 active | 1 retryable\n")) || bytes.Contains(plain, []byte("private-")) {
		t.Fatalf("plain status = %q, %v", plain, err)
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"__complete", "--context", "h"}, want: "home\n"},
		{args: []string{"__complete", "context", "alias", "remove", "o"}, want: "offline\n"},
		{args: []string{"__complete", "transfer", "retry", ""}, want: retryID + "\n"},
	} {
		args := append([]string{"--home", home}, test.args...)
		output, err := exec.CommandContext(ctx, binaryPath("px"), args...).CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(test.want)) || bytes.Contains(output, []byte("private-")) {
			t.Fatalf("completion %v = %q, %v", test.args, output, err)
		}
	}

	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "stop").CombinedOutput(); err != nil {
		t.Fatalf("stop agent: %v\n%s", err, output)
	}
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferInventoryProcessSurvivesRestartAndDeletesPrivateSpool(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindAgent, paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := databaseStore.DB().Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values ('home', 'http://127.0.0.1:1', 'server', 'device', 'private', 'public', 'local', 'enrolled', 0, 'offered', 'inbox', ?, ?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("7", 64)
	spool := filepath.Join(paths.AgentTransfers, ".stdin-process.spool")
	if err := os.WriteFile(spool, []byte("private stdin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('send', ?, 'home', 'peer-id', 'build-vm', 'artifact.bin', 13, ?, ?, ?, 'secret-token', 0, ?, 1, 'transferring', ?, ?, ?, 3, 'public')`, id, strings.Repeat("0", 64), transfer.ResumeChunkSize, transfer.ResumeAckWindow, spool, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	agent := startAgentProcess(t, ctx, home)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	assertInventory := func() {
		output := runPXOutput(t, ctx, home, "--context", "home", "transfer", "list", "--json")
		var inventory transfer.Inventory
		if err := json.Unmarshal(output, &inventory); err != nil || inventory.Version != transfer.InventoryVersion || len(inventory.Transfers) != 1 || inventory.Transfers[0].ID != id || inventory.Transfers[0].Visibility != transfer.VisibilityPublic {
			t.Fatalf("inventory = %+v, %v\n%s", inventory, err, output)
		}
		for _, secret := range []string{spool, "secret-token", "source_path", "resume_token"} {
			if bytes.Contains(output, []byte(secret)) {
				t.Fatalf("inventory exposed %q: %s", secret, output)
			}
		}
		shown := runPXOutput(t, ctx, home, "--context", "home", "transfer", "show", id, "--json")
		if bytes.Contains(shown, []byte(spool)) || !bytes.Contains(shown, []byte(`"state":"retryable"`)) {
			t.Fatalf("show output = %s", shown)
		}
	}
	assertInventory()
	stopAgentCommand(t, ctx, home)
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	agent = startAgentProcess(t, ctx, home)
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	assertInventory()
	deleted := runPXOutput(t, ctx, home, "--context", "home", "transfer", "delete", id, "--yes", "--json")
	if !bytes.Contains(deleted, []byte(id)) {
		t.Fatalf("delete output = %s", deleted)
	}
	if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted stdin spool remains: %v", err)
	}
	empty := runPXOutput(t, ctx, home, "--context", "home", "transfer", "list", "--json")
	var inventory transfer.Inventory
	if err := json.Unmarshal(empty, &inventory); err != nil || len(inventory.Transfers) != 0 {
		t.Fatalf("empty inventory = %+v, %v\n%s", inventory, err, empty)
	}
}

func TestNoAgentErrorsAreActionableAndMachineReadable(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	plainCommands := [][]string{
		{"agent", "stop"},
		{"agent", "status", "--json", "--json=false"},
		{"--context", "home", "peers"},
		{"--context", "home", "ls", "vm"},
		{"--context", "home", "@vm", "ls"},
		{"--context", "home", "get", "vm", "artifact", "--output", filepath.Join(t.TempDir(), "artifact")},
		{"--context", "home", "send", "vm", source},
		{"--context", "home", "join", "https://px.example", "--name", "laptop", "--offered-root", t.TempDir(), "--inbox-root", t.TempDir()},
	}
	for _, args := range plainCommands {
		t.Run("plain "+strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, exitCode := runFailedPX(t, home, args...)
			if exitCode != 1 || stdout != "" {
				t.Fatalf("exit = %d, stdout = %q", exitCode, stdout)
			}
			if stderr != "px: "+localipc.ErrAgentUnavailable.Error()+"\n" {
				t.Fatalf("stderr = %q", stderr)
			}
			if strings.Contains(stderr, home) || strings.Contains(stderr, "agent.sock") || strings.Contains(stderr, `\\.\pipe`) {
				t.Fatalf("stderr leaks endpoint: %q", stderr)
			}
		})
	}

	jsonCommands := [][]string{
		{"agent", "status", "--json=1"},
		{"context", "list", "--json=t"},
		{"--context", "home", "devices", "list", "--json"},
		{"--context", "home", "devices", "pending", "--json"},
		{"onboard", "--yes", "--json"},
	}
	for _, args := range jsonCommands {
		t.Run("json "+strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, exitCode := runFailedPX(t, home, args...)
			if exitCode != 1 || stdout != "" {
				t.Fatalf("exit = %d, stdout = %q", exitCode, stdout)
			}
			var envelope struct {
				Version int `json:"version"`
				Error   struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatalf("decode stderr: %v\n%s", err, stderr)
			}
			if envelope.Version != 1 || envelope.Error.Code != "local_agent_unavailable" || envelope.Error.Message != localipc.ErrAgentUnavailable.Error() {
				t.Fatalf("error envelope = %+v", envelope)
			}
			if strings.Contains(stderr, home) || strings.Contains(stderr, "agent.sock") || strings.Contains(stderr, `\\.\pipe`) {
				t.Fatalf("stderr leaks endpoint: %q", stderr)
			}
		})
	}
}

func runFailedPX(t *testing.T, home string, args ...string) (string, string, int) {
	t.Helper()
	commandArgs := append([]string{"--home", home}, args...)
	command := exec.Command(binaryPath("px"), commandArgs...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("command error = %v, stderr = %s", err, stderr.String())
	}
	return stdout.String(), stderr.String(), exitError.ExitCode()
}

func TestAgentTransferAndCancellation(t *testing.T) {
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + server.URL[len("http"):] + "/signal"
	dir := t.TempDir()
	homeA, homeB := filepath.Join(dir, "home-a"), filepath.Join(dir, "home-b")
	pathsA, err := apphome.Resolve(homeA)
	if err != nil {
		t.Fatal(err)
	}
	pathsB, err := apphome.Resolve(homeB)
	if err != nil {
		t.Fatal(err)
	}
	privateA, publicA := filepath.Join(dir, "a.key"), filepath.Join(dir, "a.pub")
	privateB, publicB := filepath.Join(dir, "b.key"), filepath.Join(dir, "b.pub")
	runBinary(t, "px", "debug", "keygen", "--private", privateA, "--public", publicA)
	runBinary(t, "px", "debug", "keygen", "--private", privateB, "--public", publicB)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	agentA := startAgentProcess(t, ctx, homeA)
	agentB := startAgentProcess(t, ctx, homeB)
	defer stopAgentProcess(agentA)
	defer stopAgentProcess(agentB)
	waitAgentStatus(t, ctx, pathsA.AgentEndpoint)
	waitAgentStatus(t, ctx, pathsB.AgentEndpoint)
	probeReceiver := make(chan error, 1)
	go func() {
		var result probe.Result
		probeReceiver <- localipc.NewClient(pathsB.AgentEndpoint).JSON(ctx, "POST", "/v1/probe", agentapi.ProbeRequest{
			ConnectionRequest: agentapi.ConnectionRequest{
				SignalURL:      signalURL,
				Session:        "agent-probe",
				PrivatePath:    privateB,
				PeerPublicPath: publicA,
				Timeout:        30 * time.Second,
				AllowLoopback:  true,
			},
		}, &result)
	}()
	probeSender := exec.CommandContext(ctx, binaryPath("px"),
		"--home", homeA,
		"probe",
		"--signal", signalURL,
		"--session", "agent-probe",
		"--private", privateA,
		"--peer-public", publicB,
		"--allow-loopback",
		"--offer",
		"--timeout", "30s",
		"--json",
	)
	probeOutput, probeErr := probeSender.CombinedOutput()
	if probeErr != nil {
		t.Fatalf("agent probe failed: %v\n%s", probeErr, probeOutput)
	}
	var probeCommandResult probe.Result
	if err := json.Unmarshal(probeOutput, &probeCommandResult); err != nil {
		t.Fatalf("decode agent probe output: %v\n%s", err, probeOutput)
	}
	if probeCommandResult.CandidateType != "host" {
		t.Fatalf("agent probe result = %+v", probeCommandResult)
	}
	if err := <-probeReceiver; err != nil {
		t.Fatal(err)
	}

	source := filepath.Join(dir, "agent-source.bin")
	content := bytes.Repeat([]byte("agent-owned-transfer\n"), 1<<17)
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(dir, "inbox")
	receiverResult := make(chan error, 1)
	go func() {
		var result agentapi.TransferResult
		receiverResult <- localipc.NewClient(pathsB.AgentEndpoint).JSON(ctx, "POST", "/v1/receive-file", agentapi.ReceiveFileRequest{
			ConnectionRequest: agentapi.ConnectionRequest{
				SignalURL:      signalURL,
				Session:        "agent-transfer",
				PrivatePath:    privateB,
				PeerPublicPath: publicA,
				Timeout:        30 * time.Second,
				AllowLoopback:  true,
			},
			Inbox:        inbox,
			Context:      "home",
			Sender:       "builder",
			MaxFileBytes: transfer.DefaultMaxFileBytes,
		}, &result)
	}()
	var sendResult agentapi.TransferResult
	if err := localipc.NewClient(pathsA.AgentEndpoint).JSON(ctx, "POST", "/v1/send-file", agentapi.SendFileRequest{
		ConnectionRequest: agentapi.ConnectionRequest{
			SignalURL: signalURL, Session: "agent-transfer", PrivatePath: privateA, PeerPublicPath: publicB,
			Timeout: 30 * time.Second, AllowLoopback: true,
		},
		Source: source, Name: "received.bin", MaxFileBytes: transfer.DefaultMaxFileBytes,
	}, &sendResult); err != nil {
		t.Fatalf("agent send failed: %v", err)
	}
	if sendResult.Bytes != int64(len(content)) || sendResult.CandidateType != "host" {
		t.Fatalf("agent send result = %+v", sendResult)
	}
	if err := <-receiverResult; err != nil {
		t.Fatal(err)
	}
	received, err := os.ReadFile(filepath.Join(inbox, "home", "builder", "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, content) {
		t.Fatal("agent-transferred file differs")
	}

	cancelContext, cancelRequest := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelRequest()
	var probeResult probe.Result
	err = localipc.NewClient(pathsA.AgentEndpoint).JSON(cancelContext, "POST", "/v1/probe", agentapi.ProbeRequest{
		ConnectionRequest: agentapi.ConnectionRequest{
			SignalURL:      signalURL,
			Session:        "canceled-agent-probe",
			PrivatePath:    privateA,
			PeerPublicPath: publicB,
			Timeout:        30 * time.Second,
			AllowLoopback:  true,
		},
		Offer: true,
	}, &probeResult)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled request error = %v", err)
	}
	waitAgentStatus(t, ctx, pathsA.AgentEndpoint)

	stopAgentCommand(t, ctx, homeA)
	stopAgentCommand(t, ctx, homeB)
	if err := agentA.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := agentB.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestServerEnrollmentAuthenticationAndRevocation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	initCommand := exec.Command(binaryPath("px-server"), "--home", home, "init")
	serverIDBytes, err := initCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	serverID := strings.TrimSpace(string(serverIDBytes))
	if serverID == "" {
		t.Fatal("server init returned no identity")
	}
	if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err == nil {
		t.Fatalf("second server init succeeded: %s", output)
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(paths.ServerAuthorityKey)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("authority key mode = %o, want 600", info.Mode().Perm())
		}
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, home, address)
	defer stopAgentProcess(server)
	baseURL := "http://" + address
	waitServerReady(t, ctx, baseURL)
	status := serverStatus(t, ctx, home)
	if !status.Ready || !status.AuthorityAvailable || !status.DatabaseHealthy || !status.HTTPListenerReady || status.PendingEnrollments != 0 || status.AuthenticatedConnections != 0 {
		t.Fatalf("initial server status = %+v", status)
	}
	plainStatus, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "status").Output()
	if err != nil || !bytes.Contains(plainStatus, []byte("ready\ttrue\n")) || !bytes.Contains(plainStatus, []byte("signaling_queue_per_client_capacity\t32\n")) || bytes.Contains(plainStatus, []byte("{")) {
		t.Fatalf("plain server status: %v\n%s", err, plainStatus)
	}
	rejectedRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/enrollments", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	rejectedResponse, err := http.DefaultClient.Do(rejectedRequest)
	if err != nil {
		t.Fatal(err)
	}
	rejectedResponse.Body.Close()
	if rejectedResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("rejected enrollment status = %s", rejectedResponse.Status)
	}
	failedAuthentication, _, err := websocket.Dial(ctx, "ws://"+address+"/v1/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := failedAuthentication.Read(ctx); err != nil {
		t.Fatal(err)
	}
	writeServerMessage(t, ctx, failedAuthentication, map[string]string{"type": "invalid"})
	if _, _, err := failedAuthentication.Read(ctx); err == nil {
		t.Fatal("invalid authentication remained connected")
	}
	failedAuthentication.CloseNow()
	status = serverStatus(t, ctx, home)
	if status.Counters.EnrollmentRejected != 1 || status.Counters.AuthenticationFailed != 1 {
		t.Fatalf("rejection server status = %+v", status)
	}
	secondContext, secondCancel := context.WithTimeout(ctx, 5*time.Second)
	defer secondCancel()
	second := exec.CommandContext(secondContext, binaryPath("px-server"), "--home", home, "serve", "--listen", reserveTCPAddress(t))
	secondOutput, secondErr := second.CombinedOutput()
	if secondErr == nil || !bytes.Contains(secondOutput, []byte("already running")) {
		t.Fatalf("second server error = %v\n%s", secondErr, secondOutput)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentRequest := rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: "first"}
	var enrollment membership.Enrollment
	postHTTPJSON(t, ctx, baseURL+"/v1/enrollments", enrollmentRequest, &enrollment)
	if enrollment.State != "pending" || enrollment.Code == "" {
		t.Fatalf("enrollment = %+v", enrollment)
	}
	status = serverStatus(t, ctx, home)
	if status.PendingEnrollments != 1 {
		t.Fatalf("pending server status = %+v", status)
	}
	pendingOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "pending", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var pending []membership.Pending
	if err := json.Unmarshal(pendingOutput, &pending); err != nil || len(pending) != 1 || pending[0].Code != enrollment.Code {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "approve", enrollment.Code, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve: %v\n%s", err, output)
	}
	membersOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "list", "--limit", "1", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var serverMembers serveradmin.ListDevicesResponse
	if err := json.Unmarshal(membersOutput, &serverMembers); err != nil || serverMembers.Version != serveradmin.Version || len(serverMembers.Devices) != 1 || serverMembers.Devices[0].Label != "first" || serverMembers.Devices[0].Revision != 1 {
		t.Fatalf("server members = %+v, %v\n%s", serverMembers, err, membersOutput)
	}
	postHTTPJSON(t, ctx, baseURL+"/v1/enrollments", enrollmentRequest, &enrollment)
	if enrollment.State != "enrolled" || enrollment.Credential == nil || enrollment.Credential.Claims.ServerID != serverID {
		t.Fatalf("enrolled = %+v", enrollment)
	}

	conn := authenticateServerConnection(t, ctx, baseURL, privateKey, *enrollment.Credential)
	defer conn.CloseNow()
	readServerMessageType(t, ctx, conn, "authenticated")
	status = serverStatus(t, ctx, home)
	if status.AuthenticatedConnections != 1 || status.Counters.AuthenticatedConnected != 1 {
		t.Fatalf("connected server status = %+v", status)
	}
	deviceID := identity.ID(publicKey)
	writeServerMessage(t, ctx, conn, map[string]any{"version": rendezvousapi.Version, "type": "signal", "to": deviceID, "payload": map[string]string{"candidate": "rejected"}})
	signalError := readServerMessageType(t, ctx, conn, "signal.error")
	if signalError.Version != rendezvousapi.Version {
		t.Fatalf("signal error = %+v", signalError)
	}
	status = serverStatus(t, ctx, home)
	if status.Counters.SignalingRejected != 1 {
		t.Fatalf("signaling rejection status = %+v", status)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "revoke", "--json", "--", deviceID).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("JSON revocation requires --yes")) {
		t.Fatalf("unconfirmed JSON revocation = %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "revoke", "--", deviceID).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("requires --yes when input is not a terminal")) {
		t.Fatalf("unconfirmed non-TTY revocation = %v\n%s", err, output)
	}
	revokeOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "revoke", "--yes", "--json", "--", deviceID).CombinedOutput()
	if err != nil {
		t.Fatalf("revoke: %v\n%s", err, revokeOutput)
	}
	var revokedMember membership.Member
	if err := json.Unmarshal(revokeOutput, &revokedMember); err != nil || revokedMember.DeviceID != deviceID || revokedMember.RevokedAt == nil {
		t.Fatalf("revocation result = %+v, %v\n%s", revokedMember, err, revokeOutput)
	}
	membersOutput, err = exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "list", "--limit", "1", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	serverMembers = serveradmin.ListDevicesResponse{}
	if err := json.Unmarshal(membersOutput, &serverMembers); err != nil || len(serverMembers.Devices) != 1 || serverMembers.Devices[0].RevokedAt == nil || serverMembers.Devices[0].Revision != 2 {
		t.Fatalf("historical server members = %+v, %v\n%s", serverMembers, err, membersOutput)
	}
	auditOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "audit", "list", "--limit", "3", "--json").Output()
	if err != nil {
		t.Fatalf("audit: %v\n%s", err, auditOutput)
	}
	var audit []membership.AuditEvent
	if err := json.Unmarshal(auditOutput, &audit); err != nil || len(audit) != 3 || audit[0].Action != "member.revoked" || audit[1].Action != "member.approved" || audit[2].Action != "enrollment.requested" {
		t.Fatalf("audit = %+v, %v\n%s", audit, err, auditOutput)
	}
	for _, forbidden := range []string{"credential", "device_key", "nonce", "source_ip", "request_body", "signaling"} {
		if bytes.Contains(auditOutput, []byte(forbidden)) {
			t.Fatalf("audit contains %q: %s", forbidden, auditOutput)
		}
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "revoke", "--yes", "--json", "--", deviceID).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("already revoked")) {
		t.Fatalf("duplicate revocation = %v\n%s", err, output)
	}
	auditOutput, err = exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "audit", "list", "--limit", "10", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	audit = nil
	if err := json.Unmarshal(auditOutput, &audit); err != nil || len(audit) != 3 || audit[0].Action != "member.revoked" {
		t.Fatalf("audit after duplicate = %+v, %v", audit, err)
	}
	revocationEvents := 0
	for _, event := range audit {
		if event.Action == "member.revoked" {
			revocationEvents++
		}
	}
	if revocationEvents != 1 {
		t.Fatalf("revocation audit events = %d, want 1: %+v", revocationEvents, audit)
	}
	revoked := readServerMessageType(t, ctx, conn, "revoked")
	if revoked.DeviceID != deviceID {
		t.Fatalf("revocation = %+v", revoked)
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}

	server = startServerProcess(t, ctx, home, address)
	waitServerReady(t, ctx, baseURL)
	failed, _, err := websocket.Dial(ctx, "ws://"+address+"/v1/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer failed.CloseNow()
	_, challengeData, err := failed.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var challenge rendezvousapi.Challenge
	if err := json.Unmarshal(challengeData, &challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := rendezvousapi.SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeServerMessage(t, ctx, failed, rendezvousapi.Authentication{Version: rendezvousapi.AuthenticationVersion, Type: "authenticate", Credential: *enrollment.Credential, Signature: signature})
	if _, _, err := failed.Read(ctx); err == nil {
		t.Fatal("revoked credential authenticated after restart")
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestServerStartupDatabaseAndListenerFailuresNeverBecomeReady(t *testing.T) {
	t.Run("database", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "px")
		if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
			t.Fatalf("init server: %v\n%s", err, output)
		}
		paths, err := apphome.Resolve(home)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(paths.ServerDatabase, 0o700); err != nil {
			t.Fatal(err)
		}
		address := reserveTCPAddress(t)
		output, err := exec.Command(binaryPath("px-server"), "--home", home, "serve", "--listen", address).CombinedOutput()
		if err == nil {
			t.Fatalf("server started with database directory: %s", output)
		}
		assertReadinessUnavailable(t, "http://"+address)
		if output, err := exec.Command(binaryPath("px-server"), "--home", home, "status", "--json").CombinedOutput(); err == nil {
			t.Fatalf("status succeeded after database startup failure: %s", output)
		}
	})

	t.Run("listener", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "px")
		if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
			t.Fatalf("init server: %v\n%s", err, output)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		output, err := exec.Command(binaryPath("px-server"), "--home", home, "serve", "--listen", listener.Addr().String()).CombinedOutput()
		if err == nil {
			t.Fatalf("server started on occupied listener: %s", output)
		}
		if output, err := exec.Command(binaryPath("px-server"), "--home", home, "status", "--json").CombinedOutput(); err == nil {
			t.Fatalf("status succeeded after listener startup failure: %s", output)
		}
	})
}

func TestServerProcessMigratesAndRestartsVersionThreeDatabase(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	createLegacyServerV3(t, paths.ServerDatabase)
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, home, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	status := serverStatus(t, ctx, home)
	if !status.Ready || !status.AuthorityAvailable || !status.DatabaseHealthy || !status.HTTPListenerReady || status.PendingEnrollments != 1 {
		t.Fatalf("migrated process status = %+v", status)
	}
	state, err := sql.Open("sqlite", database.DSN(paths.ServerDatabase))
	if err != nil {
		t.Fatal(err)
	}
	var version, facts int
	var enrollmentID string
	if err := state.QueryRow(`select version_id from goose_db_version where is_applied = 1 order by id desc limit 1`).Scan(&version); err != nil || version != 5 {
		state.Close()
		t.Fatalf("process migration version = %d, %v", version, err)
	}
	if err := state.QueryRow(`select enrollment_id from pending_enrollments where code = 'ABCD-2345'`).Scan(&enrollmentID); err != nil || len(enrollmentID) != 32 {
		state.Close()
		t.Fatalf("process enrollment ID = %q, %v", enrollmentID, err)
	}
	if err := state.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind = 'enrollment.pending_admitted'`, enrollmentID).Scan(&facts); err != nil || facts != 1 {
		state.Close()
		t.Fatalf("process backfill facts = %d, %v", facts, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
	server = startServerProcess(t, ctx, home, address)
	waitServerReady(t, ctx, "http://"+address)
	status = serverStatus(t, ctx, home)
	if !status.Ready || !status.DatabaseHealthy || status.PendingEnrollments != 1 {
		t.Fatalf("restarted migrated process status = %+v", status)
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func createLegacyServerV3(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", database.DSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements := []string{
		`create table goose_db_version (id integer primary key autoincrement, version_id bigint not null, is_applied boolean not null, tstamp timestamp default current_timestamp)`,
		`insert into goose_db_version(version_id, is_applied) values (0, 1), (1, 1), (2, 1), (3, 1)`,
		`create table app_metadata(component text primary key, created_at text not null default current_timestamp)`,
		`insert into app_metadata(component) values ('server')`,
		`create table pending_enrollments(code text primary key, device_id text not null unique, device_key text not null, label text not null, label_key text not null unique, source_ip text not null, created_at integer not null, expires_at integer not null)`,
		`create index pending_enrollments_expires_at_idx on pending_enrollments(expires_at)`,
		`create table members(device_id text primary key, device_key text not null unique, label text not null, label_key text not null unique, revision integer not null check(revision > 0), credential text not null, created_at integer not null, revoked_at integer)`,
		`create table audit_events(id integer primary key autoincrement, occurred_at integer not null, actor_type text not null, actor_device_id text, action text not null, target_device_id text, target_label text, target_revision integer)`,
		`create index audit_events_occurred_at_idx on audit_events(occurred_at)`,
		`insert into pending_enrollments(code, device_id, device_key, label, label_key, source_ip, created_at, expires_at) values ('ABCD-2345', 'legacy-device', 'legacy-key', 'legacy', 'legacy', '192.0.2.1', ?, ?)`,
	}
	now := time.Now().UTC()
	for index, statement := range statements {
		var execErr error
		if index == len(statements)-1 {
			_, execErr = db.Exec(statement, now.Unix(), now.Add(time.Hour).Unix())
		} else {
			_, execErr = db.Exec(statement)
		}
		if execErr != nil {
			t.Fatalf("create legacy v3 database statement %d: %v", index, execErr)
		}
	}
}

func assertReadinessUnavailable(t *testing.T, baseURL string) {
	t.Helper()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	response, err := client.Get(baseURL + "/readyz")
	if err == nil {
		response.Body.Close()
		t.Fatalf("readiness endpoint unexpectedly returned %s", response.Status)
	}
}

func TestServerSTUNProcess(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	httpAddress := reserveTCPAddress(t)
	stunAddress := reserveUDPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "serve", "--listen", httpAddress, "--stun-listen", stunAddress)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopAgentProcess(command)
	waitServerReady(t, ctx, "http://"+httpAddress)
	conn, err := net.Dial("udp", stunAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if _, err := conn.Write(request.Raw); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1200)
	count, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response := &stun.Message{Raw: buffer[:count]}
	if err := response.Decode(); err != nil || response.Type != stun.BindingSuccess {
		t.Fatalf("STUN response type = %v, err = %v", response.Type, err)
	}
	stopServerCommand(t, ctx, home)
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestServerListsAllActiveMembersAcrossPages(t *testing.T) {
	home := filepath.Join(t.TempDir(), "px")
	if output, err := exec.Command(binaryPath("px-server"), "--home", home, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindServer, paths.ServerDatabase)
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool, 200)
	for index := range 200 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		deviceID := identity.ID(publicKey)
		label := fmt.Sprintf("active-%03d", index)
		if _, err := databaseStore.DB().Exec(`insert into members (device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) values (?, ?, ?, ?, 1, ?, ?, ?)`,
			deviceID, deviceID, label, label, `{}`, 1_700_000_000+index, fmt.Sprintf("%032x", index+1)); err != nil {
			t.Fatal(err)
		}
		want[deviceID] = true
	}
	if err := databaseStore.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, home, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "devices", "list", "--active", "--all", "--limit", "64", "--json").Output()
	if err != nil {
		t.Fatalf("list all active members: %v\n%s", err, output)
	}
	var response serveradmin.ListDevicesResponse
	if err := json.Unmarshal(output, &response); err != nil || response.Version != serveradmin.Version || response.NextCursor != "" || len(response.Devices) != len(want) {
		t.Fatalf("active member response = version %d, count %d, cursor %q, %v", response.Version, len(response.Devices), response.NextCursor, err)
	}
	seen := make(map[string]bool, len(response.Devices))
	for _, member := range response.Devices {
		if !want[member.DeviceID] || seen[member.DeviceID] || member.RevokedAt != nil {
			t.Fatalf("unexpected active member = %+v", member)
		}
		seen[member.DeviceID] = true
	}
	stopServerCommand(t, ctx, home)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestSecureRendezvousProxyProcesses(t *testing.T) {
	dir := t.TempDir()
	serverHome := filepath.Join(dir, "server")
	agentHome := filepath.Join(dir, "agent")
	initOutput, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").Output()
	if err != nil {
		t.Fatal(err)
	}
	serverID := strings.TrimSpace(string(initOutput))
	backendAddress := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	backend := startServerProcess(t, ctx, serverHome, backendAddress, "--trusted-proxy", "127.0.0.1/32")
	defer stopAgentProcess(backend)
	waitServerReady(t, ctx, "http://"+backendAddress)

	backendURL, err := url.Parse("http://" + backendAddress)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(backendURL))
	defer proxy.Close()
	untrustedClient := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	if response, err := untrustedClient.Get(proxy.URL + "/readyz"); err == nil {
		response.Body.Close()
		t.Fatal("disposable reverse-proxy certificate was trusted by default")
	}
	response, err := proxy.Client().Get(proxy.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("proxied /readyz status = %s", response.Status)
	}
	certificateFile := filepath.Join(dir, "proxy-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	if err := os.WriteFile(certificateFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	paths, err := apphome.Resolve(agentHome)
	if err != nil {
		t.Fatal(err)
	}
	agent := exec.CommandContext(ctx, binaryPath("px"), "--home", agentHome, "agent", "run")
	agent.Env = append(os.Environ(), contextstate.EnvCAFile+"="+certificateFile)
	agent.Stdout = io.Discard
	var agentLogs bytes.Buffer
	agent.Stderr = &agentLogs
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)

	joinOutput := runPXOutput(t, ctx, agentHome, "--context", "secure", "join", proxy.URL, "--name", "secure-device", "--offered-root", filepath.Join(dir, "offered"), "--inbox-root", filepath.Join(dir, "inbox"), "--json")
	var joined contextstate.State
	if err := json.Unmarshal(joinOutput, &joined); err != nil {
		t.Fatal(err)
	}
	if joined.State != "pending" || joined.PendingCode == "" || joined.ServerID != serverID || joined.ServerURL != proxy.URL {
		t.Fatalf("secure join = %+v", joined)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", joined.PendingCode, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve secure enrollment: %v\n%s", err, output)
	}
	waitContextStates(t, ctx, agentHome, map[string]string{"secure": "connected"})

	membersOutput := runPXOutput(t, ctx, agentHome, "--context", "secure", "devices", "list", "--json")
	var members []contextstate.Device
	if err := json.Unmarshal(membersOutput, &members); err != nil || len(members) != 1 || members[0].DeviceID != joined.DeviceID || members[0].Status != "local" {
		t.Fatalf("secure WSS members = %+v, err = %v", members, err)
	}

	stopServerCommand(t, ctx, serverHome)
	if err := backend.Wait(); err != nil {
		t.Fatal(err)
	}
	waitContextStates(t, ctx, agentHome, map[string]string{"secure": "disconnected"})
	impostorHome := filepath.Join(dir, "impostor-server")
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", impostorHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init replacement authority: %v\n%s", err, output)
	}
	impostor := startServerProcess(t, ctx, impostorHome, backendAddress)
	waitServerReady(t, ctx, "http://"+backendAddress)
	// A rejected reconnect leaves the context in its existing disconnected state,
	// so there is no observable rejection edge to wait on without production hooks.
	time.Sleep(3 * time.Second)
	pinned := listContexts(t, ctx, agentHome)["secure"]
	if pinned.State != "disconnected" || pinned.ServerID != serverID {
		t.Fatalf("context accepted replacement server identity: %+v", pinned)
	}
	stopServerCommand(t, ctx, impostorHome)
	if err := impostor.Wait(); err != nil {
		t.Fatal(err)
	}
	backend = startServerProcess(t, ctx, serverHome, backendAddress, "--trusted-proxy", "127.0.0.1/32")
	waitServerReady(t, ctx, "http://"+backendAddress)
	reconnected := waitContextStates(t, ctx, agentHome, map[string]string{"secure": "connected"})
	if reconnected["secure"].ServerID != serverID {
		t.Fatalf("server identity changed after WSS reconnect: %+v", reconnected["secure"])
	}
	membersOutput = runPXOutput(t, ctx, agentHome, "--context", "secure", "devices", "list", "--json")
	if err := json.Unmarshal(membersOutput, &members); err != nil || len(members) != 1 || members[0].Status != "local" {
		t.Fatalf("member operation after WSS reconnect = %+v, err = %v", members, err)
	}

	stopAgentCommand(t, ctx, agentHome)
	if err := agent.Wait(); err != nil {
		t.Fatalf("stop secure agent: %v\n%s", err, agentLogs.String())
	}
	stopServerCommand(t, ctx, serverHome)
	if err := backend.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentContextProcesses(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "agent")
	serverHomes := []string{filepath.Join(dir, "server-home"), filepath.Join(dir, "server-work")}
	addresses := []string{reserveTCPAddress(t), reserveTCPAddress(t)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	servers := make([]*exec.Cmd, 0, len(serverHomes))
	for index, serverHome := range serverHomes {
		if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
			t.Fatalf("init server %d: %v\n%s", index, err, output)
		}
		server := startServerProcess(t, ctx, serverHome, addresses[index])
		servers = append(servers, server)
		defer stopAgentProcess(server)
		waitServerReady(t, ctx, "http://"+addresses[index])
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	agent := startAgentProcess(t, ctx, home)
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	sharedOffered := filepath.Join(dir, "offered")
	sharedInbox := filepath.Join(dir, "inbox")

	states := make(map[string]contextstate.State)
	for index, name := range []string{"home", "work"} {
		output := runPXOutput(t, ctx, home, "--context", name, "join", "http://"+addresses[index], "--name", name+"-device", "--offered-root", sharedOffered, "--inbox-root", sharedInbox, "--json")
		var state contextstate.State
		if err := json.Unmarshal(output, &state); err != nil {
			t.Fatalf("decode %s join: %v\n%s", name, err, output)
		}
		if state.State != "pending" || state.PendingCode == "" {
			t.Fatalf("%s join = %+v", name, state)
		}
		states[name] = state
	}
	if states["home"].DeviceID == states["work"].DeviceID || states["home"].ServerID == states["work"].ServerID {
		t.Fatalf("home = %+v, work = %+v", states["home"], states["work"])
	}
	if states["home"].OfferedRoot != states["work"].OfferedRoot || states["home"].InboxRoot != states["work"].InboxRoot {
		t.Fatal("context roots differ")
	}

	type waitingJoin struct {
		command *exec.Cmd
		decoder *json.Decoder
		stderr  bytes.Buffer
	}
	waiting := make(map[string]*waitingJoin)
	for index, name := range []string{"home", "work"} {
		command := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", name, "join", "http://"+addresses[index], "--name", name+"-device", "--offered-root", sharedOffered, "--inbox-root", sharedInbox, "--wait", "--json")
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		process := &waitingJoin{command: command, decoder: json.NewDecoder(stdout)}
		command.Stderr = &process.stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		var pending contextstate.State
		if err := process.decoder.Decode(&pending); err != nil || pending.State != "pending" {
			t.Fatalf("%s waiting join initial state = %+v, err = %v\n%s", name, pending, err, process.stderr.String())
		}
		waiting[name] = process
	}
	for index, name := range []string{"home", "work"} {
		code := states[name].PendingCode
		if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHomes[index], "devices", "approve", code, "--json").CombinedOutput(); err != nil {
			t.Fatalf("approve %s: %v\n%s", name, err, output)
		}
	}
	for _, name := range []string{"home", "work"} {
		process := waiting[name]
		var approved contextstate.State
		if err := process.decoder.Decode(&approved); err != nil {
			t.Fatalf("decode %s approval: %v\n%s", name, err, process.stderr.String())
		}
		if approved.State != "enrolled" && approved.State != "connected" {
			t.Fatalf("%s approval state = %+v", name, approved)
		}
		if err := process.command.Wait(); err != nil {
			t.Fatalf("wait for %s join: %v\n%s", name, err, process.stderr.String())
		}
	}

	connected := waitContextStates(t, ctx, home, map[string]string{"home": "connected", "work": "connected"})
	for _, name := range []string{"home", "work"} {
		runPXOutput(t, ctx, home, "--context", name, "context", "alias", "set", "vm", name+"-peer", "--json")
	}
	connected = listContexts(t, ctx, home)
	if connected["home"].Aliases["vm"] != "home-peer" || connected["work"].Aliases["vm"] != "work-peer" {
		t.Fatalf("home aliases = %+v, work aliases = %+v", connected["home"].Aliases, connected["work"].Aliases)
	}
	showOutput := runPXOutput(t, ctx, home, "--context", "home", "context", "show", "--json")
	var shown contextstate.Configuration
	if err := json.Unmarshal(showOutput, &shown); err != nil || shown.Name != "home" || !shown.IsDefault || shown.ServerOrigin != "http://"+addresses[0] || shown.ServerID != states["home"].ServerID || shown.DeviceID != states["home"].DeviceID || shown.Label != "home-device" || len(shown.Warnings) != 2 || len(shown.Aliases) != 1 {
		t.Fatalf("shown configuration = %+v, %v\n%s", shown, err, showOutput)
	}
	for _, forbidden := range []string{"credential", "private_key", "private_path", "pending_code", "resume_token", "endpoint", "signature"} {
		if bytes.Contains(bytes.ToLower(showOutput), []byte(forbidden)) {
			t.Fatalf("context show exposed %q: %s", forbidden, showOutput)
		}
	}
	plainShow := runPXOutput(t, ctx, home, "context", "show", "home")
	for _, field := range []string{"name\thome", "is_default\ttrue", "server_origin\thttp://" + addresses[0], "offered_root\t" + canonicalPath(t, sharedOffered), "alias\tvm=home-peer"} {
		if !bytes.Contains(plainShow, []byte(field)) {
			t.Fatalf("plain context show missing %q: %s", field, plainShow)
		}
	}
	aliasList := runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "list", "--json")
	var aliases []contextstate.Alias
	if err := json.Unmarshal(aliasList, &aliases); err != nil || len(aliases) != 1 || aliases[0].Name != "vm" || aliases[0].Target != "home-peer" {
		t.Fatalf("alias list = %+v, %v", aliases, err)
	}
	aliasShow := runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "show", "vm", "--json")
	var shownAlias contextstate.Alias
	if err := json.Unmarshal(aliasShow, &shownAlias); err != nil || shownAlias != aliases[0] {
		t.Fatalf("alias show = %+v, %v", shownAlias, err)
	}
	runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "remove", "vm", "--json")
	absentAlias := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "home", "context", "alias", "remove", "VM")
	if output, err := absentAlias.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("context alias not found")) {
		t.Fatalf("absent alias removal = %v\n%s", err, output)
	}
	runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "set", "Build", "first-peer", "--json")
	runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "set", "build", "second-peer", "--json")
	caseListOutput := runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "list", "--json")
	var caseAliases []contextstate.Alias
	if err := json.Unmarshal(caseListOutput, &caseAliases); err != nil || len(caseAliases) != 2 || caseAliases[0].Name != "Build" || caseAliases[1].Name != "build" {
		t.Fatalf("case-sensitive alias list = %+v, %v", caseAliases, err)
	}
	for _, value := range caseAliases {
		output := runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "show", value.Name, "--json")
		var shownValue contextstate.Alias
		if err := json.Unmarshal(output, &shownValue); err != nil || shownValue != value {
			t.Fatalf("case-sensitive alias show = %+v, %v", shownValue, err)
		}
		runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "remove", value.Name, "--json")
	}
	runPXOutput(t, ctx, home, "--context", "home", "context", "alias", "set", "vm", "home-peer", "--json")

	updatedOffered := filepath.Join(dir, "updated-offered")
	updatedInbox := filepath.Join(dir, "updated-inbox")
	for _, root := range []string{updatedOffered, updatedInbox} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configureOutput := runPXOutput(t, ctx, home, "--context", "home", "context", "configure", "--offered-root", updatedOffered, "--inbox-root", updatedInbox, "--stun", "stun:first.example:3478", "--stun", "stun:second.example:3478", "--json")
	var configured contextstate.Configuration
	if err := json.Unmarshal(configureOutput, &configured); err != nil || configured.OfferedRoot != canonicalPath(t, updatedOffered) || configured.InboxRoot != canonicalPath(t, updatedInbox) || strings.Join(configured.STUNURLs, ",") != "stun:first.example:3478,stun:second.example:3478" || len(configured.Warnings) != 0 {
		t.Fatalf("configured context = %+v, %v\n%s", configured, err, configureOutput)
	}
	waitContextStates(t, ctx, home, map[string]string{"home": "connected", "work": "connected"})
	invalidConfigure := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "home", "context", "configure", "--offered-root", filepath.Join(dir, "invalid-root"), "--stun", "turn:relay.example:3478", "--json")
	if err := os.Mkdir(filepath.Join(dir, "invalid-root"), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := invalidConfigure.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("invalid STUN URL")) {
		t.Fatalf("invalid configuration = %v\n%s", err, output)
	}
	afterInvalidOutput := runPXOutput(t, ctx, home, "--context", "home", "context", "show", "--json")
	var afterInvalid contextstate.Configuration
	if err := json.Unmarshal(afterInvalidOutput, &afterInvalid); err != nil || afterInvalid.OfferedRoot != canonicalPath(t, updatedOffered) || !slices.Equal(afterInvalid.STUNURLs, configured.STUNURLs) {
		t.Fatalf("invalid configuration persisted = %+v, %v", afterInvalid, err)
	}
	clearOutput := runPXOutput(t, ctx, home, "--context", "home", "context", "configure", "--clear-stun", "--json")
	if err := json.Unmarshal(clearOutput, &configured); err != nil || configured.STUNURLs == nil || len(configured.STUNURLs) != 0 {
		t.Fatalf("cleared STUN = %+v, %v\n%s", configured, err, clearOutput)
	}
	waitContextStates(t, ctx, home, map[string]string{"home": "connected", "work": "connected"})
	updatedReport, _, updatedDoctorErr := runDoctorProcess(ctx, home, "--context", "home")
	if updatedDoctorErr != nil || diagnosticCheck(updatedReport, "local.offered_root").Status != diagnostics.Pass || diagnosticCheck(updatedReport, "local.inbox_root").Status != diagnostics.Pass {
		t.Fatalf("updated-root doctor = %+v, %v", updatedReport, updatedDoctorErr)
	}
	runPXOutput(t, ctx, home, "context", "default", "work", "--json")
	if current := strings.TrimSpace(string(runPXOutput(t, ctx, home, "context", "current"))); current != "work" {
		t.Fatalf("default current = %q", current)
	}
	envCommand := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "current")
	envCommand.Env = append(os.Environ(), "PX_CONTEXT=home")
	if output, err := envCommand.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "home" {
		t.Fatalf("environment current: %v, %q", err, output)
	}
	explicitCommand := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "work", "context", "current")
	explicitCommand.Env = append(os.Environ(), "PX_CONTEXT=home")
	if output, err := explicitCommand.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "work" {
		t.Fatalf("explicit current: %v, %q", err, output)
	}
	envShow := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "show", "--json")
	envShow.Env = append(os.Environ(), "PX_CONTEXT=home")
	if output, err := envShow.Output(); err != nil || json.Unmarshal(output, &shown) != nil || shown.Name != "home" {
		t.Fatalf("environment context show: %v, %+v, %q", err, shown, output)
	}
	explicitShow := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "show", "work", "--json")
	explicitShow.Env = append(os.Environ(), "PX_CONTEXT=home")
	if output, err := explicitShow.Output(); err != nil || json.Unmarshal(output, &shown) != nil || shown.Name != "work" || !shown.IsDefault {
		t.Fatalf("explicit context show: %v, %+v, %q", err, shown, output)
	}
	disabledOutput := runPXOutput(t, ctx, home, "context", "disable", "home", "--json")
	var disabled contextstate.State
	if err := json.Unmarshal(disabledOutput, &disabled); err != nil || disabled.Enabled || disabled.DeviceID != states["home"].DeviceID {
		t.Fatalf("disabled context = %+v, %v\n%s", disabled, err, disabledOutput)
	}
	if current := listContexts(t, ctx, home); current["work"].State != "connected" {
		t.Fatalf("disabling home affected work: %+v", current)
	}

	stopAgentCommand(t, ctx, home)
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	agent = startAgentProcess(t, ctx, home)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	waitContextStates(t, ctx, home, map[string]string{"home": "disconnected", "work": "connected"})
	afterRestart := listContexts(t, ctx, home)
	if afterRestart["home"].Enabled || afterRestart["home"].OfferedRoot != canonicalPath(t, updatedOffered) || afterRestart["home"].InboxRoot != canonicalPath(t, updatedInbox) || len(afterRestart["home"].STUNURLs) != 0 || afterRestart["home"].Aliases["vm"] != "home-peer" {
		t.Fatalf("disabled context re-enabled after restart: %+v", afterRestart["home"])
	}
	enabledOutput := runPXOutput(t, ctx, home, "context", "enable", "home", "--json")
	var enabled contextstate.State
	if err := json.Unmarshal(enabledOutput, &enabled); err != nil || !enabled.Enabled || enabled.DeviceID != states["home"].DeviceID {
		t.Fatalf("enabled context = %+v, %v\n%s", enabled, err, enabledOutput)
	}
	waitContextStates(t, ctx, home, map[string]string{"home": "connected", "work": "connected"})
	rejoinedOutput := runPXOutput(t, ctx, home, "--context", "home", "join", "http://"+addresses[0], "--name", "home-device", "--offered-root", sharedOffered, "--inbox-root", sharedInbox, "--json")
	var rejoined contextstate.State
	if err := json.Unmarshal(rejoinedOutput, &rejoined); err != nil {
		t.Fatal(err)
	}
	if rejoined.DeviceID != states["home"].DeviceID || rejoined.State != "connected" {
		t.Fatalf("idempotent join = %+v", rejoined)
	}
	if err := os.MkdirAll(sharedOffered, 0o700); err != nil {
		t.Fatal(err)
	}
	rootMarker := filepath.Join(sharedOffered, "preserved.txt")
	if err := os.WriteFile(rootMarker, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "remove", "home").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("requires --yes")) {
		t.Fatalf("unconfirmed removal error = %v\n%s", err, output)
	}
	runPXOutput(t, ctx, home, "context", "default", "home")
	removeOutput := runPXOutput(t, ctx, home, "context", "remove", "home", "--yes", "--json")
	var removed map[string]string
	if err := json.Unmarshal(removeOutput, &removed); err != nil || removed["name"] != "home" {
		t.Fatalf("removed context = %+v, %v\n%s", removed, err, removeOutput)
	}
	remaining := listContexts(t, ctx, home)
	if _, exists := remaining["home"]; exists || remaining["work"].State != "connected" {
		t.Fatalf("contexts after removal = %+v", remaining)
	}
	if content, err := os.ReadFile(rootMarker); err != nil || string(content) != "preserved" {
		t.Fatalf("offered root marker = %q, %v", content, err)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "context", "current").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("default context is not configured")) {
		t.Fatalf("removed default context = %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHomes[1], "devices", "revoke", "--yes", "--json", "--", states["work"].DeviceID).CombinedOutput(); err != nil {
		t.Fatalf("revoke work: %v\n%s", err, output)
	}
	waitContextStates(t, ctx, home, map[string]string{"work": "revoked"})
	revokedReport, _, doctorErr := runDoctorProcess(ctx, home, "--context", "work")
	if doctorErr == nil || diagnosticCheck(revokedReport, "context.enrollment").Status != diagnostics.Fail || diagnosticCheck(revokedReport, "context.heartbeat").Status != diagnostics.Skipped {
		t.Fatalf("revoked doctor = %+v, %v", revokedReport, doctorErr)
	}
	for _, check := range revokedReport.Checks {
		if check.Context != "" && check.Context != "work" {
			t.Fatalf("--context work included another context: %+v", check)
		}
	}

	stopAgentCommand(t, ctx, home)
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	for index, server := range servers {
		stopServerCommand(t, ctx, serverHomes[index])
		if err := server.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOnboardProcesses(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "agent")
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	create := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "create", "invited-device", "--expires", "1h")
	var createOutput, createErrors bytes.Buffer
	create.Stdout, create.Stderr = &createOutput, &createErrors
	if err := create.Run(); err != nil {
		t.Fatalf("create bootstrap invite: %v (stdout_bytes=%d stderr_bytes=%d)", err, createOutput.Len(), createErrors.Len())
	}
	inviteToken := strings.TrimSpace(createOutput.String())
	parsedInvite, err := membership.ParseInviteToken(inviteToken)
	bootstrapStderrLeak := inviteMaterialPresent(createErrors.Bytes(), inviteToken, parsedInvite)
	if err != nil || bootstrapStderrLeak || strings.Count(createOutput.String(), "\n") != 1 {
		t.Fatalf("bootstrap invite separation: parse_error=%v stdout_bytes=%d stdout_lines=%d stderr_bytes=%d stderr_leak=%t", err, createOutput.Len(), strings.Count(createOutput.String(), "\n"), createErrors.Len(), bootstrapStderrLeak)
	}
	inviteID := fmt.Sprintf("%x", parsedInvite.InviteID)
	listOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "list", "--json").Output()
	var activeInvites serveradmin.InviteList
	listDecodeErr := json.Unmarshal(listOutput, &activeInvites)
	listLeak := inviteMaterialPresent(listOutput, inviteToken, parsedInvite)
	if err != nil || listDecodeErr != nil || len(activeInvites.Invites) != 1 || activeInvites.Invites[0].InviteID != inviteID || listLeak || bytes.Contains(listOutput, []byte("token")) {
		t.Fatalf("bootstrap invite list: command_error=%v decode_error=%v count=%d id_matches=%t output_bytes=%d bearer_leak=%t token_field=%t", err, listDecodeErr, len(activeInvites.Invites), len(activeInvites.Invites) == 1 && activeInvites.Invites[0].InviteID == inviteID, len(listOutput), listLeak, bytes.Contains(listOutput, []byte("token")))
	}
	stopServerCommand(t, ctx, serverHome)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
	server = startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	listOutput, err = exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "list", "--json").Output()
	activeInvites = serveradmin.InviteList{}
	listDecodeErr = json.Unmarshal(listOutput, &activeInvites)
	if err != nil || listDecodeErr != nil || len(activeInvites.Invites) != 1 || activeInvites.Invites[0].InviteID != inviteID {
		t.Fatalf("restart invite list: command_error=%v decode_error=%v count=%d id_matches=%t output_bytes=%d", err, listDecodeErr, len(activeInvites.Invites), len(activeInvites.Invites) == 1 && activeInvites.Invites[0].InviteID == inviteID, len(listOutput))
	}
	revocableOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "create", "revoke-before-use", "--json").Output()
	var revocable serveradmin.InviteCreation
	revocableDecodeErr := json.Unmarshal(revocableOutput, &revocable)
	revocableParsed, revocableParseErr := membership.ParseInviteToken(revocable.Token)
	if err != nil || revocableDecodeErr != nil || revocableParseErr != nil || revocable.Version != serveradmin.InviteVersion {
		t.Fatalf("create JSON invite: command_error=%v decode_error=%v token_parse_error=%v version=%d output_bytes=%d token_length=%d", err, revocableDecodeErr, revocableParseErr, revocable.Version, len(revocableOutput), len(revocable.Token))
	}
	revokedOutput, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "revoke", revocable.InviteID, "--yes", "--json").Output()
	var revokedInvite serveradmin.InviteRevocation
	revokedDecodeErr := json.Unmarshal(revokedOutput, &revokedInvite)
	revokedLeak := inviteMaterialPresent(revokedOutput, revocable.Token, revocableParsed)
	if err != nil || revokedDecodeErr != nil || revokedInvite.Version != serveradmin.InviteVersion || revokedInvite.State != "revoked" || revokedInvite.Invite.InviteID != revocable.InviteID || revokedLeak {
		t.Fatalf("revoke JSON invite: command_error=%v decode_error=%v version=%d state_matches=%t id_matches=%t output_bytes=%d bearer_leak=%t", err, revokedDecodeErr, revokedInvite.Version, revokedInvite.State == "revoked", revokedInvite.Invite.InviteID == revocable.InviteID, len(revokedOutput), revokedLeak)
	}
	listOutput, err = exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "invite", "list", "--json").Output()
	activeInvites = serveradmin.InviteList{}
	listDecodeErr = json.Unmarshal(listOutput, &activeInvites)
	listLeak = inviteMaterialPresent(listOutput, revocable.Token, revocableParsed)
	if err != nil || listDecodeErr != nil || len(activeInvites.Invites) != 1 || activeInvites.Invites[0].InviteID != inviteID || listLeak {
		t.Fatalf("invite list after revoke: command_error=%v decode_error=%v count=%d id_matches=%t output_bytes=%d bearer_leak=%t", err, listDecodeErr, len(activeInvites.Invites), len(activeInvites.Invites) == 1 && activeInvites.Invites[0].InviteID == inviteID, len(listOutput), listLeak)
	}
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	var initialInviteAgentLogs bytes.Buffer
	agent := startAgentProcessWithStderr(t, ctx, home, &initialInviteAgentLogs)
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	inviteFile := filepath.Join(dir, "invite.txt")
	if err := os.WriteFile(inviteFile, []byte(inviteToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inviteOutput := runPXSensitiveOutput(t, ctx, home, [][]byte{[]byte(inviteToken), inviteSecret(parsedInvite)}, "--context", "invited", "onboard", "http://"+address, "--name", "invited-device", "--offered-root", filepath.Join(dir, "invite-shared"), "--inbox-root", filepath.Join(dir, "invite-inbox"), "--no-stun", "--invite-file", inviteFile, "--yes", "--wait", "--json")
	var invited contextstate.State
	if err := json.NewDecoder(bytes.NewReader(inviteOutput)).Decode(&invited); err != nil || invited.State != "enrolled" || invited.PendingCode != "" {
		t.Fatalf("invite onboarding = %+v, %v\n%s", invited, err, inviteOutput)
	}
	waitContextStates(t, ctx, home, map[string]string{"invited": "connected"})
	memberCreate := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "invited", "invite", "create", "member-invited", "--expires", "1h")
	var memberCreateOutput, memberCreateErrors bytes.Buffer
	memberCreate.Stdout, memberCreate.Stderr = &memberCreateOutput, &memberCreateErrors
	if err := memberCreate.Run(); err != nil {
		t.Fatalf("member invite create: %v (stdout_bytes=%d stderr_bytes=%d)", err, memberCreateOutput.Len(), memberCreateErrors.Len())
	}
	memberToken := strings.TrimSpace(memberCreateOutput.String())
	memberParsed, err := membership.ParseInviteToken(memberToken)
	memberStderrLeak := inviteMaterialPresent(memberCreateErrors.Bytes(), memberToken, memberParsed)
	if err != nil || memberStderrLeak || strings.Count(memberCreateOutput.String(), "\n") != 1 {
		t.Fatalf("member invite separation: parse_error=%v stdout_bytes=%d stdout_lines=%d stderr_bytes=%d stderr_leak=%t", err, memberCreateOutput.Len(), strings.Count(memberCreateOutput.String(), "\n"), memberCreateErrors.Len(), memberStderrLeak)
	}
	memberInviteID := fmt.Sprintf("%x", memberParsed.InviteID)
	memberListOutput, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "invited", "invite", "list", "--json").Output()
	var memberInvites serveradmin.InviteList
	memberListDecodeErr := json.Unmarshal(memberListOutput, &memberInvites)
	memberListLeak := inviteMaterialPresent(memberListOutput, memberToken, memberParsed)
	if err != nil || memberListDecodeErr != nil || len(memberInvites.Invites) != 1 || memberInvites.Invites[0].InviteID != memberInviteID || memberInvites.Invites[0].IssuerType != "member" || memberListLeak || bytes.Contains(memberListOutput, []byte(`"token"`)) {
		t.Fatalf("member invite list: command_error=%v decode_error=%v count=%d id_matches=%t issuer_matches=%t output_bytes=%d bearer_leak=%t token_field=%t", err, memberListDecodeErr, len(memberInvites.Invites), len(memberInvites.Invites) == 1 && memberInvites.Invites[0].InviteID == memberInviteID, len(memberInvites.Invites) == 1 && memberInvites.Invites[0].IssuerType == "member", len(memberListOutput), memberListLeak, bytes.Contains(memberListOutput, []byte(`"token"`)))
	}
	memberRevokedOutput, err := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "--context", "invited", "invite", "revoke", memberInviteID, "--yes", "--json").Output()
	var memberRevoked serveradmin.InviteRevocation
	memberRevokedDecodeErr := json.Unmarshal(memberRevokedOutput, &memberRevoked)
	memberRevokedLeak := inviteMaterialPresent(memberRevokedOutput, memberToken, memberParsed)
	if err != nil || memberRevokedDecodeErr != nil || memberRevoked.State != "revoked" || memberRevoked.Invite.InviteID != memberInviteID || memberRevokedLeak {
		t.Fatalf("member invite revoke: command_error=%v decode_error=%v state_matches=%t id_matches=%t output_bytes=%d bearer_leak=%t", err, memberRevokedDecodeErr, memberRevoked.State == "revoked", memberRevoked.Invite.InviteID == memberInviteID, len(memberRevokedOutput), memberRevokedLeak)
	}
	if databaseBytes, err := os.ReadFile(paths.AgentDatabase); err != nil || inviteMaterialPresent(databaseBytes, inviteToken, parsedInvite) || inviteMaterialPresent(databaseBytes, memberToken, memberParsed) {
		t.Fatalf("agent invite persistence: error=%v database_bytes=%d onboarding_bearer_present=%t member_bearer_present=%t", err, len(databaseBytes), inviteMaterialPresent(databaseBytes, inviteToken, parsedInvite), inviteMaterialPresent(databaseBytes, memberToken, memberParsed))
	}
	stopAgentCommand(t, ctx, home)
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	initialOnboardingLogLeak := inviteMaterialPresent(initialInviteAgentLogs.Bytes(), inviteToken, parsedInvite)
	initialMemberLogLeak := inviteMaterialPresent(initialInviteAgentLogs.Bytes(), memberToken, memberParsed)
	if initialOnboardingLogLeak || initialMemberLogLeak {
		t.Fatalf("initial agent logs contain invite bearer material: log_bytes=%d onboarding_bearer_present=%t member_bearer_present=%t", initialInviteAgentLogs.Len(), initialOnboardingLogLeak, initialMemberLogLeak)
	}
	var inviteAgentLogs bytes.Buffer
	agent = startAgentProcessWithStderr(t, ctx, home, &inviteAgentLogs)
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	replayed := runPXSensitiveOutput(t, ctx, home, [][]byte{[]byte(inviteToken), inviteSecret(parsedInvite), []byte(memberToken), inviteSecret(memberParsed)}, "--context", "invited", "onboard", "http://"+address, "--name", "invited-device", "--offered-root", filepath.Join(dir, "invite-shared"), "--inbox-root", filepath.Join(dir, "invite-inbox"), "--no-stun", "--invite-file", inviteFile, "--yes", "--wait", "--json")
	var replayedState contextstate.State
	if err := json.NewDecoder(bytes.NewReader(replayed)).Decode(&replayedState); err != nil || replayedState.DeviceID != invited.DeviceID {
		t.Fatalf("restart replay state = %+v, %v", replayedState, err)
	}
	insecureArgs := []string{"--home", home, "--context", "insecure-invite", "onboard", "http://192.0.2.1", "--name", "insecure-device", "--offered-root", filepath.Join(dir, "insecure-shared"), "--inbox-root", filepath.Join(dir, "insecure-inbox"), "--no-stun", "--invite", inviteToken, "--yes", "--json"}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), insecureArgs...).CombinedOutput(); err == nil || inviteMaterialPresent(output, inviteToken, parsedInvite) || inviteMaterialPresent(output, memberToken, memberParsed) || !bytes.Contains(output, []byte("requires HTTPS")) {
		t.Fatalf("insecure invite result: command_failed=%t output_bytes=%d onboarding_bearer_present=%t member_bearer_present=%t guidance_present=%t", err != nil, len(output), inviteMaterialPresent(output, inviteToken, parsedInvite), inviteMaterialPresent(output, memberToken, memberParsed), bytes.Contains(output, []byte("requires HTTPS")))
	}
	offeredRoot := filepath.Join(dir, "shared")
	inboxRoot := filepath.Join(dir, "inbox")
	baseArgs := []string{"--home", home, "--context", "home", "onboard", "http://" + address, "--name", "laptop", "--offered-root", offeredRoot, "--inbox-root", inboxRoot, "--no-stun", "--json"}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), baseArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("requires --yes")) {
		t.Fatalf("unconfirmed onboarding error = %v\n%s", err, output)
	}
	if _, err := os.Stat(offeredRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfirmed onboarding created roots: %v", err)
	}

	waitArgs := append(append([]string{}, baseArgs...), "--yes", "--wait")
	command := exec.CommandContext(ctx, binaryPath("px"), waitArgs...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(stdout)
	var pending contextstate.State
	if err := decoder.Decode(&pending); err != nil || pending.State != "pending" || pending.PendingCode == "" {
		t.Fatalf("pending onboarding = %+v, %v\n%s", pending, err, stderr.String())
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", pending.PendingCode, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve onboarding: %v\n%s", err, output)
	}
	connected := false
	var report diagnostics.Report
	for decoder.More() {
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(value, &shape); err != nil {
			t.Fatal(err)
		}
		if _, ok := shape["checks"]; ok {
			if err := json.Unmarshal(value, &report); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var state contextstate.State
		if err := json.Unmarshal(value, &state); err != nil {
			t.Fatal(err)
		}
		connected = connected || state.State == "connected"
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("onboard: %v\n%s", err, stderr.String())
	}
	if !connected || report.Status != diagnostics.Pass {
		t.Fatalf("onboarding connected = %v, report = %+v", connected, report)
	}
	for _, path := range []string{offeredRoot, inboxRoot} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("onboarding root %q = %v, %v", path, info, err)
		}
	}

	idempotentArgs := append(append([]string{}, baseArgs...), "--yes")
	idempotent := exec.CommandContext(ctx, binaryPath("px"), idempotentArgs...)
	idempotentOutput, err := idempotent.Output()
	if err != nil {
		t.Fatal(err)
	}
	idempotentDecoder := json.NewDecoder(bytes.NewReader(idempotentOutput))
	var same contextstate.State
	if err := idempotentDecoder.Decode(&same); err != nil || same.DeviceID != pending.DeviceID {
		t.Fatalf("idempotent onboarding = %+v, %v", same, err)
	}
	mismatchArgs := append(append([]string{}, baseArgs...), "--yes", "--inbox-root", filepath.Join(dir, "other-inbox"))
	if output, err := exec.CommandContext(ctx, binaryPath("px"), mismatchArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("different settings")) {
		t.Fatalf("mismatched onboarding error = %v\n%s", err, output)
	}
	runPXOutput(t, ctx, home, "context", "disable", "home")
	if output, err := exec.CommandContext(ctx, binaryPath("px"), idempotentArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("is disabled")) {
		t.Fatalf("disabled onboarding error = %v\n%s", err, output)
	}
	runPXOutput(t, ctx, home, "context", "enable", "home")
	waitContextStates(t, ctx, home, map[string]string{"home": "connected"})

	cancelContext, cancelOnboard := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancelOnboard()
	cancelArgs := []string{"--home", home, "--context", "cancelled", "onboard", "http://" + address, "--name", "cancel-device", "--offered-root", filepath.Join(dir, "cancel-shared"), "--inbox-root", filepath.Join(dir, "cancel-inbox"), "--no-stun", "--yes", "--wait", "--json"}
	if output, err := exec.CommandContext(cancelContext, binaryPath("px"), cancelArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte(`"state":"pending"`)) {
		t.Fatalf("cancelled onboarding error = %v\n%s", err, output)
	}
	contexts := listContexts(t, ctx, home)
	if contexts["cancelled"].State != "pending" || contexts["home"].State != "connected" {
		t.Fatalf("contexts after cancellation = %+v", contexts)
	}
	if runtime.GOOS != "windows" {
		userHome := filepath.Join(dir, "user-home")
		defaultArgs := []string{"--home", home, "--context", "defaults", "onboard", "http://" + address, "--name", "default-device", "--yes", "--json"}
		defaultCommand := exec.CommandContext(ctx, binaryPath("px"), defaultArgs...)
		defaultCommand.Env = append(os.Environ(), "HOME="+userHome, "USERPROFILE="+userHome)
		defaultOutput, err := defaultCommand.Output()
		if err != nil {
			t.Fatal(err)
		}
		var defaults contextstate.State
		if err := json.Unmarshal(defaultOutput, &defaults); err != nil {
			t.Fatal(err)
		}
		wantOffered := filepath.Join(userHome, ".local", "share", "px", "shared")
		wantInbox := filepath.Join(userHome, ".local", "share", "px", "inbox")
		if defaults.OfferedRoot != canonicalPath(t, wantOffered) || defaults.InboxRoot != canonicalPath(t, wantInbox) {
			t.Fatalf("default roots = %q, %q", defaults.OfferedRoot, defaults.InboxRoot)
		}
		if !slices.Equal(defaults.STUNURLs, []string{contextstate.DefaultSTUNURL}) {
			t.Fatalf("default STUN = %v", defaults.STUNURLs)
		}
	}

	guidanceArgs := []string{"--home", home, "--context", "guidance", "onboard", "http://" + address, "--name", "guide-device", "--offered-root", filepath.Join(dir, "guide-shared"), "--inbox-root", filepath.Join(dir, "guide-inbox"), "--no-stun", "--yes"}
	guidanceOutput, err := exec.CommandContext(ctx, binaryPath("px"), guidanceArgs...).Output()
	if err != nil || bytes.Count(guidanceOutput, []byte("px --context guidance devices approve")) != 1 || bytes.Count(guidanceOutput, []byte("px-server devices approve")) != 1 {
		t.Fatalf("approval guidance = %q, %v", guidanceOutput, err)
	}

	missingHome := filepath.Join(dir, "missing-agent")
	missingArgs := []string{"--home", missingHome, "onboard", "http://" + address, "--yes"}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), missingArgs...).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("agent is not reachable")) {
		t.Fatalf("missing-agent onboarding error = %v\n%s", err, output)
	}
	stopAgentCommand(t, ctx, home)
	if err := agent.Wait(); err != nil {
		t.Fatal(err)
	}
	restartedOnboardingLogLeak := inviteMaterialPresent(inviteAgentLogs.Bytes(), inviteToken, parsedInvite)
	restartedMemberLogLeak := inviteMaterialPresent(inviteAgentLogs.Bytes(), memberToken, memberParsed)
	if restartedOnboardingLogLeak || restartedMemberLogLeak {
		t.Fatalf("restarted agent logs contain invite bearer material: log_bytes=%d onboarding_bearer_present=%t member_bearer_present=%t", inviteAgentLogs.Len(), restartedOnboardingLogLeak, restartedMemberLogLeak)
	}
	stopServerCommand(t, ctx, serverHome)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestOnboardDefaultContextProcess(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "agent")
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	agent := startAgentProcess(t, ctx, home)
	defer stopAgentProcess(agent)
	waitAgentStatus(t, ctx, paths.AgentEndpoint)

	args := []string{"onboard", "http://" + address, "--name", "default-device", "--offered-root", filepath.Join(dir, "shared"), "--inbox-root", filepath.Join(dir, "inbox"), "--no-stun", "--yes", "--json"}
	output := runPXOutput(t, ctx, home, args...)
	var pending contextstate.State
	if err := json.Unmarshal(output, &pending); err != nil || pending.Name != "default" || pending.State != "pending" {
		t.Fatalf("default context onboarding = %+v, %v\n%s", pending, err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", pending.PendingCode, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve default context: %v\n%s", err, output)
	}
	connected := waitContextStates(t, ctx, home, map[string]string{"default": "connected"})["default"]

	var fetched contextstate.State
	if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", "/v1/contexts/default", nil, &fetched); err != nil || fetched.DeviceID != connected.DeviceID || !fetched.Enabled {
		t.Fatalf("fetch default-named context = %+v, %v", fetched, err)
	}
	var selected map[string]string
	if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", "/v1/default-context", nil, &selected); err != nil || selected["name"] != "default" {
		t.Fatalf("fetch default selection = %+v, %v", selected, err)
	}
}

func TestOfferedRootProcesses(t *testing.T) {
	dir := t.TempDir()
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	stunAddress := reserveUDPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	server := startServerWithSTUNProcess(t, ctx, serverHome, address, stunAddress)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	homes := []string{filepath.Join(dir, "laptop-home"), filepath.Join(dir, "vm-home"), filepath.Join(dir, "clear-home")}
	offeredRoots := []string{filepath.Join(dir, "laptop-offered"), filepath.Join(dir, "vm-offered"), filepath.Join(dir, "clear-offered")}
	inboxRoots := []string{filepath.Join(dir, "laptop-inbox"), filepath.Join(dir, "vm-inbox"), filepath.Join(dir, "clear-inbox")}
	labels := []string{"laptop", "vm", "clear"}
	agents := make([]*exec.Cmd, 0, len(homes))
	agentLogs := make([]bytes.Buffer, len(homes))
	for index := range homes {
		if err := os.MkdirAll(offeredRoots[index], 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(inboxRoots[index], 0o700); err != nil {
			t.Fatal(err)
		}
		agent := startAgentProcessWithStderr(t, ctx, homes[index], &agentLogs[index])
		agents = append(agents, agent)
		defer stopAgentProcess(agent)
		paths, err := apphome.Resolve(homes[index])
		if err != nil {
			t.Fatal(err)
		}
		waitAgentStatus(t, ctx, paths.AgentEndpoint)
		joinArgs := []string{"--context", "home", "join", "http://" + address, "--name", labels[index], "--offered-root", offeredRoots[index], "--inbox-root", inboxRoots[index], "--json"}
		if index == 0 {
			joinArgs = append(joinArgs, "--stun", "stun:"+stunAddress)
		} else {
			joinArgs = append(joinArgs, "--stun", "stun:127.0.0.1:1")
		}
		output := runPXOutput(t, ctx, homes[index], joinArgs...)
		var state contextstate.State
		if err := json.Unmarshal(output, &state); err != nil || state.PendingCode == "" {
			t.Fatalf("decode %s join: %+v, %v\n%s", labels[index], state, err, output)
		}
		if bytes.Contains(output, []byte("credential")) || bytes.Contains(output, []byte("signature")) {
			t.Fatalf("join exposed credential: %s", output)
		}
		if index == 0 {
			if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", state.PendingCode, "--json").CombinedOutput(); err != nil {
				t.Fatalf("bootstrap approve %s: %v\n%s", labels[index], err, output)
			}
			waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
		} else {
			pendingOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "devices", "pending", "--json")
			var pending []contextstate.PendingDevice
			if err := json.Unmarshal(pendingOutput, &pending); err != nil || len(pending) != 1 || pending[0].Code != state.PendingCode || bytes.Contains(pendingOutput, []byte("source")) || bytes.Contains(pendingOutput, []byte("192.0.")) {
				t.Fatalf("member pending = %+v, %v\n%s", pending, err, pendingOutput)
			}
			approvedOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "devices", "approve", strings.ToLower(state.PendingCode), "--json")
			var approved contextstate.Device
			if err := json.Unmarshal(approvedOutput, &approved); err != nil || approved.Label != labels[index] || approved.Status != "offline" {
				t.Fatalf("member approval = %+v, %v\n%s", approved, err, approvedOutput)
			}
			duplicate := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "devices", "approve", state.PendingCode, "--json")
			if output, err := duplicate.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("pending enrollment not found or expired")) {
				t.Fatalf("duplicate member approval = %v\n%s", err, output)
			}
		}
	}
	waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
	waitContextStates(t, ctx, homes[1], map[string]string{"home": "connected"})
	waitContextStates(t, ctx, homes[2], map[string]string{"home": "connected"})
	if err := os.Mkdir(filepath.Join(offeredRoots[1], "releases"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("offered-root-data\n"), 10_000)
	if err := os.WriteFile(filepath.Join(offeredRoots[1], "releases", "app.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(offeredRoots[1], "releases", "notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	runPXOutput(t, ctx, homes[0], "--context", "home", "context", "alias", "set", "build", "vm", "--json")
	peerOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "peers", "--json")
	var peers []contextstate.Peer
	if err := json.Unmarshal(peerOutput, &peers); err != nil || len(peers) != 2 {
		t.Fatalf("online peers = %+v, %v\n%s", peers, err, peerOutput)
	}
	var vmPeer, clearPeer contextstate.Peer
	for _, peer := range peers {
		switch peer.Label {
		case "vm":
			vmPeer = peer
		case "clear":
			clearPeer = peer
		}
	}
	if vmPeer.DeviceID == "" || clearPeer.DeviceID == "" || strings.Join(vmPeer.Aliases, ",") != "build" {
		t.Fatalf("online peers = %+v", peers)
	}
	plainPeers := runPXOutput(t, ctx, homes[0], "--context", "home", "peers")
	if !bytes.Contains(plainPeers, []byte("@vm\tonline\taliases: build\n")) || !bytes.Contains(plainPeers, []byte("@clear\tonline\n")) || bytes.Contains(plainPeers, []byte(vmPeer.DeviceID)) || bytes.Contains(plainPeers, []byte(clearPeer.DeviceID)) {
		t.Fatalf("plain peers = %q", plainPeers)
	}
	widePeers := runPXOutput(t, ctx, homes[0], "--context", "home", "peers", "--wide")
	if !bytes.Contains(widePeers, []byte(vmPeer.DeviceID)) || !bytes.Contains(widePeers, []byte(clearPeer.DeviceID)) {
		t.Fatalf("wide peers = %q", widePeers)
	}
	statusOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "status", "--json")
	var dailyStatus agentapi.Summary
	if err := json.Unmarshal(statusOutput, &dailyStatus); err != nil || dailyStatus.Status != "ok" || dailyStatus.Context == nil || dailyStatus.Context.OnlinePeers == nil || *dailyStatus.Context.OnlinePeers != 2 {
		t.Fatalf("connected daily status = %+v, %v\n%s", dailyStatus, err, statusOutput)
	}
	completionOutput, err := exec.CommandContext(ctx, binaryPath("px"), "__complete", "--home", homes[0], "--context", "home", "@b").CombinedOutput()
	if err != nil || !bytes.Contains(completionOutput, []byte("@build\n")) {
		t.Fatalf("connected peer completion = %q, %v", completionOutput, err)
	}
	serverPingOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "ping", "--server", "--count", "2", "--json")
	var serverPing ping.Result
	if err := json.Unmarshal(serverPingOutput, &serverPing); err != nil || serverPing.Mode != "server" || serverPing.Requested != 2 || serverPing.Attempted != 2 || serverPing.Succeeded != 2 || serverPing.SetupDurationNS != nil || serverPing.MinRTTNS == nil {
		t.Fatalf("server ping = %+v, %v\n%s", serverPing, err, serverPingOutput)
	}
	peerPingOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@build", "ping", "--count", "2", "--json")
	var peerPing ping.Result
	if err := json.Unmarshal(peerPingOutput, &peerPing); err != nil || peerPing.Mode != "peer" || peerPing.Requested != 2 || peerPing.Attempted != 2 || peerPing.Succeeded != 2 || peerPing.SetupDurationNS == nil || peerPing.MinRTTNS == nil || peerPing.SelectedLocalCandidateType == "" || peerPing.SelectedRemoteCandidateType == "" || peerPing.RelayUsed == nil || bytes.Contains(peerPingOutput, []byte("local_address")) || bytes.Contains(peerPingOutput, []byte("remote_address")) {
		t.Fatalf("peer ping = %+v, %v\n%s", peerPing, err, peerPingOutput)
	}
	addressPingOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@build", "ping", "--count", "1", "--show-addresses", "--json")
	var addressPing ping.Result
	if err := json.Unmarshal(addressPingOutput, &addressPing); err != nil || addressPing.SelectedLocalAddress == "" || addressPing.SelectedRemoteAddress == "" || !bytes.Contains(addressPingOutput, []byte(`"selected_local_address"`)) || !bytes.Contains(addressPingOutput, []byte(`"selected_remote_address"`)) {
		t.Fatalf("address ping = %+v, %v\n%s", addressPing, err, addressPingOutput)
	}
	plainAddressPing := runPXOutput(t, ctx, homes[0], "--context", "home", "ping", "build", "--count", "1", "--show-addresses")
	if !bytes.Contains(plainAddressPing, []byte(" -> ")) {
		t.Fatalf("plain address ping = %q", plainAddressPing)
	}
	plainPing := runPXOutput(t, ctx, homes[0], "--context", "home", "ping", "build", "--count", "1")
	if !bytes.Contains(plainPing, []byte("connect ")) || !bytes.Contains(plainPing, []byte("rtt min/avg/max")) || bytes.Contains(plainPing, []byte("latency")) || bytes.Contains(plainPing, []byte(" -> ")) {
		t.Fatalf("plain ping = %q", plainPing)
	}
	benchmarkRoots := []string{inboxRoots[0], inboxRoots[1], offeredRoots[0], offeredRoots[1]}
	filesBeforeBenchmark := snapshotTrees(t, benchmarkRoots)
	inventoryBeforeBenchmark := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "list", "--json")
	recentBeforeBenchmark := runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json")
	benchmarkOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@build", "benchmark", "--duration", "1s", "--json")
	var benchmarkResult benchmark.Result
	if err := json.Unmarshal(benchmarkOutput, &benchmarkResult); err != nil || benchmarkResult.Version != benchmark.Version || benchmarkResult.RequestedDurationNS != int64(time.Second) || benchmarkResult.Upload.Bytes <= 0 || benchmarkResult.Download.Bytes <= 0 || benchmarkResult.Upload.MiBPerSecond <= 0 || benchmarkResult.Download.MiBPerSecond <= 0 || benchmarkResult.RTTNS <= 0 || benchmarkResult.SelectedLocalCandidateType == "" || benchmarkResult.SelectedRemoteCandidateType == "" {
		t.Fatalf("peer benchmark = %+v, %v\n%s", benchmarkResult, err, benchmarkOutput)
	}
	plainBenchmark := runPXOutput(t, ctx, homes[0], "--context", "home", "benchmark", "build", "--duration", "1s")
	if !bytes.Contains(plainBenchmark, []byte("upload ")) || !bytes.Contains(plainBenchmark, []byte("download ")) || !bytes.Contains(plainBenchmark, []byte("rtt ")) {
		t.Fatalf("plain benchmark = %q", plainBenchmark)
	}
	if filesAfterBenchmark := snapshotTrees(t, benchmarkRoots); !slices.Equal(filesBeforeBenchmark, filesAfterBenchmark) {
		t.Fatalf("benchmark changed filesystem: before=%v after=%v", filesBeforeBenchmark, filesAfterBenchmark)
	}
	if inventoryAfterBenchmark := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "list", "--json"); !bytes.Equal(inventoryBeforeBenchmark, inventoryAfterBenchmark) {
		t.Fatalf("benchmark changed transfer inventory: before=%s after=%s", inventoryBeforeBenchmark, inventoryAfterBenchmark)
	}
	if recentAfterBenchmark := runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json"); !bytes.Equal(recentBeforeBenchmark, recentAfterBenchmark) {
		t.Fatalf("benchmark changed recent observations: before=%s after=%s", recentBeforeBenchmark, recentAfterBenchmark)
	}
	rejectedAddressPing, rejectedAddressErr := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "ping", "--server", "--show-addresses").CombinedOutput()
	if rejectedAddressErr == nil || !bytes.Contains(rejectedAddressPing, []byte("only for peer ping")) {
		t.Fatalf("server address ping = %v, %q", rejectedAddressErr, rejectedAddressPing)
	}
	memberOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "devices", "list", "--json")
	var devices []contextstate.Device
	if err := json.Unmarshal(memberOutput, &devices); err != nil || len(devices) != 3 {
		t.Fatalf("member devices = %+v, %v\n%s", devices, err, memberOutput)
	}
	laptopDeviceID := ""
	for _, device := range devices {
		if device.Label == "laptop" {
			laptopDeviceID = device.DeviceID
		}
	}
	if laptopDeviceID == "" {
		t.Fatalf("local device missing from members: %+v", devices)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "ls", "laptop").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("peer resolves to the local device")) {
		t.Fatalf("self peer resolution = %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "ls", "missing").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("peer is not enrolled")) {
		t.Fatalf("unknown peer resolution = %v\n%s", err, output)
	}
	listOutput := runPXOutput(t, ctx, homes[0], "-c", "home", "@build", "ls", "releases", "--json")
	var entries []offered.Entry
	if err := json.Unmarshal(listOutput, &entries); err != nil || len(entries) != 2 || entries[0].Name != "app.bin" || entries[1].Name != "notes.txt" {
		t.Fatalf("offered entries = %+v, %v\n%s", entries, err, listOutput)
	}
	activeSource := filepath.Join(offeredRoots[1], "releases", "active.bin")
	if err := os.WriteFile(activeSource, bytes.Repeat([]byte("active-root-operation\n"), 1<<22), 0o600); err != nil {
		t.Fatal(err)
	}
	activeGet := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "get", "vm", "releases/active.bin", "--output", filepath.Join(dir, "active-download.bin"), "--json")
	activeStdout, err := activeGet.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var activeStderr bytes.Buffer
	activeGet.Stderr = &activeStderr
	if err := activeGet.Start(); err != nil {
		t.Fatal(err)
	}
	activeDecoder := json.NewDecoder(activeStdout)
	var activeEvent offered.GetEvent
	if err := activeDecoder.Decode(&activeEvent); err != nil || activeEvent.State != "submitted" {
		t.Fatalf("active get initial event = %+v, %v\n%s", activeEvent, err, activeStderr.String())
	}
	candidate := filepath.Join(dir, "outgoing-get-independent-root")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, configureErr := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "context", "configure", "--offered-root", candidate).CombinedOutput(); configureErr != nil {
		t.Fatalf("outgoing get blocked local offered-root update = %v\n%s", configureErr, output)
	}
	activeInventoryOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "list", "--json")
	var activeInventory transfer.Inventory
	if err := json.Unmarshal(activeInventoryOutput, &activeInventory); err != nil {
		t.Fatal(err)
	}
	activeID := ""
	for _, item := range activeInventory.Transfers {
		if item.Kind == "get" && item.State == "active" {
			activeID = item.ID
			break
		}
	}
	if activeID == "" {
		t.Fatalf("active get missing from inventory: %s", activeInventoryOutput)
	}
	activeCompletion, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "__complete", "transfer", "cancel", "get-").CombinedOutput()
	if err != nil || !bytes.Contains(activeCompletion, []byte(activeID+"\n")) {
		t.Fatalf("active get completion = %q, %v", activeCompletion, err)
	}
	cancelOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "cancel", activeID, "--json")
	if !bytes.Contains(cancelOutput, []byte(`"state":"cancel_requested"`)) {
		t.Fatalf("cancel output = %s", cancelOutput)
	}
	for activeDecoder.More() {
		if err := activeDecoder.Decode(&activeEvent); err != nil {
			t.Fatal(err)
		}
	}
	if err := activeGet.Wait(); err == nil || activeEvent.State != "failed" {
		t.Fatalf("active get completion = %+v, %v\n%s", activeEvent, err, activeStderr.String())
	}
	disconnectContext, disconnect := context.WithCancel(ctx)
	disconnectedGet := exec.CommandContext(disconnectContext, binaryPath("px"), "--home", homes[0], "--context", "home", "get", "vm", "releases/active.bin", "--output", filepath.Join(dir, "disconnected-download.bin"), "--json")
	disconnectedStdout, err := disconnectedGet.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := disconnectedGet.Start(); err != nil {
		t.Fatal(err)
	}
	var disconnectedEvent offered.GetEvent
	if err := json.NewDecoder(disconnectedStdout).Decode(&disconnectedEvent); err != nil || disconnectedEvent.State != "submitted" {
		t.Fatalf("disconnected get initial event = %+v, %v", disconnectedEvent, err)
	}
	disconnect()
	_ = disconnectedGet.Wait()
	releaseDeadline := time.Now().Add(5 * time.Second)
	for {
		inventoryOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "list", "--json")
		var inventory transfer.Inventory
		if err := json.Unmarshal(inventoryOutput, &inventory); err != nil {
			t.Fatal(err)
		}
		active := false
		for _, item := range inventory.Transfers {
			active = active || item.Kind == "get" && item.State == "active"
		}
		if !active {
			break
		}
		if time.Now().After(releaseDeadline) {
			t.Fatalf("disconnected get retained operation ownership: %s", inventoryOutput)
		}
		time.Sleep(25 * time.Millisecond)
	}
	runPXOutput(t, ctx, homes[0], "--context", "home", "context", "configure", "--offered-root", offeredRoots[0], "--json")
	destination := filepath.Join(dir, "downloaded.bin")
	getEvents, _, err := runGetProcess(ctx, homes[0], "-c", "home", "@vm", "get", "releases/app.bin", "--output", destination)
	if err != nil || len(getEvents) < 3 || getEvents[0].State != "submitted" || getEvents[len(getEvents)-1].State != "committed" || getEvents[len(getEvents)-1].Bytes != int64(len(content)) {
		t.Fatalf("get events = %+v, %v", getEvents, err)
	}
	actual, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("download differs: %v", err)
	}
	plainDestination := filepath.Join(dir, "notes.txt")
	plainGet := runPXOutput(t, ctx, homes[0], "-c", "home", "@vm", "get", "releases/notes.txt", "--output", plainDestination)
	if !bytes.Contains(plainGet, []byte("submitted\t0/0")) || !bytes.Contains(plainGet, []byte("committed\t5/5")) || bytes.Contains(plainGet, []byte("\x1b")) {
		t.Fatalf("redirected get output = %q", plainGet)
	}
	if err := os.WriteFile(filepath.Join(offeredRoots[1], "releases", "empty.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyEvents, _, err := runGetProcess(ctx, homes[0], "-c", "home", "@vm", "get", "releases/empty.txt", "--output", filepath.Join(dir, "empty.txt"))
	if err != nil || len(emptyEvents) < 3 || emptyEvents[len(emptyEvents)-1].State != "committed" || emptyEvents[len(emptyEvents)-1].Total != 0 {
		t.Fatalf("empty get events = %+v, %v", emptyEvents, err)
	}
	failedGet, _, err := runGetProcess(ctx, homes[0], "-c", "home", "@vm", "get", "releases/app.bin", "--output", destination)
	if err == nil || len(failedGet) == 0 || failedGet[len(failedGet)-1].State != "failed" {
		t.Fatalf("failed get events = %+v, %v", failedGet, err)
	}
	sendSource := filepath.Join(dir, "send-source.bin")
	sendContent := bytes.Repeat([]byte("resumable-send-data\n"), 100_000)
	if err := os.WriteFile(sendSource, sendContent, 0o600); err != nil {
		t.Fatal(err)
	}
	fastEvents, _, err := runSendProcess(ctx, homes[0], nil, "-c", "home", "@vm", "send", sendSource, "--name", "fast.bin")
	if err != nil || len(fastEvents) < 3 || fastEvents[0].TransferID != "" || fastEvents[len(fastEvents)-1].State != "committed" {
		t.Fatalf("fast send events = %+v, %v", fastEvents, err)
	}
	fastSent, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "fast.bin"))
	if err != nil || !bytes.Equal(fastSent, sendContent) {
		t.Fatalf("fast sent file differs: %v", err)
	}
	fastPublicEvents, _, err := runSendProcess(ctx, homes[0], nil, "-c", "home", "@vm", "send", sendSource, "--name", "fast-public.bin", "--public")
	if err != nil || len(fastPublicEvents) < 3 || fastPublicEvents[0].TransferID != "" || fastPublicEvents[len(fastPublicEvents)-1].State != "committed" {
		t.Fatalf("fast public send events = %+v, %v", fastPublicEvents, err)
	}
	fastPublicSent, err := os.ReadFile(filepath.Join(offeredRoots[1], "fast-public.bin"))
	if err != nil || !bytes.Equal(fastPublicSent, sendContent) {
		t.Fatalf("fast public sent file differs: %v", err)
	}
	fastStdinContent := []byte("fast stdin pipeline\n")
	fastStdinEvents, _, err := runSendProcess(ctx, homes[0], bytes.NewReader(fastStdinContent), "--context", "home", "send", "vm", "--stdin", "--name", "fast-pipeline.log")
	if err != nil || len(fastStdinEvents) == 0 || fastStdinEvents[0].TransferID != "" || fastStdinEvents[len(fastStdinEvents)-1].State != "committed" {
		t.Fatalf("fast stdin events = %+v, %v", fastStdinEvents, err)
	}
	fastStdinDestination, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "fast-pipeline.log"))
	if err != nil || !bytes.Equal(fastStdinDestination, fastStdinContent) {
		t.Fatalf("fast stdin destination differs: %v", err)
	}
	sendEvents, _, err := runSendProcess(ctx, homes[0], nil, "-c", "home", "@vm", "send", sendSource, "--name", "sent.bin", "--recoverable")
	if err != nil || len(sendEvents) < 3 || sendEvents[0].State != "submitted" || sendEvents[len(sendEvents)-1].State != "committed" {
		t.Fatalf("send events = %+v, %v", sendEvents, err)
	}
	sent, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "sent.bin"))
	if err != nil || !bytes.Equal(sent, sendContent) {
		t.Fatalf("sent file differs: %v", err)
	}
	publicEvents, _, err := runSendProcess(ctx, homes[0], nil, "-c", "home", "@vm", "send", sendSource, "--name", "sent.bin", "--public", "--recoverable")
	if err != nil || len(publicEvents) < 3 || publicEvents[len(publicEvents)-1].State != "committed" || publicEvents[0].TransferID == sendEvents[0].TransferID {
		t.Fatalf("public send events = %+v, %v", publicEvents, err)
	}
	publicSent, err := os.ReadFile(filepath.Join(offeredRoots[1], "sent.bin"))
	if err != nil || !bytes.Equal(publicSent, sendContent) {
		t.Fatalf("public sent file differs: %v", err)
	}
	rootOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "ls", "vm", "--json")
	var rootEntries []offered.Entry
	if err := json.Unmarshal(rootOutput, &rootEntries); err != nil || !hasOfferedEntry(rootEntries, "sent.bin") {
		t.Fatalf("public offered entries = %+v, %v\n%s", rootEntries, err, rootOutput)
	}
	stdinContent := bytes.Repeat([]byte("stdin-pipeline\n"), 10_000)
	stdinEvents, _, err := runSendProcess(ctx, homes[0], bytes.NewReader(stdinContent), "--context", "home", "send", "vm", "--stdin", "--name", "pipeline.log", "--recoverable")
	if err != nil || len(stdinEvents) == 0 || stdinEvents[len(stdinEvents)-1].State != "committed" {
		t.Fatalf("stdin events = %+v, %v", stdinEvents, err)
	}
	stdinDestination, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "pipeline.log"))
	if err != nil || !bytes.Equal(stdinDestination, stdinContent) {
		t.Fatalf("stdin destination differs: %v", err)
	}
	literalText := "build is ready & deploy | verify"
	textEvents, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "@vm", "text", literalText, "--name", "build-note.txt")
	if err != nil || len(textEvents) == 0 || textEvents[len(textEvents)-1].State != "committed" {
		t.Fatalf("literal text events = %+v, %v", textEvents, err)
	}
	textDestination, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "build-note.txt"))
	if err != nil || string(textDestination) != literalText {
		t.Fatalf("literal text destination = %q, %v", textDestination, err)
	}
	inboxOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "inbox", "--json")
	var inboxEntries []inbox.Entry
	if err := json.Unmarshal(inboxOutput, &inboxEntries); err != nil || !hasInboxEntry(inboxEntries, "laptop/build-note.txt") {
		t.Fatalf("inbox entries = %+v, %v\n%s", inboxEntries, err, inboxOutput)
	}
	filteredInbox := runPXOutput(t, ctx, homes[1], "--context", "home", "inbox", "@laptop")
	if !bytes.Contains(filteredInbox, []byte("laptop/build-note.txt\t")) || bytes.Contains(filteredInbox, []byte(inboxRoots[1])) {
		t.Fatalf("filtered inbox = %q", filteredInbox)
	}
	inboxPathOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "inbox", "path", "laptop/fast-pipeline.log")
	canonicalInboxRoot, err := filepath.EvalSymlinks(inboxRoots[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(inboxPathOutput)), filepath.Join(canonicalInboxRoot, "home", "laptop", "fast-pipeline.log"); got != want {
		t.Fatalf("inbox path = %q, want %q", got, want)
	}
	moveDirectory := t.TempDir()
	moveOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "inbox", "move", "laptop/fast-pipeline.log", moveDirectory)
	movedPath := filepath.Join(moveDirectory, "fast-pipeline.log")
	if !bytes.Contains(moveOutput, []byte("laptop/fast-pipeline.log -> "+movedPath)) {
		t.Fatalf("inbox move output = %q", moveOutput)
	}
	movedContent, err := os.ReadFile(movedPath)
	if err != nil || !bytes.Equal(movedContent, fastStdinContent) {
		t.Fatalf("moved inbox content = %q, %v", movedContent, err)
	}
	if _, err := os.Lstat(filepath.Join(inboxRoots[1], "home", "laptop", "fast-pipeline.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("moved inbox source error = %v", err)
	}
	collisionPath := filepath.Join(moveDirectory, "sent.bin")
	if err := os.WriteFile(collisionPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	moveCollision := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[1], "--context", "home", "inbox", "move", "laptop/sent.bin", collisionPath)
	if output, err := moveCollision.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("destination already exists")) {
		t.Fatalf("inbox move collision = %q, %v", output, err)
	}
	if source, err := os.ReadFile(filepath.Join(inboxRoots[1], "home", "laptop", "sent.bin")); err != nil || !bytes.Equal(source, sendContent) {
		t.Fatalf("inbox collision source = %q, %v", source, err)
	}
	pipedText := []byte("clipboard line one\nline two\n")
	pipedEvents, _, err := runSendProcess(ctx, homes[0], bytes.NewReader(pipedText), "--context", "home", "@vm", "text")
	if err != nil || len(pipedEvents) == 0 || pipedEvents[len(pipedEvents)-1].State != "committed" {
		t.Fatalf("piped text events = %+v, %v", pipedEvents, err)
	}
	generated, err := filepath.Glob(filepath.Join(inboxRoots[1], "home", "laptop", "pxmsg-????????T??????Z-????????.txt"))
	if err != nil || len(generated) != 1 {
		t.Fatalf("generated text files = %v, %v", generated, err)
	}
	generatedText, err := os.ReadFile(generated[0])
	if err != nil || !bytes.Equal(generatedText, pipedText) {
		t.Fatalf("generated text destination = %q, %v", generatedText, err)
	}
	localRecentOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json")
	var localRecent recent.Snapshot
	if err := json.Unmarshal(localRecentOutput, &localRecent); err != nil || recent.ValidateSnapshot(localRecent, false) != nil || localRecent.Reporter.Label != "laptop" || localRecent.Reporter.Context != "home" || len(localRecent.Observations) != 5 {
		t.Fatalf("local recent = %+v, %v\n%s", localRecent, err, localRecentOutput)
	}
	for _, observation := range localRecent.Observations {
		if observation.Direction != "send" || observation.Kind != "sender_observed_commit" || observation.PeerLabel != "vm" {
			t.Fatalf("local observation = %+v", observation)
		}
	}
	remoteRecentCommand := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "@vm", "recent", "--json")
	remoteRecentOutput, err := remoteRecentCommand.CombinedOutput()
	if err != nil {
		t.Fatalf("remote recent command: %v\n%s\nagent A:\n%s\nagent B:\n%s", err, remoteRecentOutput, agentLogs[0].String(), agentLogs[1].String())
	}
	var remoteRecent recent.Snapshot
	if err := json.Unmarshal(remoteRecentOutput, &remoteRecent); err != nil || recent.ValidateSnapshot(remoteRecent, true) != nil || remoteRecent.Reporter.Label != "vm" || remoteRecent.Reporter.Context != "" || len(remoteRecent.Observations) != 5 {
		t.Fatalf("remote recent = %+v, %v\n%s", remoteRecent, err, remoteRecentOutput)
	}
	for _, observation := range remoteRecent.Observations {
		if observation.Direction != "receive" || observation.Kind != "receiver_published" || observation.PeerLabel != "laptop" || observation.Context != "" {
			t.Fatalf("remote observation = %+v", observation)
		}
	}
	unrelatedRecentOutput := runPXOutput(t, ctx, homes[2], "--context", "home", "recent", "vm", "--json")
	var unrelatedRecent recent.Snapshot
	if err := json.Unmarshal(unrelatedRecentOutput, &unrelatedRecent); err != nil || recent.ValidateSnapshot(unrelatedRecent, true) != nil || unrelatedRecent.Reporter.DeviceID != vmPeer.DeviceID || len(unrelatedRecent.Observations) != 0 {
		t.Fatalf("unrelated recent = %+v, %v\n%s", unrelatedRecent, err, unrelatedRecentOutput)
	}
	clearPeerRecentOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@clear", "recent", "--yes", "--json")
	var clearPeerRecent recent.Snapshot
	if err := json.Unmarshal(clearPeerRecentOutput, &clearPeerRecent); err != nil || clearPeerRecent.Reporter.DeviceID != clearPeer.DeviceID || clearPeerRecent.Reporter.Label != "clear" || len(clearPeerRecent.Observations) != 0 {
		t.Fatalf("clear peer recent = %+v, %v\n%s", clearPeerRecent, err, clearPeerRecentOutput)
	}
	localAfterClearPeer := runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json")
	if err := json.Unmarshal(localAfterClearPeer, &localRecent); err != nil || len(localRecent.Observations) != 5 {
		t.Fatalf("@clear recent deleted local rows = %+v, %v", localRecent, err)
	}
	plainRecent := runPXOutput(t, ctx, homes[0], "--context", "home", "recent")
	if !bytes.Contains(plainRecent, []byte("Recent activity on this device (@laptop)")) || !bytes.Contains(plainRecent, []byte("TIME (UTC)")) || !bytes.Contains(plainRecent, []byte("sent")) || !bytes.Contains(plainRecent, []byte("not receipts or global settlement")) || bytes.Contains(plainRecent, []byte("sender_observed_commit")) {
		t.Fatalf("plain recent = %q", plainRecent)
	}
	recentCompletion, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "__complete", "recent", "b").CombinedOutput()
	if err != nil || !bytes.Contains(recentCompletion, []byte("build\n")) {
		t.Fatalf("recent peer completion = %q, %v", recentCompletion, err)
	}
	clearRecentOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "recent", "--json", "clear", "--yes")
	var cleared recent.ClearResult
	if err := json.Unmarshal(clearRecentOutput, &cleared); err != nil || cleared.Version != recent.Version || cleared.Description != recent.Description || cleared.Reporter.Label != "vm" || cleared.Reporter.Context != "home" || cleared.Cleared != 5 {
		t.Fatalf("recent clear = %+v, %v\n%s", cleared, err, clearRecentOutput)
	}
	clearedRecentOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "recent", "--json")
	var clearedRecent recent.Snapshot
	if err := json.Unmarshal(clearedRecentOutput, &clearedRecent); err != nil || len(clearedRecent.Observations) != 0 {
		t.Fatalf("cleared recent = %+v, %v\n%s", clearedRecent, err, clearedRecentOutput)
	}
	localRecentOutput = runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json")
	if err := json.Unmarshal(localRecentOutput, &localRecent); err != nil || len(localRecent.Observations) != 5 {
		t.Fatalf("peer clear changed local recent = %+v, %v", localRecent, err)
	}
	collisionEvents, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "@vm", "text", "replacement", "--name", "build-note.txt")
	if err == nil || len(collisionEvents) == 0 || collisionEvents[len(collisionEvents)-1].State != "rejected" {
		t.Fatalf("text collision events = %+v, %v", collisionEvents, err)
	}
	runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "delete", collisionEvents[len(collisionEvents)-1].TransferID, "--yes", "--json")
	invalidSources := []struct {
		path string
		code string
		args []string
	}{
		{path: filepath.Join(dir, "missing-source"), code: transfer.SourceNotFoundCode},
		{path: filepath.Join(dir, "bad\nsource"), code: transfer.SourceInvalidCode},
		{path: dir, code: transfer.SourceDirectoryCode},
		{path: sendSource, code: transfer.SourceTooLargeCode, args: []string{"--max-file-bytes", "1"}},
	}
	sourceLink := filepath.Join(dir, "source-link")
	if err := os.Symlink(sendSource, sourceLink); err == nil {
		invalidSources = append(invalidSources, struct {
			path string
			code string
			args []string
		}{path: sourceLink, code: transfer.SourceSymlinkCode})
	}
	for _, invalid := range invalidSources {
		args := []string{"--context", "home", "send", "vm", invalid.path}
		args = append(args, invalid.args...)
		events, stderr, sendErr := runSendProcess(ctx, homes[0], nil, args...)
		if sendErr == nil || len(events) != 0 || !strings.Contains(stderr, `"code":"`+invalid.code+`"`) || strings.Contains(stderr, invalid.path) {
			t.Errorf("invalid source %s events = %+v, %v, stderr = %q", invalid.code, events, sendErr, stderr)
		}
	}
	plainMissing := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "send", "vm", invalidSources[0].path)
	plainMissingOutput, plainMissingErr := plainMissing.CombinedOutput()
	if plainMissingErr == nil || !bytes.Contains(plainMissingOutput, []byte("local source does not exist or is unavailable")) || bytes.Contains(plainMissingOutput, []byte(invalidSources[0].path)) {
		t.Fatalf("plain missing source = %q, %v", plainMissingOutput, plainMissingErr)
	}
	oversizedTextEvents, oversizedTextStderr, err := runSendProcess(ctx, homes[0], bytes.NewReader(bytes.Repeat([]byte("x"), (64<<10)+1)), "--context", "home", "@vm", "text", "--name", "too-large.txt")
	if err == nil || len(oversizedTextEvents) != 0 || !strings.Contains(oversizedTextStderr, "stdin exceeds 65536 byte limit") {
		t.Fatalf("oversized text events = %+v, %v, stderr = %q", oversizedTextEvents, err, oversizedTextStderr)
	}
	publicStdinEvents, _, err := runSendProcess(ctx, homes[0], bytes.NewReader(stdinContent), "--context", "home", "send", "vm", "--stdin", "--name", "public-pipeline.log", "--public", "--recoverable")
	if err != nil || len(publicStdinEvents) == 0 || publicStdinEvents[len(publicStdinEvents)-1].State != "committed" {
		t.Fatalf("public stdin events = %+v, %v", publicStdinEvents, err)
	}
	publicStdinDestination, err := os.ReadFile(filepath.Join(offeredRoots[1], "public-pipeline.log"))
	if err != nil || !bytes.Equal(publicStdinDestination, stdinContent) {
		t.Fatalf("public stdin destination differs: %v", err)
	}
	pathsA, err := apphome.Resolve(homes[0])
	if err != nil {
		t.Fatal(err)
	}
	capacityDB, err := sql.Open("sqlite", database.DSN(pathsA.AgentDatabase))
	if err != nil {
		t.Fatal(err)
	}
	capacityNow := time.Now().UTC()
	for index := range transfer.MaxSendResumeStates {
		id := fmt.Sprintf("%064x", index+1)
		if _, err := capacityDB.Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,source_path,stdin_spool,state,created_at,updated_at,expires_at,manifest_version,visibility) values ('send',?,'home','capacity-device','capacity-fixture','capacity.bin',1,?, ?, ?, 'token',0,'/source',0,'transferring',?,?,?,3,'private')`, id, strings.Repeat("0", 64), transfer.ResumeChunkSize, transfer.ResumeAckWindow, capacityNow.Unix(), capacityNow.Unix(), capacityNow.Add(time.Hour).Unix()); err != nil {
			capacityDB.Close()
			t.Fatal(err)
		}
	}
	if err := capacityDB.Close(); err != nil {
		t.Fatal(err)
	}
	capacityEvents, capacityStderr, err := runSendProcess(ctx, homes[0], strings.NewReader("bounded stdin"), "--context", "home", "send", "vm", "--stdin", "--name", "capacity.bin", "--recoverable")
	if err == nil || len(capacityEvents) == 0 || capacityEvents[len(capacityEvents)-1].State != "failed" || !strings.Contains(capacityEvents[len(capacityEvents)-1].Error, transfer.ErrSendResumeCapacity.Error()) {
		t.Fatalf("capacity send events = %+v, %v\n%s", capacityEvents, err, capacityStderr)
	}
	capacityDB, err = sql.Open("sqlite", database.DSN(pathsA.AgentDatabase))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capacityDB.Exec(`delete from transfer_resumes where direction='send' and peer_label='capacity-fixture'`); err != nil {
		capacityDB.Close()
		t.Fatal(err)
	}
	if err := capacityDB.Close(); err != nil {
		t.Fatal(err)
	}
	spools, err := filepath.Glob(filepath.Join(pathsA.AgentTransfers, ".stdin-*.spool"))
	if err != nil || len(spools) != 0 {
		t.Fatalf("stdin spools remain: %v, %v", spools, err)
	}
	rejected, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "send", "vm", sendSource, "--name", "sent.bin")
	if err == nil || len(rejected) == 0 || rejected[len(rejected)-1].State != "rejected" {
		t.Fatalf("duplicate send events = %+v, %v", rejected, err)
	}
	publicRejected, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "send", "vm", sendSource, "--name", "sent.bin", "--public")
	if err == nil || len(publicRejected) == 0 || publicRejected[len(publicRejected)-1].State != "rejected" {
		t.Fatalf("duplicate public send events = %+v, %v", publicRejected, err)
	}
	restartSource := filepath.Join(dir, "restart.bin")
	restartFile, err := os.OpenFile(restartSource, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartFile.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := restartFile.Close(); err != nil {
		t.Fatal(err)
	}
	interrupt := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "send", "vm", restartSource, "--recoverable", "--json")
	stdout, err := interrupt.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var interruptStderr bytes.Buffer
	interrupt.Stderr = &interruptStderr
	if err := interrupt.Start(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(stdout)
	var submitted, transferring transfer.ResumeEvent
	if err := decoder.Decode(&submitted); err != nil || submitted.State != "submitted" {
		t.Fatalf("submitted event = %+v, %v\n%s", submitted, err, interruptStderr.String())
	}
	if err := decoder.Decode(&transferring); err != nil || transferring.State != "transferring" {
		t.Fatalf("transferring event = %+v, %v\n%s", transferring, err, interruptStderr.String())
	}
	var progressed transfer.ResumeEvent
	if err := decoder.Decode(&progressed); err != nil || progressed.State != "transferring" || progressed.Bytes == 0 {
		t.Fatalf("progress event = %+v, %v\n%s", progressed, err, interruptStderr.String())
	}
	stopAgentCommand(t, ctx, homes[1])
	if err := agents[1].Wait(); err != nil {
		t.Fatal(err)
	}
	vmPaths, err := apphome.Resolve(homes[1])
	if err != nil {
		t.Fatal(err)
	}
	vmConfig, err := database.Config(database.KindAgent, vmPaths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	vmStore := sqlite.New(vmConfig)
	if err := vmStore.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := vmStore.DB().Exec(`delete from recent_observations where context_name='home'`); err != nil {
		t.Fatal(err)
	}
	fixtureNow := time.Now().UTC()
	agePrunedID := strings.Repeat("a", 64)
	pressurePrunedID := strings.Repeat("b", 64)
	insertRecent := `insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values('home','receive',?,'receiver_published',?,'laptop',?,'private',1,?)`
	if _, err := vmStore.DB().Exec(insertRecent, agePrunedID, laptopDeviceID, "age-pruned.txt", fixtureNow.Add(-31*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := vmStore.DB().Exec(insertRecent, pressurePrunedID, laptopDeviceID, "pressure-pruned.txt", fixtureNow.Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	oldClearID := strings.Repeat("C", 43)
	if _, err := vmStore.DB().Exec(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values('home','receive',?,'receiver_published',?,'clear','old-clear.txt','private',1,?)`, strings.Repeat("e", 64), oldClearID, fixtureNow.Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	oneSidedID := strings.Repeat("c", 64)
	if _, err := vmStore.DB().Exec(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values('home','receive',?,'receiver_published',?,'laptop','lost-response.txt','private',1,?)`, oneSidedID, laptopDeviceID, fixtureNow.Add(-30*time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	for index := range 61 {
		if _, err := vmStore.DB().Exec(insertRecent, fmt.Sprintf("%064x", 1000+index), laptopDeviceID, fmt.Sprintf("fixture-%02d.txt", index), fixtureNow.Add(time.Duration(-500+index)*time.Second).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := vmStore.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) select 'work','http://127.0.0.1:1',server_id,device_id,private_key_path,public_key_path,label,'pending',1,offered_root,inbox_root,created_at,updated_at from contexts where name='home'`); err != nil {
		t.Fatal(err)
	}
	if _, err := vmStore.DB().Exec(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values('work','receive',?,'receiver_published',?,'clear','work-only.txt','private',1,?)`, strings.Repeat("d", 64), clearPeer.DeviceID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := vmStore.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := interrupt.Wait(); err == nil {
		t.Fatal("interrupted transfer succeeded")
	}
	stopAgentCommand(t, ctx, homes[0])
	if err := agents[0].Wait(); err != nil {
		t.Fatal(err)
	}
	agents[0] = startAgentProcessWithStderr(t, ctx, homes[0], &agentLogs[0])
	pathsA, err = apphome.Resolve(homes[0])
	if err != nil {
		t.Fatal(err)
	}
	waitAgentStatus(t, ctx, pathsA.AgentEndpoint)
	waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
	agents[1] = startAgentProcessWithStderr(t, ctx, homes[1], &agentLogs[1])
	pathsB, err := apphome.Resolve(homes[1])
	if err != nil {
		t.Fatal(err)
	}
	waitAgentStatus(t, ctx, pathsB.AgentEndpoint)
	waitContextStates(t, ctx, homes[1], map[string]string{"home": "connected"})
	restartedRecentOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "recent", "--json")
	var restartedRecent recent.Snapshot
	if err := json.Unmarshal(restartedRecentOutput, &restartedRecent); err != nil {
		t.Fatal(err)
	}
	foundOriginal := false
	for _, observation := range restartedRecent.Observations {
		foundOriginal = foundOriginal || observation.TransferID == sendEvents[0].TransferID
	}
	if !foundOriginal {
		t.Fatalf("restart lost original recent observation: %+v", restartedRecent)
	}
	foundOneSidedSender := false
	for _, observation := range restartedRecent.Observations {
		foundOneSidedSender = foundOneSidedSender || observation.TransferID == oneSidedID
	}
	if foundOneSidedSender {
		t.Fatal("one-sided receiver observation appeared in sender journal")
	}
	reusedLabelOutput := runPXOutput(t, ctx, homes[2], "--context", "home", "recent", "vm", "--json")
	var reusedLabel recent.Snapshot
	if err := json.Unmarshal(reusedLabelOutput, &reusedLabel); err != nil {
		t.Fatal(err)
	}
	for _, observation := range reusedLabel.Observations {
		if observation.PeerLabel == "clear" || observation.PeerDeviceID == oldClearID {
			t.Fatalf("new clear identity inherited old row: %+v", observation)
		}
	}
	workRecentOutput := runPXOutput(t, ctx, homes[1], "--context", "work", "recent", "--json")
	var workRecent recent.Snapshot
	if err := json.Unmarshal(workRecentOutput, &workRecent); err != nil || len(workRecent.Observations) != 1 || workRecent.Observations[0].Destination != "work-only.txt" {
		t.Fatalf("work recent = %+v, %v", workRecent, err)
	}
	homeRecentOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "recent", "--json")
	var homeRecent recent.Snapshot
	if err := json.Unmarshal(homeRecentOutput, &homeRecent); err != nil {
		t.Fatal(err)
	}
	for _, observation := range homeRecent.Observations {
		if observation.TransferID == oneSidedID && observation.Kind != "receiver_published" {
			t.Fatalf("one-sided receiver observation changed kind: %+v", observation)
		}
		if observation.Destination == "work-only.txt" {
			t.Fatalf("work observation leaked into home: %+v", observation)
		}
	}
	foundOneSidedReceiver := false
	for _, observation := range homeRecent.Observations {
		foundOneSidedReceiver = foundOneSidedReceiver || observation.TransferID == oneSidedID
	}
	if !foundOneSidedReceiver {
		t.Fatal("one-sided receiver observation missing after restart")
	}
	retryEvents, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "transfer", "retry", submitted.TransferID)
	if err != nil || len(retryEvents) == 0 || retryEvents[len(retryEvents)-1].State != "committed" || !hasTransferEvent(retryEvents, "resumed") {
		t.Fatalf("retry events = %+v, %v", retryEvents, err)
	}
	retainedOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "recent", "--limit", "64", "--json")
	var retained recent.Snapshot
	if err := json.Unmarshal(retainedOutput, &retained); err != nil || len(retained.Observations) != 64 {
		t.Fatalf("retained observations = %d, %v\n%s", len(retained.Observations), err, retainedOutput)
	}
	foundRetry := false
	for _, observation := range retained.Observations {
		if observation.TransferID == agePrunedID || observation.TransferID == pressurePrunedID {
			t.Fatalf("eligible oldest observation survived insertion: %+v", observation)
		}
		foundRetry = foundRetry || observation.TransferID == submitted.TransferID
	}
	if !foundRetry {
		t.Fatalf("binary retry observation missing after retention: %+v", retained)
	}
	restartedInfo, err := os.Stat(filepath.Join(inboxRoots[1], "home", "laptop", "restart.bin"))
	if err != nil || restartedInfo.Size() != 64<<20 {
		t.Fatalf("restarted destination = %v, %v", restartedInfo, err)
	}
	legacyRestartSource := filepath.Join(dir, "legacy-restart.bin")
	legacyRestartFile, err := os.OpenFile(legacyRestartSource, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyRestartFile.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := legacyRestartFile.Close(); err != nil {
		t.Fatal(err)
	}
	legacyInterrupt := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "send", "vm", legacyRestartSource, "--recoverable", "--json")
	legacyStdout, err := legacyInterrupt.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var legacyStderr bytes.Buffer
	legacyInterrupt.Stderr = &legacyStderr
	if err := legacyInterrupt.Start(); err != nil {
		t.Fatal(err)
	}
	legacyDecoder := json.NewDecoder(legacyStdout)
	var legacySubmitted, legacyTransferring, legacyProgressed transfer.ResumeEvent
	if err := legacyDecoder.Decode(&legacySubmitted); err != nil || legacySubmitted.State != "submitted" {
		t.Fatalf("legacy submitted event = %+v, %v\n%s", legacySubmitted, err, legacyStderr.String())
	}
	if err := legacyDecoder.Decode(&legacyTransferring); err != nil || legacyTransferring.State != "transferring" {
		t.Fatalf("legacy transferring event = %+v, %v\n%s", legacyTransferring, err, legacyStderr.String())
	}
	if err := legacyDecoder.Decode(&legacyProgressed); err != nil || legacyProgressed.State != "transferring" || legacyProgressed.Bytes == 0 {
		t.Fatalf("legacy progress event = %+v, %v\n%s", legacyProgressed, err, legacyStderr.String())
	}
	stopAgentCommand(t, ctx, homes[1])
	if err := agents[1].Wait(); err != nil {
		t.Fatal(err)
	}
	if err := legacyInterrupt.Wait(); err == nil {
		t.Fatal("legacy interrupted transfer succeeded")
	}
	stopAgentCommand(t, ctx, homes[0])
	if err := agents[0].Wait(); err != nil {
		t.Fatal(err)
	}
	agents[0] = startAgentProcessWithStderr(t, ctx, homes[0], &agentLogs[0])
	waitAgentStatus(t, ctx, pathsA.AgentEndpoint)
	waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
	agents[1] = startAgentProcessWithStderr(t, ctx, homes[1], &agentLogs[1])
	waitAgentStatus(t, ctx, pathsB.AgentEndpoint)
	waitContextStates(t, ctx, homes[1], map[string]string{"home": "connected"})
	legacyRetryEvents, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "send", "vm", "--retry", legacySubmitted.TransferID)
	if err != nil || len(legacyRetryEvents) == 0 || legacyRetryEvents[len(legacyRetryEvents)-1].State != "committed" || !hasTransferEvent(legacyRetryEvents, "resumed") {
		t.Fatalf("legacy retry events = %+v, %v", legacyRetryEvents, err)
	}
	legacyRestartedInfo, err := os.Stat(filepath.Join(inboxRoots[1], "home", "laptop", "legacy-restart.bin"))
	if err != nil || legacyRestartedInfo.Size() != 64<<20 {
		t.Fatalf("legacy restarted destination = %v, %v", legacyRestartedInfo, err)
	}
	crashDir := filepath.Join(dir, "get-crash")
	if err := os.Mkdir(crashDir, 0o700); err != nil {
		t.Fatal(err)
	}
	crashDestination := filepath.Join(crashDir, "restarted.bin")
	crashGet := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "get", "vm", "releases/active.bin", "--output", crashDestination, "--json")
	if err := crashGet.Start(); err != nil {
		t.Fatal(err)
	}
	var staged []string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		staged, err = filepath.Glob(filepath.Join(crashDir, ".px-*.get"))
		if err != nil {
			t.Fatal(err)
		}
		if len(staged) == 1 {
			if info, statErr := os.Stat(filepath.Join(staged[0], "data.part")); statErr == nil && info.Mode().IsRegular() && info.Size() >= offered.MaxMessageBytes {
				if _, probeErr := os.Stat(filepath.Join(staged[0], ".link-test")); errors.Is(probeErr, os.ErrNotExist) {
					break
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	if len(staged) != 1 {
		_ = crashGet.Process.Kill()
		_ = crashGet.Wait()
		t.Fatal("get staging was not observable before completion")
	}
	if err := agents[0].Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := agents[0].Wait(); err == nil {
		t.Fatal("crashed agent exited successfully")
	}
	if err := crashGet.Wait(); err == nil {
		t.Fatal("get survived agent crash")
	}
	if _, err := os.Stat(staged[0]); err != nil {
		t.Fatalf("crash staging disappeared before restart: %v", err)
	}
	inspectionConfig, err := database.Config(database.KindAgent, pathsA.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	inspection := sqlite.New(inspectionConfig)
	if err := inspection.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var crashStage, crashMarker, crashPhase string
	var crashRows, leased int
	if err := inspection.DB().QueryRow(`select count(*),stage_name,marker_name,phase,lease_token is not null from get_cleanup`).Scan(&crashRows, &crashStage, &crashMarker, &crashPhase, &leased); err != nil {
		t.Fatal(err)
	}
	if crashRows != 1 || crashStage != filepath.Base(staged[0]) || crashPhase != "data_created" || leased != 1 {
		t.Fatalf("durable crash row = rows=%d stage=%q phase=%q leased=%d", crashRows, crashStage, crashPhase, leased)
	}
	markerInfo, err := os.Lstat(filepath.Join(staged[0], crashMarker))
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Size() != 0 {
		t.Fatalf("durable crash marker = %v, %v", markerInfo, err)
	}
	if err := inspection.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	agents[0] = startAgentProcessWithStderr(t, ctx, homes[0], &agentLogs[0])
	waitAgentStatus(t, ctx, pathsA.AgentEndpoint)
	waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
	if _, err := os.Stat(staged[0]); err != nil {
		t.Fatalf("DB-only restart touched staging: %v", err)
	}
	crashEvents, _, err := runGetProcess(ctx, homes[0], "--context", "home", "get", "vm", "releases/active.bin", "--output", crashDestination)
	if err != nil || len(crashEvents) < 3 || crashEvents[1].State != "transferring" || crashEvents[1].Bytes != 0 || crashEvents[len(crashEvents)-1].State != "committed" {
		t.Fatalf("restart-from-zero get = %+v, %v", crashEvents, err)
	}
	if _, err := os.Stat(staged[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("same-parent get did not clean crash stage: %v", err)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "get", "vm", "releases/app.bin", "--output", destination).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("destination already exists")) {
		t.Fatalf("existing destination error = %v\n%s", err, output)
	}
	secretRoot := filepath.Join(dir, "private-secret")
	if err := os.Mkdir(secretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretRoot, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretRoot, filepath.Join(offeredRoots[1], "escape")); err == nil {
		output, getErr := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "get", "vm", "escape/secret.txt", "--output", filepath.Join(dir, "escaped.txt")).CombinedOutput()
		if getErr == nil || bytes.Contains(output, []byte(secretRoot)) {
			t.Fatalf("symlink escape error = %v\n%s", getErr, output)
		}
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "ls", "vm", "../private-secret").CombinedOutput(); err == nil || bytes.Contains(output, []byte(secretRoot)) {
		t.Fatalf("traversal error = %v\n%s", err, output)
	}
	healthy, _, err := runDoctorProcess(ctx, homes[0], "--context", "home", "--peer", "vm")
	if err != nil || healthy.Status != diagnostics.Pass || diagnosticCheck(healthy, "peer.direct").Status != diagnostics.Pass || diagnosticCheck(healthy, "context.stun").Status != diagnostics.Pass {
		t.Fatalf("healthy doctor = %+v, %v", healthy, err)
	}
	if check := diagnosticCheck(healthy, "peer.direct"); check.LocalCandidateType == "" || check.RemoteCandidateType == "" || check.LocalAddress == "" || check.RemoteAddress == "" {
		t.Fatalf("peer check = %+v", check)
	}
	peerDoctorOutput := runPXOutput(t, ctx, homes[0], "-c", "home", "@vm", "doctor", "--json")
	var peerDoctor diagnostics.Report
	if err := json.Unmarshal(peerDoctorOutput, &peerDoctor); err != nil || peerDoctor.Status != diagnostics.Pass || diagnosticCheck(peerDoctor, "peer.direct").Status != diagnostics.Pass {
		t.Fatalf("peer-first doctor = %+v, %v", peerDoctor, err)
	}
	failedPeer, _, err := runDoctorProcess(ctx, homes[0], "--context", "home", "--peer", "missing")
	if err == nil || diagnosticCheck(failedPeer, "peer.direct").Status != diagnostics.Fail {
		t.Fatalf("failed peer doctor = %+v, %v", failedPeer, err)
	}
	stunFailure, _, err := runDoctorProcess(ctx, homes[1], "--context", "home")
	if err == nil || diagnosticCheck(stunFailure, "context.stun").Status != diagnostics.Fail {
		t.Fatalf("STUN failure doctor = %+v, %v", stunFailure, err)
	}
	if runtime.GOOS != "windows" {
		withoutAcknowledgement := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[1], "--context", "home", "context", "configure", "--offered-root", "/")
		if output, configureErr := withoutAcknowledgement.CombinedOutput(); configureErr == nil || !bytes.Contains(output, []byte("--allow-filesystem-root is required")) {
			t.Fatalf("filesystem-root without acknowledgement = %v\n%s", configureErr, output)
		}
		narrowAcknowledgement := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[1], "--context", "home", "context", "configure", "--offered-root", offeredRoots[1], "--allow-filesystem-root")
		if output, configureErr := narrowAcknowledgement.CombinedOutput(); configureErr == nil || !bytes.Contains(output, []byte("only valid for a filesystem root")) {
			t.Fatalf("narrow-root acknowledgement = %v\n%s", configureErr, output)
		}
		// Native isolated filesystem-root end-to-end validation remains issue #138.
	}
	stopAgentCommand(t, ctx, homes[1])
	if err := agents[1].Wait(); err != nil {
		t.Fatal(err)
	}
	globalConfig, err := database.Config(database.KindAgent, pathsB.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	globalStore := sqlite.New(globalConfig)
	if err := globalStore.Start(ctx); err != nil {
		t.Fatal(err)
	}
	globalTx, err := globalStore.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := globalTx.Exec(`delete from recent_observations`); err != nil {
		t.Fatal(err)
	}
	if _, err := globalTx.Exec(`delete from contexts where name!='home'`); err != nil {
		t.Fatal(err)
	}
	for index := range 63 {
		name := fmt.Sprintf("f%02d", index)
		if _, err := globalTx.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) select ?,'http://127.0.0.1:1',server_id,device_id,private_key_path,public_key_path,label,'pending',0,offered_root,inbox_root,created_at,updated_at from contexts where name='home'`, name); err != nil {
			t.Fatal(err)
		}
	}
	insertGlobal, err := globalTx.Prepare(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values(?,'receive',?,'receiver_published',?,'laptop',?,'private',1,?)`)
	if err != nil {
		t.Fatal(err)
	}
	globalBase := time.Now().Add(-10_000 * time.Second).Unix()
	globalIndex := 0
	globalOldestID := ""
	insertFixture := func(contextName string, count int) {
		for range count {
			id := fmt.Sprintf("%064x", 100_000+globalIndex)
			if globalOldestID == "" {
				globalOldestID = id
			}
			if _, err := insertGlobal.Exec(contextName, id, laptopDeviceID, fmt.Sprintf("global-%04d.txt", globalIndex), globalBase+int64(globalIndex)); err != nil {
				t.Fatal(err)
			}
			globalIndex++
		}
	}
	insertFixture("f00", 65)
	for index := 1; index < 63; index++ {
		insertFixture(fmt.Sprintf("f%02d", index), 64)
	}
	insertFixture("home", 63)
	if globalIndex != recent.MaxPerAgent {
		t.Fatalf("global fixture rows = %d", globalIndex)
	}
	if err := insertGlobal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := globalTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := globalStore.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	agents[1] = startAgentProcessWithStderr(t, ctx, homes[1], &agentLogs[1])
	waitAgentStatus(t, ctx, pathsB.AgentEndpoint)
	waitContextStates(t, ctx, homes[1], map[string]string{"home": "connected"})
	globalEvents, _, err := runSendProcess(ctx, homes[0], nil, "--context", "home", "send", "vm", sendSource, "--name", "global-pressure.bin", "--recoverable")
	if err != nil || len(globalEvents) == 0 || globalEvents[len(globalEvents)-1].State != "committed" {
		t.Fatalf("global pressure send = %+v, %v", globalEvents, err)
	}
	globalRecentOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "recent", "--limit", "64", "--json")
	var globalRecent recent.Snapshot
	if err := json.Unmarshal(globalRecentOutput, &globalRecent); err != nil || len(globalRecent.Observations) != 64 || globalRecent.Observations[0].Destination != "global-pressure.bin" {
		t.Fatalf("global pressure recent = %+v, %v", globalRecent, err)
	}
	if err := os.RemoveAll(offeredRoots[0]); err != nil {
		t.Fatal(err)
	}
	degraded, _, err := runDoctorProcess(ctx, homes[0], "--local")
	if err == nil || diagnosticCheck(degraded, "local.offered_root").Status != diagnostics.Fail {
		t.Fatalf("degraded doctor = %+v, %v", degraded, err)
	}
	stopAgentCommand(t, ctx, homes[1])
	if err := agents[1].Wait(); err != nil {
		t.Fatal(err)
	}
	agents[1] = nil
	globalInspection := sqlite.New(globalConfig)
	if err := globalInspection.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var globalRows, oldestRows int
	if err := globalInspection.DB().QueryRow(`select count(*) from recent_observations`).Scan(&globalRows); err != nil {
		t.Fatal(err)
	}
	if err := globalInspection.DB().QueryRow(`select count(*) from recent_observations where transfer_id=?`, globalOldestID).Scan(&oldestRows); err != nil {
		t.Fatal(err)
	}
	if globalRows != recent.MaxPerAgent || oldestRows != 0 {
		t.Fatalf("global retention rows=%d oldest=%d", globalRows, oldestRows)
	}
	if err := globalInspection.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		memberOutput = runPXOutput(t, ctx, homes[0], "--context", "home", "devices", "list", "--json")
		devices = nil
		if err := json.Unmarshal(memberOutput, &devices); err == nil && len(devices) == 3 {
			for _, device := range devices {
				if device.DeviceID == vmPeer.DeviceID && device.Status == "offline" {
					deadline = time.Time{}
					break
				}
			}
			if deadline.IsZero() {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("offline member devices = %+v\n%s", devices, memberOutput)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "ls", "build").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("peer is enrolled but offline")) {
		t.Fatalf("offline peer resolution = %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "recent", "vm", "--json").CombinedOutput(); err == nil || !bytes.Contains(output, []byte("peer is enrolled but offline")) {
		t.Fatalf("offline recent query = %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "revoke", "--yes", "--json", "--", clearPeer.DeviceID).CombinedOutput(); err != nil {
		t.Fatalf("revoke clear peer = %v\n%s", err, output)
	}
	waitContextStates(t, ctx, homes[2], map[string]string{"home": "revoked"})
	if output, err := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[2], "--context", "home", "recent", "vm", "--json").CombinedOutput(); err == nil {
		t.Fatalf("revoked recent query succeeded: %s", output)
	}
	for index, agent := range agents {
		if agent == nil {
			continue
		}
		stopAgentCommand(t, ctx, homes[index])
		if err := agent.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	for role, expected := range map[int]string{0: "outgoing", 1: "incoming"} {
		logs := agentLogs[role].String()
		if ready, connected := strings.Index(logs, `"event":"agent.ready"`), strings.Index(logs, `"event":"context.connected"`); ready < 0 || connected < 0 || ready > connected {
			t.Fatalf("agent %d readiness/context order is invalid: %s", role, logs)
		}
		for _, event := range []string{"context.connected", "context.disconnected"} {
			if !strings.Contains(logs, `"event":"`+event+`"`) {
				t.Fatalf("agent %d operational logs missing %s: %s", role, event, logs)
			}
		}
		for _, event := range []string{"transfer.started", "transfer.committed"} {
			if !strings.Contains(logs, `"event":"`+event+`"`) || !strings.Contains(logs, `"direction":"`+expected+`"`) {
				t.Fatalf("agent %d operational logs missing %s/%s: %s", role, event, expected, logs)
			}
		}
		if role == 0 && !strings.Contains(logs, `"event":"transfer.failed"`) {
			t.Fatalf("outgoing agent logs missing transfer failure: %s", logs)
		}
		if !strings.Contains(logs, `"transfer_id":`) {
			t.Fatalf("agent %d transfer events are not correlated: %s", role, logs)
		}
		if strings.Contains(logs, "direct probe succeeded") || strings.Contains(logs, restartSource) || strings.Contains(logs, "resume_token") || strings.Contains(logs, "remote_address") || strings.Contains(logs, "local_address") {
			t.Fatalf("agent %d logs contain sensitive transfer details: %s", role, logs)
		}
	}
	stopServerCommand(t, ctx, serverHome)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorWithoutAgent(t *testing.T) {
	home := filepath.Join(t.TempDir(), "unused-home")
	for _, args := range [][]string{nil, {"--local"}} {
		report, stderr, err := runDoctorProcess(context.Background(), home, args...)
		if err == nil || report.Version != diagnostics.Version || report.Status != diagnostics.Fail {
			t.Fatalf("args = %v, report = %+v, stderr = %q, err = %v", args, report, stderr, err)
		}
		if stderr != "" {
			t.Fatalf("args = %v, duplicate stderr = %q", args, stderr)
		}
		if check := diagnosticCheck(report, "local.agent"); check.Status != diagnostics.Fail || !strings.Contains(check.Summary, "run px agent run or px startup install") {
			t.Fatalf("args = %v, local.agent = %+v", args, check)
		}
		for _, id := range []string{"local.ipc", "local.lock"} {
			if check := diagnosticCheck(report, id); check.Status != diagnostics.Skipped {
				t.Fatalf("args = %v, %s = %+v", args, id, check)
			}
		}
		if len(args) == 0 && diagnosticCheck(report, "context.prerequisite").Status != diagnostics.Skipped {
			t.Fatalf("context prerequisite was not skipped: %+v", report)
		}
	}
	command := exec.Command(binaryPath("px"), "--home", home, "doctor", "--local")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil || !strings.Contains(stdout.String(), "[fail] local local.agent: PX agent is not reachable; run px agent run or px startup install") || stderr.Len() != 0 {
		t.Fatalf("plain doctor stdout = %q, stderr = %q, err = %v", stdout.String(), stderr.String(), err)
	}
	if _, statErr := os.Stat(home); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("doctor mutated PX home: %v", statErr)
	}
}

func runDoctorProcess(ctx context.Context, home string, args ...string) (diagnostics.Report, string, error) {
	arguments := append([]string{"--home", home, "doctor", "--json"}, args...)
	command := exec.CommandContext(ctx, binaryPath("px"), arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	var report diagnostics.Report
	decodeErr := json.Unmarshal(stdout.Bytes(), &report)
	if decodeErr != nil && err == nil {
		err = decodeErr
	}
	return report, stderr.String(), err
}

func snapshotTrees(t *testing.T, roots []string) []string {
	t.Helper()
	var snapshot []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			identity := ""
			if info.Mode().IsRegular() {
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				identity = fmt.Sprintf("%x", sha256.Sum256(content))
			}
			snapshot = append(snapshot, root+"\x00"+filepath.ToSlash(relative)+"\x00"+info.Mode().String()+"\x00"+fmt.Sprint(info.Size())+"\x00"+identity)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(snapshot)
	return snapshot
}

func runSendProcess(ctx context.Context, home string, input io.Reader, args ...string) ([]transfer.ResumeEvent, string, error) {
	arguments := append([]string{"--home", home}, args...)
	arguments = append(arguments, "--json")
	command := exec.CommandContext(ctx, binaryPath("px"), arguments...)
	command.Stdin = input
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
	events := make([]transfer.ResumeEvent, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var event transfer.ResumeEvent
		if decodeErr := json.Unmarshal(line, &event); decodeErr != nil {
			if err == nil {
				err = decodeErr
			}
			break
		}
		events = append(events, event)
	}
	return events, stderr.String(), err
}

func runGetProcess(ctx context.Context, home string, args ...string) ([]offered.GetEvent, string, error) {
	arguments := append([]string{"--home", home}, args...)
	arguments = append(arguments, "--json")
	command := exec.CommandContext(ctx, binaryPath("px"), arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	decoder := json.NewDecoder(&stdout)
	events := make([]offered.GetEvent, 0)
	for decoder.More() {
		var event offered.GetEvent
		if decodeErr := decoder.Decode(&event); decodeErr != nil {
			if err == nil {
				err = decodeErr
			}
			break
		}
		events = append(events, event)
	}
	return events, stderr.String(), err
}

func diagnosticCheck(report diagnostics.Report, id string) diagnostics.Check {
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	return diagnostics.Check{}
}

func hasTransferEvent(events []transfer.ResumeEvent, state string) bool {
	for _, event := range events {
		if event.State == state {
			return true
		}
	}
	return false
}

func hasOfferedEntry(entries []offered.Entry, name string) bool {
	for _, entry := range entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}

func hasInboxEntry(entries []inbox.Entry, path string) bool {
	for _, entry := range entries {
		if entry.Path == path {
			return true
		}
	}
	return false
}

func runPXOutput(t *testing.T, ctx context.Context, home string, args ...string) []byte {
	t.Helper()
	arguments := append([]string{"--home", home}, args...)
	output, err := exec.CommandContext(ctx, binaryPath("px"), arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("px %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func runPXSensitiveOutput(t *testing.T, ctx context.Context, home string, forbidden [][]byte, args ...string) []byte {
	t.Helper()
	arguments := append([]string{"--home", home}, args...)
	output, err := exec.CommandContext(ctx, binaryPath("px"), arguments...).CombinedOutput()
	leaked := false
	for _, value := range forbidden {
		if len(value) > 0 && bytes.Contains(output, value) {
			leaked = true
		}
	}
	if err != nil || leaked {
		t.Fatalf("sensitive px command failed safely: command_error=%v output_bytes=%d bearer_present=%t", err, len(output), leaked)
	}
	return output
}

func inviteMaterialPresent(data []byte, token string, parsed membership.InviteToken) bool {
	return token != "" && bytes.Contains(data, []byte(token)) || bytes.Contains(data, inviteSecret(parsed))
}

func inviteSecret(parsed membership.InviteToken) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(parsed.Secret[:]))
}

func canonicalPath(t *testing.T, path string) string {
	t.Helper()
	value, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(value)
}

func listContexts(t *testing.T, ctx context.Context, home string) map[string]contextstate.State {
	t.Helper()
	output := runPXOutput(t, ctx, home, "context", "list", "--json")
	var states []contextstate.State
	if err := json.Unmarshal(output, &states); err != nil {
		t.Fatalf("decode context list: %v\n%s", err, output)
	}
	result := make(map[string]contextstate.State, len(states))
	for _, state := range states {
		result[state.Name] = state
	}
	return result
}

func waitContextStates(t *testing.T, ctx context.Context, home string, expected map[string]string) map[string]contextstate.State {
	t.Helper()
	for range 400 {
		states := listContexts(t, ctx, home)
		matched := true
		for name, expectedState := range expected {
			if states[name].State != expectedState {
				matched = false
				break
			}
		}
		if matched {
			return states
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("contexts did not reach states %+v", expected)
	return nil
}

func waitForFile(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", path, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func reserveUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startServerProcess(t *testing.T, ctx context.Context, home, address string, extraArgs ...string) *exec.Cmd {
	t.Helper()
	args := []string{"--home", home, "serve", "--listen", address}
	args = append(args, extraArgs...)
	command := exec.CommandContext(ctx, binaryPath("px-server"), args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return command
}

func startServerWithSTUNProcess(t *testing.T, ctx context.Context, home, address, stunAddress string) *exec.Cmd {
	t.Helper()
	command := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "serve", "--listen", address, "--stun-listen", stunAddress)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return command
}

func waitServerReady(t *testing.T, ctx context.Context, baseURL string) {
	t.Helper()
	for range 100 {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("rendezvous server did not become ready")
}

func serverStatus(t *testing.T, ctx context.Context, home string) serveradmin.Status {
	t.Helper()
	output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "status", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("server status: %v\n%s", err, output)
	}
	var status serveradmin.Status
	if err := json.Unmarshal(output, &status); err != nil || status.Version != serveradmin.Version {
		t.Fatalf("server status = %+v, %v\n%s", status, err, output)
	}
	return status
}

func postHTTPJSON(t *testing.T, ctx context.Context, endpoint string, input, output any) {
	postHTTPJSONFromIP(t, ctx, endpoint, "", input, output)
}

func postHTTPJSONFromIP(t *testing.T, ctx context.Context, endpoint, sourceIP string, input, output any) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if sourceIP != "" {
		request.Header.Set("X-Forwarded-For", sourceIP)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("POST %s: %s: %s", endpoint, response.Status, body)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func authenticateServerConnection(t *testing.T, ctx context.Context, baseURL string, privateKey ed25519.PrivateKey, credential membership.Credential) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(baseURL, "http")+"/v1/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var challenge rendezvousapi.Challenge
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	if err := rendezvousapi.VerifyServerChallenge(challenge, credential.Claims.ServerID, time.Now()); err != nil {
		t.Fatal(err)
	}
	signature, err := rendezvousapi.SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeServerMessage(t, ctx, conn, rendezvousapi.Authentication{Version: rendezvousapi.AuthenticationVersion, Type: "authenticate", Credential: credential, Signature: signature})
	return conn
}

func readServerMessageType(t *testing.T, ctx context.Context, conn *websocket.Conn, messageType string) mapServerMessage {
	t.Helper()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var message mapServerMessage
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == messageType {
			return message
		}
	}
}

type mapServerMessage struct {
	Version  int    `json:"version"`
	Type     string `json:"type"`
	DeviceID string `json:"device_id"`
}

func writeServerMessage(t *testing.T, ctx context.Context, conn *websocket.Conn, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func stopServerCommand(t *testing.T, ctx context.Context, home string) {
	t.Helper()
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", home, "stop").CombinedOutput(); err != nil {
		t.Fatalf("stop server: %v\n%s", err, output)
	}
}

func startAgentProcess(t *testing.T, ctx context.Context, home string) *exec.Cmd {
	return startAgentProcessWithStderr(t, ctx, home, io.Discard)
}

func startAgentProcessWithStderr(t *testing.T, ctx context.Context, home string, stderr io.Writer) *exec.Cmd {
	t.Helper()
	command := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "run")
	command.Stdout = io.Discard
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return command
}

func stopAgentProcess(command *exec.Cmd) {
	if command.ProcessState == nil || !command.ProcessState.Exited() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}
}

func waitAgentStatus(t *testing.T, ctx context.Context, endpoint string) agentapi.Status {
	t.Helper()
	var status agentapi.Status
	var lastErr error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lastErr = localipc.NewClient(endpoint).JSON(ctx, "GET", "/v1/status", nil, &status)
		if lastErr == nil {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatalf("agent did not become ready: %v", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatalf("agent did not become ready: %v", lastErr)
	return agentapi.Status{}
}

func stopAgentCommand(t *testing.T, ctx context.Context, home string) {
	t.Helper()
	command := exec.CommandContext(ctx, binaryPath("px"), "--home", home, "agent", "stop")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("stop agent: %v\n%s", err, output)
	}
}

func runBinary(t *testing.T, binary string, args ...string) {
	t.Helper()
	cmd := exec.Command(binaryPath(binary), args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

func binaryPath(name string) string {
	path := filepath.Join(binaryDir, name)
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	return path
}

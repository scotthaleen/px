//go:build process && smoke

package testscript_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/offered"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/transfer"
	_ "modernc.org/sqlite"
)

func TestPeerWorkflowSmoke(t *testing.T) {
	dir := t.TempDir()
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	stunAddress := reserveUDPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startServerWithSTUNProcess(t, ctx, serverHome, address, stunAddress)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)

	homes := []string{filepath.Join(dir, "laptop-home"), filepath.Join(dir, "vm-home")}
	offeredRoots := []string{filepath.Join(dir, "laptop-offered"), filepath.Join(dir, "vm-offered")}
	inboxRoots := []string{filepath.Join(dir, "laptop-inbox"), filepath.Join(dir, "vm-inbox")}
	labels := []string{"laptop", "vm"}
	agents := make([]*exec.Cmd, 0, len(homes))
	for index := range homes {
		for _, root := range []string{offeredRoots[index], inboxRoots[index]} {
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		agent := startAgentProcess(t, ctx, homes[index])
		agents = append(agents, agent)
		defer stopAgentProcess(agent)
		paths, err := apphome.Resolve(homes[index])
		if err != nil {
			t.Fatal(err)
		}
		waitAgentStatus(t, ctx, paths.AgentEndpoint)
	}
	for index := range homes {
		joinOutput := runPXOutput(t, ctx, homes[index], "--context", "home", "join", "http://"+address, "--name", labels[index], "--offered-root", offeredRoots[index], "--inbox-root", inboxRoots[index], "--stun", "stun:"+stunAddress, "--json")
		var joined contextstate.State
		if err := json.Unmarshal(joinOutput, &joined); err != nil || joined.PendingCode == "" {
			t.Fatalf("join %s = %+v, %v\n%s", labels[index], joined, err, joinOutput)
		}
		if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", joined.PendingCode, "--json").CombinedOutput(); err != nil {
			t.Fatalf("approve %s: %v\n%s", labels[index], err, output)
		}
	}
	for index := range homes {
		waitContextStates(t, ctx, homes[index], map[string]string{"home": "connected"})
	}
	statusOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "status", "--json")
	var status agentapi.Summary
	if err := json.Unmarshal(statusOutput, &status); err != nil || status.Status != "ok" || status.Context == nil || status.Context.OnlinePeers == nil || *status.Context.OnlinePeers != 1 || status.Transfers == nil || status.Transfers.Active != 0 || status.Transfers.Retryable != 0 {
		t.Fatalf("connected status = %+v, %v\n%s", status, err, statusOutput)
	}
	completion, err := exec.CommandContext(ctx, binaryPath("px"), "__complete", "--home", homes[0], "--context", "home", "@v").CombinedOutput()
	if err != nil || !bytes.Contains(completion, []byte("@vm\n")) {
		t.Fatalf("peer completion = %q, %v", completion, err)
	}

	content := []byte("peer-workflow-smoke\n")
	if err := os.WriteFile(filepath.Join(offeredRoots[1], "artifact.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	listOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@vm", "ls", "--json")
	var entries []offered.Entry
	if err := json.Unmarshal(listOutput, &entries); err != nil || !hasOfferedEntry(entries, "artifact.txt") {
		t.Fatalf("peer-first list = %+v, %v\n%s", entries, err, listOutput)
	}
	destination := filepath.Join(dir, "downloaded.txt")
	events, _, err := runGetProcess(ctx, homes[0], "--context", "home", "@vm", "get", "artifact.txt", "--output", destination)
	if err != nil || len(events) == 0 || events[len(events)-1].State != "committed" {
		t.Fatalf("peer-first get = %+v, %v", events, err)
	}
	if downloaded, err := os.ReadFile(destination); err != nil || !bytes.Equal(downloaded, content) {
		t.Fatalf("downloaded artifact = %q, %v", downloaded, err)
	}

	putRoot := filepath.Join(dir, "vm-put")
	if err := os.Mkdir(putRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	putRoot, err = filepath.EvalSymlinks(putRoot)
	if err != nil {
		t.Fatal(err)
	}
	runPXOutput(t, ctx, homes[1], "--context", "home", "context", "configure", "--put-root", putRoot, "--allow-put", "--json")
	putSource := filepath.Join(dir, "put-source.txt")
	putContent := []byte("create-only-put-smoke\n")
	if err := os.WriteFile(putSource, putContent, 0o600); err != nil {
		t.Fatal(err)
	}
	putOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "@vm", "put", putSource, "created.txt", "--json")
	lines := bytes.Split(bytes.TrimSpace(putOutput), []byte("\n"))
	var putResult put.Event
	if len(lines) == 0 || json.Unmarshal(lines[len(lines)-1], &putResult) != nil || putResult.State != "committed" || !putResult.Created {
		t.Fatalf("peer-first put = %+v\n%s", putResult, putOutput)
	}
	if created, err := os.ReadFile(filepath.Join(putRoot, "created.txt")); err != nil || !bytes.Equal(created, putContent) {
		t.Fatalf("put destination = %q, %v", created, err)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		replacement := []byte("replacement-put-smoke\n")
		if err := os.WriteFile(putSource, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256(putContent)
		putOutput = runPXOutput(t, ctx, homes[0], "--context", "home", "@vm", "put", putSource, "created.txt", "--replace", "--expect-sha256", fmt.Sprintf("%x", expected), "--json")
		lines = bytes.Split(bytes.TrimSpace(putOutput), []byte("\n"))
		putResult = put.Event{}
		if len(lines) == 0 || json.Unmarshal(lines[len(lines)-1], &putResult) != nil || putResult.State != "committed" || !putResult.Replaced || putResult.Created {
			t.Fatalf("peer-first replacement put = %+v\n%s", putResult, putOutput)
		}
		if replaced, err := os.ReadFile(filepath.Join(putRoot, "created.txt")); err != nil || !bytes.Equal(replaced, replacement) {
			t.Fatalf("replacement put destination = %q, %v", replaced, err)
		}
		replacementID := putResult.TransferID
		failedCAS := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "@vm", "put", putSource, "created.txt", "--replace", "--expect-sha256", strings.Repeat("0", 64), "--json")
		failedOutput, err := failedCAS.CombinedOutput()
		if err == nil || bytes.Contains(failedOutput, []byte("User Initiated Abort")) {
			t.Fatalf("CAS mismatch output=%q err=%v", failedOutput, err)
		}
		failedID := ""
		foundFailure := false
		for _, line := range bytes.Split(bytes.TrimSpace(failedOutput), []byte("\n")) {
			var event put.Event
			if json.Unmarshal(line, &event) == nil && event.TransferID != "" {
				failedID = event.TransferID
				if event.State == "failed" && strings.Contains(event.Error, put.ErrCASMismatch.Error()) {
					foundFailure = true
				}
			}
		}
		if failedID == "" || !foundFailure {
			t.Fatalf("CAS mismatch did not return bounded failure:\n%s", failedOutput)
		}
		if replaced, err := os.ReadFile(filepath.Join(putRoot, "created.txt")); err != nil || !bytes.Equal(replaced, replacement) {
			t.Fatalf("CAS mismatch changed destination = %q, %v", replaced, err)
		}
		showFailed := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[0], "--context", "home", "transfer", "show", failedID, "--json")
		if output, err := showFailed.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("transfer or context not found")) {
			t.Fatalf("CAS mismatch sender state output=%q err=%v", output, err)
		}

		stopAgentCommand(t, ctx, homes[0])
		stopAgentCommand(t, ctx, homes[1])
		if err := agents[0].Wait(); err != nil {
			t.Fatal(err)
		}
		if err := agents[1].Wait(); err != nil {
			t.Fatal(err)
		}
		reopenCommittedPutSender(t, homes[0], replacementID)
		agents[0] = startAgentProcess(t, ctx, homes[0])
		var receiverLog bytes.Buffer
		agents[1] = startAgentProcessWithStderr(t, ctx, homes[1], &receiverLog)
		defer stopAgentProcess(agents[0])
		defer stopAgentProcess(agents[1])
		paths, err := apphome.Resolve(homes[0])
		if err != nil {
			t.Fatal(err)
		}
		waitAgentStatus(t, ctx, paths.AgentEndpoint)
		waitContextStates(t, ctx, homes[0], map[string]string{"home": "connected"})
		waitContextPeer(t, ctx, homes[0], "vm")
		retryOutput := runPXOutput(t, ctx, homes[0], "--context", "home", "transfer", "retry", replacementID, "--json")
		retryLines := bytes.Split(bytes.TrimSpace(retryOutput), []byte("\n"))
		var retryResult transfer.ResumeEvent
		if len(retryLines) == 0 || json.Unmarshal(retryLines[len(retryLines)-1], &retryResult) != nil || retryResult.State != "committed" || !retryResult.Replaced || retryResult.Outcome != "replaced" || retryResult.Durability != "durability_confirmed" {
			t.Fatalf("committed put retry = %+v\n%s", retryResult, retryOutput)
		}
		if replaced, err := os.ReadFile(filepath.Join(putRoot, "created.txt")); err != nil || !bytes.Equal(replaced, replacement) {
			t.Fatalf("committed replay changed destination = %q, %v", replaced, err)
		}
		if bytes.Contains(receiverLog.Bytes(), []byte(`"event":"put.committed"`)) {
			t.Fatalf("committed replay duplicated event:\n%s", receiverLog.Bytes())
		}
	}
	if runtime.GOOS != "windows" {
		stopAgentCommand(t, ctx, homes[1])
		if err := agents[1].Wait(); err != nil {
			t.Fatal(err)
		}
		resolutionID, stagePath, acceptedPath := injectUnknownPutResolutionState(t, homes[1], putRoot)
		agents[1] = startAgentProcess(t, ctx, homes[1])
		defer stopAgentProcess(agents[1])
		paths, err := apphome.Resolve(homes[1])
		if err != nil {
			t.Fatal(err)
		}
		waitAgentStatus(t, ctx, paths.AgentEndpoint)
		waitContextStates(t, ctx, homes[1], map[string]string{"home": "connected"})
		showOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "transfer", "show", resolutionID, "--json")
		var item transfer.InventoryItem
		if err := json.Unmarshal(showOutput, &item); err != nil || item.State != "outcome_unknown" || !item.ActionRequired || item.Kind != "put-receive" {
			t.Fatalf("unknown put inventory=%+v err=%v\n%s", item, err, showOutput)
		}
		blocked := exec.CommandContext(ctx, binaryPath("px"), "--home", homes[1], "--context", "home", "context", "configure", "--allow-put=false", "--clear-put-root", "--json")
		if output, err := blocked.CombinedOutput(); err == nil || !bytes.Contains(output, []byte(contextstate.ErrContextAuthorityBlocked.Error())) || bytes.Contains(output, []byte(putRoot)) || bytes.Contains(output, []byte(stagePath)) {
			t.Fatalf("unresolved put authority change output=%q err=%v", output, err)
		}
		resolveOutput := runPXOutput(t, ctx, homes[1], "--context", "home", "transfer", "resolve", resolutionID, "--accept-current", "--yes", "--json")
		var resolution put.ResolutionResult
		decoder := json.NewDecoder(bytes.NewReader(resolveOutput))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&resolution); err != nil || resolution.Version != put.ResolutionVersion || resolution.State != "resolved_accept_current" || resolution.TransferID != resolutionID || resolution.Context != "home" || resolution.Destination != "accepted-current.txt" || bytes.Contains(resolveOutput, []byte(putRoot)) || bytes.Contains(resolveOutput, []byte(stagePath)) {
			t.Fatalf("resolution=%+v err=%v\n%s", resolution, err, resolveOutput)
		}
		if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
			t.Fatalf("resolved stage remains: %v", err)
		}
		if content, err := os.ReadFile(acceptedPath); err != nil || string(content) != "accepted-current\n" {
			t.Fatalf("accepted destination=%q err=%v", content, err)
		}
		showOutput = runPXOutput(t, ctx, homes[1], "--context", "home", "transfer", "show", resolutionID, "--json")
		item = transfer.InventoryItem{}
		if err := json.Unmarshal(showOutput, &item); err != nil || item.State != "resolved_accept_current" || item.ActionRequired || item.CleanupPending || item.LocalCommitted || item.OutcomeUnknown {
			t.Fatalf("resolved put inventory=%+v err=%v\n%s", item, err, showOutput)
		}
		runPXOutput(t, ctx, homes[1], "--context", "home", "context", "configure", "--allow-put=false", "--clear-put-root", "--json")
	}

	for index, agent := range agents {
		stopAgentCommand(t, ctx, homes[index])
		if err := agent.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	stopServerCommand(t, ctx, serverHome)
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func reopenCommittedPutSender(t *testing.T, home, id string) {
	t.Helper()
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result, err := db.Exec(`update put_transfers set state='transferring',created=0,replaced=0,durability=null,lease_token=null,lease_expires_at=null where direction='send' and transfer_id=? and state='committed'`, id)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("reopen committed put sender rows=%d err=%v", rows, err)
	}
}

func injectUnknownPutResolutionState(t *testing.T, home, putRoot string) (string, string, string) {
	t.Helper()
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var localDeviceID string
	var rootRevision int64
	if err := db.QueryRow(`select device_id,put_root_revision from contexts where name='home'`).Scan(&localDeviceID, &rootRevision); err != nil {
		t.Fatal(err)
	}
	const id = "dddddddddddddddddddddddddddddddd"
	stageName := ".px-" + id + ".put"
	stagePath := filepath.Join(putRoot, stageName)
	acceptedPath := filepath.Join(putRoot, "accepted-current.txt")
	stageContent := []byte("unknown-stage\n")
	if err := os.WriteFile(stagePath, stageContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acceptedPath, []byte("accepted-current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parentIdentity := nativeTestFileIdentity(t, putRoot)
	stageIdentity := nativeTestFileIdentity(t, stagePath)
	digest := sha256.Sum256(stageContent)
	now := time.Now().UTC().Unix()
	_, err = db.Exec(`insert into put_transfers(direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,state,acknowledged_bytes,created_at,updated_at,expires_at,next_retry_at) values('receive',?,2,'home','synthetic-peer',?,'synthetic-peer','accepted-current.txt','create',?,?,32768,8,?,?,?,?,?,'outcome_unknown',?,?,?,?,?)`, id, localDeviceID, len(stageContent), fmt.Sprintf("%x", digest), rootRevision, putRoot, parentIdentity, stageName, stageIdentity, len(stageContent), now, now, now+int64(put.Lifetime/time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	return id, stagePath, acceptedPath
}

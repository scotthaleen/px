//go:build linux

package put_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/scotthaleen/px/internal/put"
	"golang.org/x/sys/unix"
)

func TestLinuxReplacementPreservesBasicMetadataAndCAS(t *testing.T) {
	db := putDatabase(t)
	store := put.NewStore(func() *sql.DB { return db })
	root := t.TempDir()
	destination := filepath.Join(root, "result")
	oldContent := []byte("old content")
	if err := os.WriteFile(destination, oldContent, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source")
	newContent := []byte("replacement content")
	if err := os.WriteFile(source, newContent, 0o600); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(oldContent)
	result, receiveErr := runReplacement(t, store, root, source, hex.EncodeToString(expected[:]))
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if result.Created || !result.Replaced {
		t.Fatalf("replacement result=%+v", result)
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != string(newContent) {
		t.Fatalf("replacement content=%q err=%v", got, err)
	}
	after, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat := before.Sys().(*syscall.Stat_t)
	afterStat := after.Sys().(*syscall.Stat_t)
	if after.Mode().Perm() != before.Mode().Perm() || afterStat.Uid != beforeStat.Uid || afterStat.Gid != beforeStat.Gid {
		t.Fatalf("metadata before=%#o/%d/%d after=%#o/%d/%d", before.Mode().Perm(), beforeStat.Uid, beforeStat.Gid, after.Mode().Perm(), afterStat.Uid, afterStat.Gid)
	}
}

func TestLinuxReplacementCASMismatchAndXattrFailWithoutChangingDestination(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string) string
	}{
		{name: "CAS mismatch", prepare: func(_ *testing.T, _ string) string { return string(make([]byte, 64)) }},
		{name: "extended attribute", prepare: func(t *testing.T, destination string) string {
			if err := unix.Setxattr(destination, "user.px-test", []byte("present"), 0); err != nil {
				t.Skipf("filesystem does not support user xattrs: %v", err)
			}
			return ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := putDatabase(t)
			store := put.NewStore(func() *sql.DB { return db })
			root := t.TempDir()
			destination := filepath.Join(root, "result")
			if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			expected := test.prepare(t, destination)
			if test.name == "CAS mismatch" {
				expected = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := runReplacement(t, store, root, source, expected)
			if err == nil {
				t.Fatal("unsafe replacement succeeded")
			}
			if test.name == "CAS mismatch" && (!strings.Contains(err.Error(), put.ErrCASMismatch.Error()) || strings.Contains(err.Error(), "User Initiated Abort")) {
				t.Fatalf("CAS mismatch error=%v", err)
			}
			got, readErr := os.ReadFile(destination)
			if readErr != nil || string(got) != "original" {
				t.Fatalf("destination=%q err=%v", got, readErr)
			}
			records, inventoryErr := store.Inventory(t.Context(), "home", 64)
			if inventoryErr != nil || len(records) != 0 {
				t.Fatalf("rejected replacement inventory=%+v err=%v", records, inventoryErr)
			}
		})
	}
}

func runReplacement(t *testing.T, store *put.Store, root, source, expected string) (put.Result, error) {
	t.Helper()
	left, right := make(chan put.Message, 8), make(chan put.Message, 8)
	received := make(chan error, 1)
	go func() {
		_, err := put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	result, sendErr := put.Send(t.Context(), memoryChannel{send: left, receive: right}, put.SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Replace: true, ExpectSHA256: expected, Store: store})
	return result, errors.Join(sendErr, <-received)
}

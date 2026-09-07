//go:build linux

package put

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinuxReplacementStageRejectsInheritedDefaultACL(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("default ACL test requires setfacl")
	}
	directory := t.TempDir()
	if output, err := exec.Command(setfacl, "-m", "d:u:65534:r--", directory).CombinedOutput(); err != nil {
		t.Skipf("filesystem does not support a default ACL: %v: %s", err, output)
	}
	path := filepath.Join(directory, "stage")
	if err := os.WriteFile(path, []byte("stage"), 0o640); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != uint32(os.Geteuid()) {
		t.Skipf("stage owner UID %d differs from effective UID %d", stat.Uid, os.Geteuid())
	}
	record := Record{Manifest: Manifest{Mode: "replace"}, OldUID: stat.Uid, OldGID: stat.Gid, OldMode: uint32(info.Mode().Perm())}
	if _, err := validateStageFileForRecord(file, 1, record); err == nil {
		t.Fatal("replacement stage with an inherited default ACL was accepted")
	}
}

func TestLinuxCreateStageAndAncestryRejectInheritedACLs(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("ACL test requires setfacl")
	}
	root := t.TempDir()
	parent, err := openDestinationParent(root, "result", false)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(setfacl, "-m", "d:u:65534:---", root).CombinedOutput(); err != nil {
		parent.Close()
		t.Skipf("filesystem does not support a default ACL: %v: %s", err, output)
	}
	record := Record{Manifest: Manifest{Mode: "create"}, ParentPath: parent.path, ParentIdentity: parentDurableIdentity(parent), StageName: ".px-0123456789abcdef0123456789abcdef.put", State: "stage_intent"}
	if stage, _, err := createOrOpenStage(parent, Manifest{}, record); err == nil {
		stage.Close()
		t.Fatal("create stage with inherited ACL metadata was accepted")
	} else {
		parent.Close()
	}
	if ancestry, err := openDestinationParent(root, "result", false); err == nil {
		ancestry.Close()
		t.Fatal("put ancestry with a default ACL was accepted")
	}
}

//go:build darwin

package put

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseDarwinACLResponse(t *testing.T) {
	valid := darwinACLResponse(kauthFileSecNoACL, kauthFileSecHeaderSize)
	for _, test := range []struct {
		name    string
		buffer  []byte
		wantErr bool
	}{
		{name: "no ACL", buffer: valid},
		{name: "APFS absent ACL", buffer: darwinAbsentACLResponse()},
		{name: "absent ACL without APFS proof", buffer: darwinAbsentACLResponse(), wantErr: true},
		{name: "absent ACL with malformed offset", buffer: mutateDarwinACLResponse(darwinAbsentACLResponse(), 24, 8), wantErr: true},
		{name: "absent ACL with malformed length", buffer: mutateDarwinACLResponse(darwinAbsentACLResponse(), 28, 44), wantErr: true},
		{name: "ACL entry", buffer: darwinACLResponse(1, kauthFileSecHeaderSize+kauthACESize), wantErr: true},
		{name: "empty ACL", buffer: darwinACLResponse(0, kauthFileSecHeaderSize), wantErr: true},
		{name: "missing returned proof", buffer: mutateDarwinACLResponse(valid, 4, 0), wantErr: true},
		{name: "missing ACL proof", buffer: mutateDarwinACLResponse(valid, 4, attrCMNReturnedAttrs), wantErr: true},
		{name: "truncated total", buffer: mutateDarwinACLResponse(valid, 0, uint32(len(valid)+4)), wantErr: true},
		{name: "short prefix", buffer: valid[:attributeResponsePrefixSize-1], wantErr: true},
		{name: "unaligned reference", buffer: mutateDarwinACLResponse(valid, 24, 9), wantErr: true},
		{name: "backward reference", buffer: mutateDarwinACLResponse(valid, 24, ^uint32(23)), wantErr: true},
		{name: "out of range reference", buffer: mutateDarwinACLResponse(valid, 28, kauthFileSecHeaderSize+4), wantErr: true},
		{name: "bad magic", buffer: mutateDarwinACLResponse(valid, attributeResponsePrefixSize, 0), wantErr: true},
		{name: "oversized count", buffer: mutateDarwinACLResponse(valid, attributeResponsePrefixSize+36, kauthACLMaxEntries+1), wantErr: true},
		{name: "NOACL with entries", buffer: darwinACLResponse(kauthFileSecNoACL, kauthFileSecHeaderSize+kauthACESize), wantErr: true},
		{name: "entry length mismatch", buffer: darwinACLResponse(1, kauthFileSecHeaderSize), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowAbsentAPFSACL := test.name == "APFS absent ACL"
			err := parseDarwinACLResponse(test.buffer, allowAbsentAPFSACL)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestDarwinACLEnumerationOnAPFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "destination")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		t.Fatal(err)
	}
	if filesystemTypeName(filesystem.Fstypename) != "apfs" {
		t.Skipf("native ACL test requires APFS, got %q", filesystemTypeName(filesystem.Fstypename))
	}
	if err := validateDarwinACL(file, true); err != nil {
		t.Fatalf("plain APFS file rejected: %v", err)
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone deny write", path).CombinedOutput(); err != nil {
		t.Skipf("cannot set test ACL: %v: %s", err, output)
	}
	if err := validateDarwinACL(file, true); err == nil {
		t.Fatal("APFS file with an ACL was accepted")
	}
}

func TestDarwinReplacementStageRejectsExtendedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage")
	if err := os.WriteFile(path, []byte("stage"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		t.Fatal(err)
	}
	if filesystemTypeName(filesystem.Fstypename) != "apfs" {
		t.Skipf("replacement stage ACL test requires APFS, got %q", filesystemTypeName(filesystem.Fstypename))
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := Record{Manifest: Manifest{Mode: "replace"}, OldUID: stat.Uid, OldGID: stat.Gid, OldMode: uint32(info.Mode().Perm())}
	if _, err := validateStageFileForRecord(file, 1, record); err != nil {
		t.Fatalf("plain APFS stage rejected: %v", err)
	}
	if err := unix.Fsetxattr(int(file.Fd()), "com.px.stage-test", []byte("present"), 0); err != nil {
		t.Skipf("cannot set test stage xattr: %v", err)
	}
	if _, err := validateStageFileForRecord(file, 1, record); err == nil {
		t.Fatal("replacement stage with an unrecognized xattr was accepted")
	}
	if err := unix.Fremovexattr(int(file.Fd()), "com.px.stage-test"); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone deny write", path).CombinedOutput(); err != nil {
		t.Skipf("cannot set test stage ACL: %v: %s", err, output)
	}
	if _, err := validateStageFileForRecord(file, 1, record); err == nil {
		t.Fatal("replacement stage with an ACL was accepted")
	}
}

func TestDarwinCreateStageRejectsInheritedSecurityMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage")
	if err := os.WriteFile(path, []byte("stage"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := requireAPFS(file); err != nil {
		t.Skipf("create stage metadata test requires APFS: %v", err)
	}
	if err := unix.Fsetxattr(int(file.Fd()), "com.px.stage-test", []byte("present"), 0); err != nil {
		t.Skipf("cannot set test stage xattr: %v", err)
	}
	if _, err := validateStageFileForRecord(file, 1, Record{Manifest: Manifest{Mode: "create"}}); err == nil {
		t.Fatal("create stage with inherited security metadata was accepted")
	}
}

func TestDarwinPutAncestryRejectsExtendedACL(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("/bin/chmod", "+a", "everyone deny write", root).CombinedOutput(); err != nil {
		t.Skipf("cannot set test directory ACL: %v: %s", err, output)
	}
	if parent, err := openDestinationParent(root, "result", false); err == nil {
		parent.Close()
		t.Fatal("put ancestry with an extended ACL was accepted")
	}
}

func darwinACLResponse(entryCount uint32, payloadLength int) []byte {
	buffer := make([]byte, attributeResponsePrefixSize+payloadLength)
	binary.LittleEndian.PutUint32(buffer[0:4], uint32(len(buffer)))
	binary.LittleEndian.PutUint32(buffer[4:8], attrCMNReturnedAttrs|attrCMNExtendedSecurity)
	binary.LittleEndian.PutUint32(buffer[24:28], 8)
	binary.LittleEndian.PutUint32(buffer[28:32], uint32(payloadLength))
	binary.LittleEndian.PutUint32(buffer[attributeResponsePrefixSize:attributeResponsePrefixSize+4], kauthFileSecMagic)
	binary.LittleEndian.PutUint32(buffer[attributeResponsePrefixSize+36:attributeResponsePrefixSize+40], entryCount)
	return buffer
}

func darwinAbsentACLResponse() []byte {
	buffer := make([]byte, attributeResponsePrefixSize)
	binary.LittleEndian.PutUint32(buffer[0:4], uint32(len(buffer)))
	binary.LittleEndian.PutUint32(buffer[4:8], attrCMNReturnedAttrs)
	return buffer
}

func mutateDarwinACLResponse(source []byte, offset int, value uint32) []byte {
	buffer := append([]byte(nil), source...)
	binary.LittleEndian.PutUint32(buffer[offset:offset+4], value)
	return buffer
}

func TestDarwinPublicationRejectsSourceIdentityChangeBeforeLink(t *testing.T) {
	root := t.TempDir()
	parent, err := openDestinationParent(root, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{ParentPath: parent.path, ParentIdentity: parent.identities[len(parent.identities)-1], StageName: ".px-0123456789abcdef0123456789abcdef.put", State: "stage_intent"}
	stage, _, err := createOrOpenStage(parent, Manifest{}, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	stagePath := filepath.Join(root, stage.Name)
	if err := os.Rename(stagePath, stagePath+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stage.Publish(t.Context(), "result", Manifest{Mode: "create"}); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("pre-link identity error=%v", err)
	}
}

func TestDarwinPostLinkIdentityMismatchClassifiesAsNotPinned(t *testing.T) {
	root := t.TempDir()
	parent, err := openDestinationParent(root, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{ParentPath: parent.path, ParentIdentity: parent.identities[len(parent.identities)-1], StageName: ".px-fedcba9876543210fedcba9876543210.put", State: "stage_intent"}
	stage, _, err := createOrOpenStage(parent, Manifest{}, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	stagePath := filepath.Join(root, stage.Name)
	if err := os.Rename(stagePath, stagePath+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishPinned(stage.File, parent.Parent(), stage.Name, "result"); err != nil {
		t.Fatal(err)
	}
	created, known := destinationHasIdentity(parent.Parent(), "result", stage.Identity)
	if !known || created {
		t.Fatalf("post-link classification known=%t pinned=%t", known, created)
	}
}

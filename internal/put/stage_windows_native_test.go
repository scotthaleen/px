//go:build windows

package put

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"golang.org/x/sys/windows"
)

func TestWindowsNativeNTFSCreatePublicationAndCleanup(t *testing.T) {
	root := t.TempDir()
	parent := openWindowsNativeTestParent(t, root, "result.txt")
	record := windowsNativeTestRecord(parent, "result.txt")
	content := []byte("Windows NTFS create-only publication\n")
	record.Manifest.Size = int64(len(content))
	record.Manifest.SHA256 = "69550e330134bf3db8651007392898392aaf040010a3f9ff40110286baf3da93"
	db := windowsNativeDatabase(t, root)
	store := NewStore(func() *sql.DB { return db })
	lease, err := store.ReserveReceiver(t.Context(), record, record.ParentPath, record.ParentIdentity, record.StageName)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	defer store.ReleaseReceiver(record.ID, lease)
	stage, attached, err := createOrOpenStage(parent, record.Manifest, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if !attached {
		t.Fatal("new stage identity was not attached")
	}
	record.StageIdentity, stage.record.StageIdentity = stage.Identity, stage.Identity
	manifest := record.Manifest
	stage.record.Manifest = manifest
	if err := store.AttachStage(t.Context(), record.ID, lease, stage.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := stage.File.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stage.VerifyContent(t.Context(), manifest); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateOffset(t.Context(), record.ID, lease, manifest.Size); err != nil {
		t.Fatal(err)
	}
	if err := store.PublicationIntent(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	created, durability, err := stage.Publish(t.Context(), "result.txt", manifest)
	if err != nil || !created || durability != "durability_confirmed" {
		t.Fatalf("publish created=%t durability=%q err=%v", created, durability, err)
	}
	if err := validateWindowsEntry(stage.parent.Parent(), "result.txt", stage.Identity, 2); err != nil {
		t.Fatalf("destination identity/link count: %v", err)
	}
	record.Manifest = manifest
	record.StageIdentity = stage.Identity
	record.State = "publication_intent"
	result, settled, err := reconcilePublication(record)
	if err != nil || !settled || !result.Created {
		t.Fatalf("recovery result=%+v settled=%t err=%v", result, settled, err)
	}
	if err := store.CommitReceiver(t.Context(), record.ID, lease, durability); err != nil {
		t.Fatal(err)
	}
	record.State = "committed"
	if err := store.CleanupCommitted(t.Context(), record, lease); err != nil {
		t.Fatalf("full committed cleanup: %v", err)
	}
	cleaned, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || cleaned.State != "committed" || cleaned.StageName != "" || cleaned.StageIdentity != "" {
		t.Fatalf("cleaned record=%+v exists=%t err=%v", cleaned, exists, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "result.txt")); err != nil || string(got) != string(content) {
		t.Fatalf("published content=%q err=%v", got, err)
	}
}

func TestWindowsNativeNTFSReplacementCASAndCleanup(t *testing.T) {
	root := t.TempDir()
	oldContent := []byte("old Windows content\n")
	newContent := []byte("new Windows content\n")
	destinationPath := filepath.Join(root, "result.txt")
	if err := os.WriteFile(destinationPath, oldContent, 0o600); err != nil {
		t.Fatal(err)
	}
	removeWindowsNativeTestShortName(t, destinationPath)
	parent := openWindowsNativeTestParent(t, root, "result.txt")
	evidence, err := inspectReplacementDestination(parent, "result.txt")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	record := windowsNativeTestRecord(parent, "result.txt")
	record.Manifest.Mode = "replace"
	record.Manifest.ExpectSHA256 = "8dbca4b1970bbfce9911771020591371e7155af960a570b6a5ed01f0d7440c47"
	record.Manifest.Size = int64(len(newContent))
	record.Manifest.SHA256 = "5218f67d7393bb76860bf0e1789a37f90ec54e865008162ff1c4207b45b48173"
	record.OldIdentity = evidence.Identity
	record.OldMetadata = evidence.Metadata
	record.BackupName, record.BackupSize, err = replacementBackupEvidence(parent, record.ID, evidence)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	record.BackupIdentity = evidence.Identity
	db := windowsNativeDatabase(t, root)
	store := NewStore(func() *sql.DB { return db })
	lease, err := store.ReserveReceiver(t.Context(), record, record.ParentPath, record.ParentIdentity, record.StageName)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	defer store.ReleaseReceiver(record.ID, lease)
	stage, attached, err := createOrOpenStage(parent, record.Manifest, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if !attached {
		t.Fatal("new replacement stage identity was not attached")
	}
	record.StageIdentity, stage.record.StageIdentity = stage.Identity, stage.Identity
	if err := store.AttachStage(t.Context(), record.ID, lease, stage.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File.Write(newContent); err != nil {
		t.Fatal(err)
	}
	if err := stage.File.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stage.VerifyContent(t.Context(), record.Manifest); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateOffset(t.Context(), record.ID, lease, record.Size); err != nil {
		t.Fatal(err)
	}
	if err := store.PublicationIntent(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	replaced, durability, err := stage.Publish(t.Context(), "result.txt", record.Manifest)
	if err != nil || !replaced || durability != "durability_confirmed" {
		t.Fatalf("publish replaced=%t durability=%q err=%v", replaced, durability, err)
	}
	if got, err := os.ReadFile(destinationPath); err != nil || string(got) != string(newContent) {
		t.Fatalf("replacement content=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, record.BackupName)); err != nil || string(got) != string(oldContent) {
		t.Fatalf("backup content=%q err=%v", got, err)
	}
	record.State = "publication_intent"
	result, settled, err := reconcilePublication(record)
	if err != nil || !settled || !result.Replaced {
		t.Fatalf("recovery result=%+v settled=%t err=%v", result, settled, err)
	}
	if err := store.CommitReceiver(t.Context(), record.ID, lease, durability); err != nil {
		t.Fatal(err)
	}
	record.State = "committed"
	if err := store.CleanupCommitted(t.Context(), record, lease); err != nil {
		t.Fatalf("replacement cleanup: %v", err)
	}
	cleaned, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || cleaned.State != "committed" || cleaned.StageName != "" || cleaned.BackupName != "" || cleaned.BackupIdentity != "" || cleaned.BackupSize != 0 {
		t.Fatalf("cleaned replacement=%+v exists=%t err=%v", cleaned, exists, err)
	}
	if _, err := os.Stat(filepath.Join(root, record.BackupName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup remains after cleanup: %v", err)
	}
}

func TestWindowsNativeNTFSReplacementCASMismatchPreservesDestination(t *testing.T) {
	root := t.TempDir()
	oldContent := []byte("old content\n")
	if err := os.WriteFile(filepath.Join(root, "result.txt"), oldContent, 0o600); err != nil {
		t.Fatal(err)
	}
	removeWindowsNativeTestShortName(t, filepath.Join(root, "result.txt"))
	parent := openWindowsNativeTestParent(t, root, "result.txt")
	evidence, err := inspectReplacementDestination(parent, "result.txt")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	record := windowsNativeTestRecord(parent, "result.txt")
	record.Manifest.Mode = "replace"
	record.Manifest.ExpectSHA256 = strings.Repeat("0", 64)
	record.OldIdentity = evidence.Identity
	record.OldMetadata = evidence.Metadata
	record.BackupName, record.BackupSize, err = replacementBackupEvidence(parent, record.ID, evidence)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	record.BackupIdentity = evidence.Identity
	stage, _, err := createOrOpenStage(parent, record.Manifest, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	stage.record.StageIdentity = stage.Identity
	if _, _, err := stage.Publish(t.Context(), "result.txt", record.Manifest); !errors.Is(err, ErrCASMismatch) || !errors.Is(err, errPublishNotAttempted) {
		t.Fatalf("CAS mismatch error=%v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "result.txt")); err != nil || string(got) != string(oldContent) {
		t.Fatalf("destination changed on CAS mismatch: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, record.BackupName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created on CAS mismatch: %v", err)
	}
}

func TestWindowsNativeNTFSReplacementRecoveryCompletesMetadata(t *testing.T) {
	root := t.TempDir()
	destinationPath := filepath.Join(root, "result.txt")
	if err := os.WriteFile(destinationPath, []byte("old Windows content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeWindowsNativeTestShortName(t, destinationPath)
	parent := openWindowsNativeTestParent(t, root, "result.txt")
	evidence, err := inspectReplacementDestination(parent, "result.txt")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	record := windowsNativeTestRecord(parent, "result.txt")
	record.Manifest.Mode = "replace"
	record.OldIdentity = evidence.Identity
	record.OldMetadata = evidence.Metadata
	record.BackupIdentity = evidence.Identity
	record.BackupName, record.BackupSize, err = replacementBackupEvidence(parent, record.ID, evidence)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	stage, _, err := createOrOpenStage(parent, record.Manifest, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	record.StageIdentity = stage.Identity
	if _, err := stage.File.Write([]byte("new Windows content\n")); err != nil {
		t.Fatal(err)
	}
	absoluteParent, err := windowsVolumeGUIDPath(stage.parent.Parent())
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.File.Close(); err != nil {
		t.Fatal(err)
	}
	stage.File = nil
	if err := stage.oldDestination.Close(); err != nil {
		t.Fatal(err)
	}
	stage.oldDestination = nil
	if err := replaceWindowsFile(filepath.Join(absoluteParent, "result.txt"), filepath.Join(absoluteParent, record.StageName), filepath.Join(absoluteParent, record.BackupName)); err != nil {
		t.Fatal(err)
	}
	raw, err := ntOpenRelative(stage.parent.Parent(), "result.txt", windowsMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(raw.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("raw replacement DACL unavailable: %v", err)
	}
	if err := windows.SetSecurityInfo(windows.Handle(raw.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsShortName(windows.Handle(raw.Fd()), "PXRCVRY.TMP"); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsNoShortName(raw); err == nil {
		t.Fatal("controlled recovery short name was not created")
	}
	rawSecurity, err := windowsSecurityEvidence(raw, windowsStageDangerous)
	_ = raw.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(record.OldMetadata, rawSecurity) {
		t.Fatal("raw ReplaceFileW result unexpectedly retained exact destination security")
	}
	result, settled, err := reconcilePublication(record)
	if err != nil || !settled || !result.Replaced {
		t.Fatalf("replacement recovery result=%+v settled=%t err=%v", result, settled, err)
	}
	parent = openWindowsNativeTestParent(t, root, "result.txt")
	defer parent.Close()
	published, err := inspectReplacementDestination(parent, "result.txt")
	if err != nil || published.Identity != record.StageIdentity || published.Metadata != record.OldMetadata {
		t.Fatalf("recovered replacement evidence=%+v err=%v", published, err)
	}
	result, settled, err = reconcilePublication(record)
	if err != nil || !settled || !result.Replaced {
		t.Fatalf("idempotent replacement recovery result=%+v settled=%t err=%v", result, settled, err)
	}
}

func TestWindowsNativeMetadataOnlyRelativeOpens(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, "result")
	defer parent.Close()
	entry, err := ntOpenRelative(parent.Parent(), "entry", windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		t.Fatalf("metadata-only open: %v", err)
	}
	defer entry.Close()
	if info, err := windowsHandleInfo(entry); err != nil || info.directory {
		t.Fatalf("metadata-only info=%+v err=%v", info, err)
	}
	if _, state := windowsEntryIdentity(parent.Parent(), "missing"); state != windowsEntryAbsent {
		t.Fatalf("missing metadata-only open state=%d", state)
	}
}

func TestWindowsNativePinsDriveRootBeforeRelativeTraversal(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, "nested/result")
	defer parent.Close()
	volume := filepath.VolumeName(root)
	if parent.anchorPath != volume+`\` || !windowsVolumeGUIDRoot(parent.anchorGUID) || parent.path != nested || len(parent.dirs) < 2 {
		t.Fatalf("pinned anchor=%q GUID=%q parent=%q handles=%d", parent.anchorPath, parent.anchorGUID, parent.path, len(parent.dirs))
	}
	if err := parent.Revalidate(); err != nil {
		t.Fatalf("drive-root revalidation: %v", err)
	}
	stablePath, err := windowsVolumeGUIDPath(parent.Parent())
	if err != nil || !strings.HasPrefix(stablePath, `\\?\Volume{`) || strings.HasPrefix(strings.ToLower(stablePath), strings.ToLower(volume)) {
		t.Fatalf("stable parent path=%q err=%v", stablePath, err)
	}
}

func TestWindowsNativeVolumeDeviceInformation(t *testing.T) {
	volumeRoot := filepath.VolumeName(t.TempDir()) + `\`
	root, err := ntOpenVolumeRoot(volumeRoot, windowsTraversalAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var device struct {
		DeviceType      uint32
		Characteristics uint32
	}
	var status windows.IO_STATUS_BLOCK
	result, _, _ := ntQueryVolumeInformationFile.Call(uintptr(root.Fd()), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), 4)
	t.Logf("FileFsDeviceInformation status=%#x device_type=%#x remote=%t", uint32(result), device.DeviceType, device.Characteristics&0x10 != 0)
	if windows.NTStatus(result) != windows.STATUS_SUCCESS {
		t.Fatalf("FileFsDeviceInformation status=%#x", uint32(result))
	}
	if device.DeviceType != 7 && device.DeviceType != 8 || device.Characteristics&0x10 != 0 {
		t.Fatalf("unsupported local disk device type=%#x characteristics=%#x", device.DeviceType, device.Characteristics)
	}
}

func TestWindowsNativeVolumeAnchorSteps(t *testing.T) {
	volumeRoot := filepath.VolumeName(t.TempDir()) + `\`
	root, err := ntOpenVolumeRoot(volumeRoot, windowsTraversalAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	t.Log("anchor opened")
	if err := requireNTFS(root); err != nil {
		t.Fatal(err)
	}
	t.Log("NTFS verified")
	if err := requireWindowsVolumeRoot(root); err != nil {
		t.Fatal(err)
	}
	t.Log("volume root verified")
	guid, err := windowsVolumeGUIDPath(root)
	if err != nil || !windowsVolumeGUIDRoot(guid) {
		t.Fatalf("volume GUID unavailable: %v", err)
	}
	t.Log("volume GUID verified")
	if _, err := windowsHandleInfo(root); err != nil {
		t.Fatal(err)
	}
	t.Log("handle identity verified")
	if err := validateProtectedWindowsHandle(root, windowsAncestorDangerous); err != nil {
		t.Fatal(err)
	}
	t.Log("anchor security verified")
}

func TestWindowsNativePutTrustsOnlyCanonicalInstallerServiceSID(t *testing.T) {
	trusted, err := trustedWindowsSIDs()
	if err != nil {
		t.Fatal(err)
	}
	installer, err := windows.StringToSid(windowsTrustedInstaller)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	if !trustedWindowsSID(copyWindowsSID(installer), trusted) {
		t.Fatal("TrustedInstaller SID is not trusted")
	}
	if trustedWindowsSID(copyWindowsSID(unrelated), trusted) {
		t.Fatal("unrelated service SID is trusted")
	}
}

func TestWindowsNativeReplacementOwnerAssignment(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("token user unavailable: %v", err)
	}
	if !windowsTokenCanAssignOwner(token, user.User.Sid, user.User.Sid) {
		t.Fatal("token user is not assignable as owner")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Attributes&windows.SE_GROUP_OWNER != 0 {
			if !windowsTokenCanAssignOwner(token, group.Sid, user.User.Sid) {
				t.Fatal("owner-enabled token group is not assignable as owner")
			}
			break
		}
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if !system.Equals(user.User.Sid) && windowsTokenCanAssignOwner(token, system, user.User.Sid) {
		t.Fatal("SID absent from the token is assignable as owner")
	}
}

func TestWindowsNativeNTFSCollisionAndRecovery(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "collision"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, "collision")
	defer parent.Close()
	if err := validateCreateDestination(parent, "collision"); err == nil {
		t.Fatal("existing destination accepted")
	}
}

func TestWindowsNativeRejectsShortNameReplacement(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "long-replacement-destination.txt")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, filepath.Base(destination))
	defer parent.Close()
	if _, err := inspectReplacementDestination(parent, filepath.Base(destination)); err == nil {
		t.Skip("campaign volume did not assign an automatic short name")
	} else if !strings.Contains(err.Error(), "short name") {
		t.Fatalf("replacement rejection = %v", err)
	}
}

func TestWindowsNativeRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Skipf("creating a Windows symlink requires unavailable privilege: %v", err)
	}
	if parent, err := openDestinationParent(root, "link/result", false); err == nil {
		parent.Close()
		t.Fatal("reparse parent accepted")
	}
}

func TestWindowsNativeRejectsUntrustedParentCreateAuthority(t *testing.T) {
	root := t.TempDir()
	unsafePath := filepath.Join(root, "unsafe")
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	path, err := windows.UTF16PtrFromString(unsafePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(path, security); err != nil {
		t.Fatal(err)
	}
	if parent, err := openDestinationParent(unsafePath, "result", false); err == nil {
		parent.Close()
		t.Fatal("untrusted parent DACL accepted")
	}
}

func TestWindowsNativeRejectsUntrustedIntermediateCreateAuthority(t *testing.T) {
	root := t.TempDir()
	unsafePath := filepath.Join(root, "unsafe")
	createWindowsNativeTestDirectory(t, unsafePath, "D:P(A;OICI;GA;;;WD)")
	trusted := filepath.Join(unsafePath, "trusted")
	userSID := currentWindowsTestSID(t)
	createWindowsNativeTestDirectory(t, trusted, "O:"+userSID+"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;"+userSID+")")
	if parent, err := openDestinationParent(root, "unsafe/trusted/result", false); err == nil {
		parent.Close()
		t.Fatal("untrusted intermediate DACL accepted")
	}
}

func TestWindowsNativeRevalidateRejectsParentSwap(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, "nested/result")
	defer parent.Close()
	if err := os.Rename(nested, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := parent.Revalidate(); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("revalidate after swap=%v", err)
	}
}

func TestWindowsNativeRevalidateRejectsUnsafeIntermediateDACL(t *testing.T) {
	root := t.TempDir()
	intermediate := filepath.Join(root, "intermediate")
	parentPath := filepath.Join(intermediate, "parent")
	if err := os.MkdirAll(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := openWindowsNativeTestParent(t, root, "intermediate/parent/result")
	defer parent.Close()
	setWindowsNativeTestDACL(t, intermediate, "D:P(A;OICI;GA;;;WD)")
	if err := parent.Revalidate(); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("revalidate after unsafe intermediate DACL=%v", err)
	}
}

func TestWindowsNativeNonWritableParentFailsBeforeReservation(t *testing.T) {
	root := t.TempDir()
	probe := openWindowsNativeTestParent(t, root, "probe")
	probe.Close()
	userSID := currentWindowsTestSID(t)
	locked := filepath.Join(root, "locked")
	createWindowsNativeTestDirectory(t, locked, "O:"+userSID+"D:P(D;;0x00000002;;;"+userSID+")(A;;0x001200a9;;;"+userSID+")")

	left, right := make(chan Message, 2), make(chan Message, 2)
	sender := windowsTestChannel{send: left, receive: right}
	receiver := windowsTestChannel{send: right, receive: left}
	manifest := Manifest{Version: protocolVersion, ID: "0123456789abcdef0123456789abcdef", Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: "result", Mode: "create", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ChunkSize: ChunkSize, AckWindow: AckWindow}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	databaseCalls := 0
	_, err := Receive(t.Context(), receiver, ReceiveConfig{Root: locked, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: NewStore(func() *sql.DB { databaseCalls++; return nil })})
	if err == nil || databaseCalls != 0 {
		t.Fatalf("receive error=%v database calls=%d", err, databaseCalls)
	}
	response, receiveErr := receiveControl(t.Context(), sender)
	if receiveErr != nil || response.Type != "error" || strings.Contains(response.Error, locked) {
		t.Fatalf("response=%+v err=%v", response, receiveErr)
	}
	names, readErr := os.ReadDir(locked)
	if readErr != nil || len(names) != 0 {
		t.Fatalf("non-writable parent entries=%v err=%v", names, readErr)
	}
}

func TestWindowsNativeCleanupRetainsStageOnSharingDenial(t *testing.T) {
	root := t.TempDir()
	parent := openWindowsNativeTestParent(t, root, "result")
	record := windowsNativeTestRecord(parent, "result")
	stage, _, err := createOrOpenStage(parent, record.Manifest, record)
	if err != nil {
		t.Fatal(err)
	}
	record.StageIdentity = stage.Identity
	if err := stage.File.Close(); err != nil {
		t.Fatal(err)
	}
	stage.File = nil
	defer stage.Close()
	path, err := windows.UTF16PtrFromString(filepath.Join(root, stage.Name))
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(blocker)
	if cleanup, err := openCleanupStage(record); err == nil {
		cleanup.Close()
		t.Fatal("sharing denial allowed cleanup stage to open")
	}
	if _, err := os.Stat(filepath.Join(root, stage.Name)); err != nil {
		t.Fatalf("stage evidence was not retained: %v", err)
	}
}

func openWindowsNativeTestParent(t *testing.T, root, destination string) *openedParent {
	t.Helper()
	parent, err := openDestinationParent(root, destination, false)
	if errors.Is(err, ErrNativeUnsupported) {
		t.Skipf("native test requires supported NTFS and APIs: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return parent
}

func windowsNativeTestRecord(parent *openedParent, destination string) Record {
	manifest := Manifest{Version: protocolVersion, ID: "0123456789abcdef0123456789abcdef", Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: destination, Mode: "create", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ChunkSize: ChunkSize, AckWindow: AckWindow, RootRevision: 1}
	return Record{Manifest: manifest, Direction: "receive", PeerLabel: "sender", ParentPath: parent.path, ParentIdentity: parentDurableIdentity(parent), StageName: ".px-0123456789abcdef0123456789abcdef.put", State: "stage_intent"}
}

func removeWindowsNativeTestShortName(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := clearWindowsShortName(handle); err != nil {
		t.Fatalf("remove automatic short name: %v", err)
	}
}

func createWindowsNativeTestDirectory(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	value, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(value, security); err != nil {
		t.Fatal(err)
	}
}

func currentWindowsTestSID(t *testing.T) string {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

func setWindowsNativeTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("test DACL unavailable: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsNativeDatabase(t *testing.T, root string) *sql.DB {
	t.Helper()
	cfg, err := database.Config(database.KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	component := sqlite.New(cfg)
	if err := component.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = component.Stop(context.Background()) })
	db := component.DB()
	_, err = db.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,put_root,allow_put,put_root_revision,created_at,updated_at) values('home','https://px.example','server','receiver','private','public','receiver','connected',1,?,?,?,1,7,1,1)`, root, root, root)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

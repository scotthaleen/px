//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCreateOwnerOnlyDirUsesProtectedCurrentUserACL(t *testing.T) {
	parent := t.TempDir()
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := CreateOwnerOnlyDir(root, parent, "stage")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := validateCurrentUserACL(directory, "staging directory"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProtectedParentWindowsACL(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		sddl string
		ok   bool
	}{
		{name: "current user", sddl: "D:(A;OICI;GA;;;" + sid.String() + ")", ok: true},
		{name: "inherited current user", sddl: "D:AI(A;OICIID;GA;;;" + sid.String() + ")", ok: true},
		{name: "TrustedInstaller", sddl: "D:(A;;GA;;;" + trustedInstallerSID + ")(A;OICI;GA;;;" + sid.String() + ")", ok: true},
		{name: "unrelated service", sddl: "D:(A;;GA;;;S-1-5-80-1-2-3-4-5)(A;OICI;GA;;;" + sid.String() + ")"},
		{name: "everyone delete child", sddl: "D:(A;;DC;;;WD)(A;OICI;GA;;;" + sid.String() + ")"},
		{name: "everyone write", sddl: "D:(A;;GW;;;WD)(A;OICI;GA;;;" + sid.String() + ")"},
		{name: "denied then allowed everyone fails closed", sddl: "D:(D;;DC;;;WD)(A;;DC;;;WD)(A;OICI;GA;;;" + sid.String() + ")"},
		{name: "inherit-only everyone", sddl: "D:(A;CIIO;DC;;;WD)(A;OICI;GA;;;" + sid.String() + ")", ok: true},
		{name: "object allow everyone", sddl: "D:(OA;;DC;;;WD)(A;OICI;GA;;;" + sid.String() + ")"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "parent")
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.CreateDirectory(name, security); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			err = ValidateProtectedParent(file)
			if (err == nil) != test.ok {
				t.Fatalf("validation = %v", err)
			}
		})
	}
}

func TestTrustedWindowsProtectionSIDs(t *testing.T) {
	current, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := trustedWindowsProtectionSIDs(current)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedService, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	arbitraryUser, err := windows.StringToSid("S-1-5-21-1000-1000-1000-1000")
	if err != nil {
		t.Fatal(err)
	}
	if !trustedWindowsSID(installer, trusted) {
		t.Fatal("TrustedInstaller SID is not trusted")
	}
	if trustedWindowsSID(unrelatedService, trusted) {
		t.Fatal("unrelated service SID is trusted")
	}
	if trustedWindowsSID(arbitraryUser, trusted) {
		t.Fatal("arbitrary user SID is trusted")
	}
	if trustedWindowsSID(nil, trusted) {
		t.Fatal("nil owner SID is trusted")
	}
}

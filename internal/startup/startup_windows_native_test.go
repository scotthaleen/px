//go:build windows

package startup

import (
	"os"
	"os/user"
	"testing"
)

func TestInspectNativeWindowsTask(t *testing.T) {
	if os.Getenv("PX_NATIVE_STARTUP_INSPECT") != "1" {
		t.Skip("set PX_NATIVE_STARTUP_INSPECT=1 for authorized native inspection")
	}
	executable := os.Getenv("PX_NATIVE_STARTUP_EXECUTABLE")
	pxHome := os.Getenv("PX_HOME")
	if executable == "" || pxHome == "" {
		t.Fatal("PX_NATIVE_STARTUP_EXECUTABLE and PX_HOME are required")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal("resolve current user failed")
	}
	localData, err := os.UserCacheDir()
	if err != nil {
		t.Fatal("resolve local application data failed")
	}
	plan, err := buildPlan("windows", current.HomeDir, executable, pxHome, localData, 0)
	if err != nil {
		t.Fatal(err)
	}
	plan.UserIDs = compactStrings(current.Uid, current.Username)
	output, err := ExecRunner{}.Run(t.Context(), Command{Name: "schtasks.exe", Args: []string{"/Query", "/TN", TaskName, "/XML"}})
	if err != nil {
		t.Fatal("query native startup task failed")
	}
	if err := validateWindowsTask(output, plan); err != nil {
		t.Fatalf("validate native startup task: %v", err)
	}
}

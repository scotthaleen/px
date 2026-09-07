package testscript_test

import (
	"bytes"
	"go/build"
	"os"
	"testing"
)

func TestProcessSuiteBuildTag(t *testing.T) {
	ordinary := build.Default
	ordinary.BuildTags = nil
	matched, err := ordinary.MatchFile(".", "script_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("script_test.go must be excluded without the process build tag")
	}

	process := build.Default
	process.BuildTags = []string{"process"}
	matched, err = process.MatchFile(".", "script_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("script_test.go must be included with the process build tag")
	}

	matched, err = ordinary.MatchFile(".", "smoke_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("smoke_test.go must be excluded without build tags")
	}
	matched, err = process.MatchFile(".", "smoke_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("smoke_test.go must be excluded from the full process suite")
	}
	processSmoke := build.Default
	processSmoke.BuildTags = []string{"process", "smoke"}
	matched, err = processSmoke.MatchFile(".", "smoke_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("smoke_test.go must be included with process and smoke build tags")
	}
}

func TestVerificationTasksKeepProcessBoundary(t *testing.T) {
	taskfile, err := os.ReadFile("../Taskfile.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]byte{
		[]byte("      - go test -count=1 ./...\n"),
		[]byte("      - go test -count=1 -race ./...\n"),
		[]byte("      - go test -count=1 -tags=process ./testscript\n"),
		[]byte("      - go test -count=1 -tags='process smoke' ./testscript -run"),
		[]byte("      - go test -count=1 -race -tags=process ./testscript -run"),
		[]byte("      - go vet -tags='process smoke' ./...\n"),
	} {
		if !bytes.Contains(taskfile, command) {
			t.Fatalf("Taskfile is missing required test boundary %q", command)
		}
	}
	if !bytes.Contains(taskfile, []byte("      - task: test:process\n      - task: test:smoke\n      - task: test:process:race\n")) {
		t.Fatal("process check must run full process, smoke, and focused process race tiers sequentially")
	}
	if !bytes.Contains(taskfile, []byte("deps: [fmt:check, lint, test, test:process:check, test:race, vuln, cross-build]")) {
		t.Fatal("authoritative check must delegate subprocess coverage only to the sequential process check")
	}
	if bytes.Contains(taskfile, []byte("test:process:check, test:smoke")) {
		t.Fatal("authoritative check must not run smoke beside the sequential process check")
	}
	if bytes.Count(taskfile, []byte("go test -count=1 -tags='process smoke'")) != 1 {
		t.Fatal("smoke-tagged process coverage must have one authoritative command")
	}
	if !bytes.Contains(taskfile, []byte("deps: [fmt:check, lint, test, test:smoke]")) {
		t.Fatal("fast gate must include the process smoke tier")
	}
}

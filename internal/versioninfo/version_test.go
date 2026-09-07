package versioninfo

import (
	"strings"
	"testing"
)

func TestSanitizeBuildMetadata(t *testing.T) {
	for input, want := range map[string]string{
		"":            "unknown",
		"dev":         "dev",
		"bad/path":    "invalid",
		`bad\path`:    "invalid",
		"bad\nvalue":  "invalid",
		"non-ascii-é": "invalid",
	} {
		if got := SanitizeBuildMetadata(input); got != want {
			t.Fatalf("SanitizeBuildMetadata(%q) = %q, want %q", input, got, want)
		}
	}
	long := strings.Repeat("a", MaxBuildMetadataBytes+10)
	if got := SanitizeBuildMetadata(long); len(got) != MaxBuildMetadataBytes {
		t.Fatalf("sanitized length = %d", len(got))
	}
}

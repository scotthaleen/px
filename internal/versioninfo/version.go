package versioninfo

import "fmt"

const MaxBuildMetadataBytes = 96

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String(name string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", name, Version, Commit, Date)
}

func SanitizeBuildMetadata(value string) string {
	if value == "" {
		return "unknown"
	}
	for index := range len(value) {
		character := value[index]
		if character < 0x20 || character > 0x7e || character == '/' || character == '\\' {
			return "invalid"
		}
	}
	if len(value) > MaxBuildMetadataBytes {
		return value[:MaxBuildMetadataBytes]
	}
	return value
}

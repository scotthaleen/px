package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/scotthaleen/px/internal/release"
)

func main() {
	var options release.Options
	var buildDate string
	flag.StringVar(&options.InputDir, "input", "dist/cross", "directory containing cross-built binaries")
	flag.StringVar(&options.OutputDir, "output", "dist/release", "release archive directory")
	flag.StringVar(&options.License, "license", "LICENSE", "project license path")
	flag.StringVar(&options.Notices, "notices", "THIRD_PARTY_NOTICES.md", "third-party notices path")
	flag.StringVar(&options.Version, "version", "", "release version")
	flag.StringVar(&options.Commit, "commit", "unknown", "source commit")
	flag.StringVar(&buildDate, "built", "", "RFC 3339 build time")
	flag.Parse()
	var err error
	options.BuildDate, err = time.Parse(time.RFC3339, buildDate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "px-package: invalid --built timestamp:", err)
		os.Exit(2)
	}
	paths, err := release.Package(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "px-package:", err)
		os.Exit(1)
	}
	for _, path := range paths {
		fmt.Println(path)
	}
}

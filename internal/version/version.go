package version

import "fmt"

// Build-time variables injected via ldflags.
var (
	Release   = "dev"
	GitCommit = "unknown"
	GOOS      = "unknown"
	GOARCH    = "unknown"
)

// Full returns the version string in the format "release (commit)".
func Full() string {
	return fmt.Sprintf("%s (commit: %s)", Release, GitCommit)
}

// FullWithPlatform returns the version string with platform information.
func FullWithPlatform() string {
	return fmt.Sprintf("%s (commit: %s, %s/%s)", Release, GitCommit, GOOS, GOARCH)
}

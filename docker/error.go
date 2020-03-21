package docker

import (
	"strings"
)

// IsErrNotRunning checks an error if the container is not running.
func IsErrNotRunning(err error) bool {
	return strings.HasSuffix(err.Error(), " is not running")
}

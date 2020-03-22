package testutil

import (
	"os"
)

func IsCI() bool {
	_, ok := os.LookupEnv("CI")
	return ok
}

func IsTravis() bool {
	_, ok := os.LookupEnv("TRAVIS")
	return ok
}

func IsAppVeyor() bool {
	_, ok := os.LookupEnv("APPVEYOR")
	return ok
}

// TestMultiplier returns a multiplier for retries and waits given environment
// the tests are being run under.
func TestMultiplier() int64 {
	if IsCI() {
		return 4
	}

	return 1
}

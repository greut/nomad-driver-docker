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

package testutil

import (
	"context"
	"runtime"
	"testing"

	docker "github.com/docker/docker/client"
)

// DockerIsConnected checks to see if a docker daemon is available (local or remote)
func DockerIsConnected(t *testing.T) bool {
	// We have docker on travis so we should try to test
	if IsTravis() {
		// Travis supports Docker on Linux only; MacOS setup does not support Docker
		return runtime.GOOS == "linux"
	}

	if IsAppVeyor() {
		return runtime.GOOS == "windows"
	}

	client, err := docker.NewClientWithOpts(
		docker.FromEnv,
		docker.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Logf("failed to create the docker client: %s", err)
		return false
	}

	// Creating a client doesn't actually connect, so make sure we do something
	// like call Version() on it.
	version, err := client.ServerVersion(context.TODO())
	if err != nil {
		t.Logf("Failed to connect to docker daemon: %s", err)
		return false
	}

	t.Logf("Successfully connected to docker daemon running version %s", version.Version)
	return true
}

// DockerCompatible skips tests if docker is not present
func DockerCompatible(t *testing.T) {
	if !DockerIsConnected(t) {
		t.Skip("Docker not connected")
	}
}

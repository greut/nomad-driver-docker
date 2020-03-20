package docker

import (
	"testing"

	tu "github.com/greut/nomad-driver-docker/testutil"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/stretchr/testify/require"
)

// TestDockerDriver_FingerprintHealth asserts that docker reports healthy
// whenever Docker is supported.
//
// In Linux CI and AppVeyor Windows environment, it should be enabled.
func TestDockerDriver_FingerprintHealth(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}

	tu.DockerCompatible(t)

	d := NewDriver(testlog.HCLogger(t))

	fp := d.buildFingerprint()
	require.Equal(t, drivers.HealthStateHealthy, fp.Health)
}

package docker

import (
	"time"
)

type DriverConfig struct {
	Endpoint                    string        `codec:"endpoint"`
	GC                          GCConfig      `codec:"gc"`
	PullActivityTimeout         string        `codec:""pull_activity_timeout`
	pullActivityTimeoutDuration time.Duration `codec:"-"`
}

const danglingContainersCreationGraceMinimum = 1 * time.Minute
const pullActivityTimeoutMinimum = 1 * time.Minute

type GCConfig struct {
	Image              bool              `codec:"image"`
	ImageDelay         string            `codec:"image_delay"`
	imageDelayDuration time.Duration     `codec:"-"`
	Container          bool              `codec:"container"`
	DanglingContainers ContainerGCConfig `codec:"dangling_containers"`
}

// ContainerGCConfig controls the behavior of the GC reconcilier to detects
// dangling nomad containers that aren't tracked due to docker/nomad bugs.
type ContainerGCConfig struct {
	// Enabled controls whether the container reconciler is enabled
	Enabled bool `codec:"enabled"`

	// DryRun indicates that the reconciler should log unexpectedly running containers
	// if found without actually killing them
	DryRun bool `codec:"dry_run"`

	// Period controls the frequency of scanning containers
	Period         string        `codec:"period"`
	periodDuration time.Duration `codec:"-"`

	// CreationGrace is the duration allowed for newly created container
	// to live without being registered as a running task in nomad.
	// A container is treated as leaked if it lived more than a grace duration
	// and haven't been registered in tasks.
	CreationGrace         string        `codec:"creation_grace"`
	creationGraceDuration time.Duration `codec:"-"`
}

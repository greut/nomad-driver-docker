package docker

import (
	"context"
	"sync"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
)

// reconclier detects and kills unexpectedly running containers.
//
// Due to Docker architecture and network based communication, it is
// possible for Docker to start a container successfully, but have the
// creation API call fail with a network error.
//
// reconciler scans for these untracked containers and kill them.
type reconciler struct {
	ctx    context.Context
	config *ContainerGCConfig
	client *docker.Client
	logger hclog.Logger

	isDriverHealthy   func() bool
	trackedContainers func() map[string]bool
	isNomadContainer  func(c types.Container) bool

	once sync.Once
}

func newReconciler(d *Driver) *reconciler {
	return &reconciler{
		ctx:    d.ctx,
		config: &d.config.GC.DanglingContainers,
		client: d.client,

		isDriverHealthy: func() bool {
			return false // d.previouslyDetected() && d.fingerprintSuccessful()
		},
		trackedContainers: d.trackedContainers,
		isNomadContainer:  isNomadContainer,
	}
}

func (r *reconciler) Start() {
	if !r.config.Enabled {
		r.logger.Debug("skipping dangling containers handling; is disable")
		return
	}

	/* TODO
	r.once.Do(func() {
		go r.removeDanglingContainersGoroutine()
	})
	*/
}

func isNomadContainer(c types.Container) bool {
	_, ok := c.Labels[dockerLabelAllocID]
	return ok
}

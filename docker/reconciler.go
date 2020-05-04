package docker

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

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
		client: d.client,
		config: &d.config.GC.DanglingContainers,
		logger: d.logger.Named("reconciler"),

		isDriverHealthy: func() bool {
			return d.previouslyDetected() && d.fingerprintSuccessful()
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

	r.once.Do(func() {
		go r.removeDanglingContainersGoroutine()
	})
}

func (r *reconciler) removeDanglingContainersGoroutine() {
	/*
		period := r.config.periodDuration

		lastIterSucceeded := true

		// ensure that we wait for at least a period or creation timeout
		// for first container GC iteration
		// The initial period is a grace period for restore allocation
		// before a driver may kill containers launched by an earlier nomad
		// process.
		initialDelay := period
		if r.config.CreationGrace > initialDelay {
			initialDelay = r.config.CreationGrace
		}

		timer := time.NewTimer(initialDelay)
		for {
			select {
			case <-timer.C:
				if r.isDriverHealthy() {
					err := r.removeDanglingContainersIteration()
					if err != nil && lastIterSucceeded {
						r.logger.Warn("failed to remove dangling containers", "error", err)
					}
					lastIterSucceeded = (err == nil)
				}

				timer.Reset(period)
			case <-r.ctx.Done():
				return
			}
		}
	*/
}

func (r *reconciler) removeDanglingContainersIteration() error {
	cutoff := time.Now().Add(-r.config.creationGraceDuration)
	tracked := r.trackedContainers()
	untracked, err := r.untrackedContainers(tracked, cutoff)
	if err != nil {
		return fmt.Errorf("failed to find untracked containers: %v", err)
	}

	if len(untracked) == 0 {
		return nil
	}

	if r.config.DryRun {
		r.logger.Info("detected untracked containers", "container_ids", untracked)
		return nil
	}

	for _, id := range untracked {
		ctx, cancel := r.dockerAPIQueryContext()
		err := r.client.ContainerRemove(
			ctx,
			id,
			types.ContainerRemoveOptions{
				Force: true,
			},
		)
		cancel()
		if err != nil {
			r.logger.Warn("failed to remove untracked container", "container_id", id, "error", err)
		} else {
			r.logger.Info("removed untracked container", "container_id", id)
		}
	}

	return nil
}

// untrackedContainers returns the ids of containers that suspected
// to have been started by Nomad but aren't tracked by this driver
func (r *reconciler) untrackedContainers(tracked map[string]bool, cutoffTime time.Time) ([]string, error) {
	result := []string{}

	ctx, cancel := r.dockerAPIQueryContext()
	defer cancel()

	cc, err := r.client.ContainerList(ctx, types.ContainerListOptions{
		All: false, // only reconcile running containers
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %v", err)
	}

	cutoff := cutoffTime.Unix()

	for _, c := range cc {
		if tracked[c.ID] {
			continue
		}

		if c.Created > cutoff {
			continue
		}

		if !isNomadContainer(c) {
			continue
		}

		result = append(result, c.ID)
	}

	return result, nil
}

// dockerAPIQueryTimeout returns a context for docker API response with an appropriate timeout
// to protect against wedged locked-up API call.
//
// We'll try hitting Docker API on subsequent iteration.
func (r *reconciler) dockerAPIQueryContext() (context.Context, context.CancelFunc) {
	// use a reasoanble floor to avoid very small limit
	timeout := 30 * time.Second

	if timeout < r.config.periodDuration {
		timeout = r.config.periodDuration
	}

	return context.WithTimeout(context.Background(), timeout)
}
func isNomadContainer(c types.Container) bool {
	_, ok := c.Labels[dockerLabelAllocID]
	return ok
}

func hasMount(c types.Container, p string) bool {
	for _, m := range c.Mounts {
		if m.Destination == p {
			return true
		}
	}

	return false
}

var nomadContainerNamePattern = regexp.MustCompile(`\/.*-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func hasNomadName(c types.Container) bool {
	for _, n := range c.Names {
		if nomadContainerNamePattern.MatchString(n) {
			return true
		}
	}

	return false
}

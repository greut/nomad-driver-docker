package docker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	cstructs "github.com/hashicorp/nomad/client/structs"
	nstructs "github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
)

type taskHandle struct {
	ctx         context.Context
	containerID string
	client      *docker.Client
	waitClient  *docker.Client
	logger      hclog.Logger
	task        *drivers.TaskConfig
	doneChan    chan bool
	waitChan    chan struct{}
	net         *drivers.DriverNetwork

	exitResult     *drivers.ExitResult
	exitResultLock sync.Mutex
}

type taskHandleState struct {
	// ReattachConfig for the docker logger plugin
	ReattachConfig *pstructs.ReattachConfig

	ContainerID   string
	DriverNetwork *drivers.DriverNetwork
}

func (h *taskHandle) ExitResult() *drivers.ExitResult {
	h.exitResultLock.Lock()
	defer h.exitResultLock.Unlock()
	return h.exitResult.Copy()
}

// Stats starts collecting stats from the docker daemon and sends them on the
// returned channel.
func (h *taskHandle) Stats(ctx context.Context, interval time.Duration) (<-chan *cstructs.TaskResourceUsage, error) {
	select {
	case <-h.doneChan:
		return nil, nstructs.NewRecoverableError(fmt.Errorf("container stopped"), false)
	default:
	}

	destChan, recvChan := newStatsChanPipe()
	go h.collectStats(ctx, destChan, interval)

	return recvChan, nil
}

// collectStats starts collecting resource usage stats of a docker container
func (h *taskHandle) collectStats(ctx context.Context, sender *usageSender, interval time.Duration) {
	defer sender.close()

	// backoff and retry used if the docker stats API returns an error
	var backoff time.Duration
	//var retry int
	// loops until doneCh is closed
	for {
		if backoff > 0 {
			select {
			case <-time.After(backoff):
				// TODO
				sender.destChan <- resourceUsage(nil)
			case <-ctx.Done():
				return
			case <-h.doneChan:
				return
			}
		}
		/*
			// make a channel for docker stats structs and start a collector to
			// receive stats from docker and emit nomad stats
			// statsCh will always be closed by docker client.
			statsCh := make(chan *docker.Stats)
			go dockerStatsCollector(destChan, statsChan, interval)

			statsOpts := docker.StatsOptions{
				ID:      h.containerID,
				Context: ctx,
				Done:    h.doneCh,
				Stats:   statsCh,
				Stream:  true,
			}

			// Stats blocks until an error has occurred, or doneCh has been closed
			if err := h.client.Stats(statsOpts); err != nil && err != io.ErrClosedPipe {
				// An error occurred during stats collection, retry with backoff
				h.logger.Debug("error collecting stats from container", "error", err)

				// Calculate the new backoff
				backoff = (1 << (2 * uint64(retry))) * statsCollectorBackoffBaseline
				if backoff > statsCollectorBackoffLimit {
					backoff = statsCollectorBackoffLimit
				}
				// Increment retry counter
				retry++
				continue
			}
			// Stats finished either because context was canceled, doneCh was closed
			// or the container stopped. Stop stats collections.
			return
		*/
	}
}

func (h *taskHandle) buildState() *taskHandleState {
	s := &taskHandleState{
		ContainerID:   h.containerID,
		DriverNetwork: h.net,
	}

	return s
}

func (h *taskHandle) run() {
	var exitCode int
	var err error

	exitChan, errChan := h.waitClient.ContainerWait(h.ctx, h.containerID, container.WaitConditionNextExit)

	for {
		select {
		case <-h.ctx.Done():
			err = h.ctx.Err()

			break

		case body, ok := <-exitChan:
			if !ok {
				continue
			}

			exitCode = int(body.StatusCode)

			if exitCode != 0 {
				h.logger.Error("docker container exited with error %d: %s", body.StatusCode, body.Error.Message)
				err = fmt.Errorf("docker container exited with non-zero exit code: %d", body.StatusCode)
			}

			break

		case e, ok := <-errChan:
			if !ok {
				continue
			}

			h.logger.Error("failed to wait for container; already terminated", "error", e)

			err = e

			break
		}
	}

	container, ierr := h.waitClient.ContainerInspect(h.ctx, h.containerID)
	oom := false
	if ierr != nil {
		h.logger.Error("failed to inspect container", "error", ierr)
	} else if container.State.OOMKilled {
		oom = true
		err = fmt.Errorf("OOM Killed")
	}

	// Shutdown stats collection
	close(h.doneChan)

	// Stop the container just incase the docker daemon's wait returned
	// incorrectly
	timeout := time.Second
	if e := h.client.ContainerStop(h.ctx, h.containerID, &timeout); e != nil {
		h.logger.Error("error stopping container", "error", e)
	}

	// Set the result
	h.exitResultLock.Lock()
	h.exitResult = &drivers.ExitResult{
		ExitCode:  exitCode,
		Signal:    0,
		OOMKilled: oom,
		Err:       err,
	}
	h.exitResultLock.Unlock()

	close(h.waitChan)
}

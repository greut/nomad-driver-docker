package docker

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"
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
	ctx                   context.Context
	containerID           string
	containerImage        string
	client                *docker.Client
	waitClient            *docker.Client
	logger                hclog.Logger
	task                  *drivers.TaskConfig
	doneChan              chan bool
	waitChan              chan struct{}
	net                   *drivers.DriverNetwork
	removeContainerOnExit bool

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

func (h *taskHandle) Signal(s os.Signal) error {
	// Convert types
	sysSig, ok := s.(syscall.Signal)
	if !ok {
		return fmt.Errorf("Failed to determine signal number")
	}

	return h.client.ContainerKill(h.ctx, h.containerID, strconv.Itoa(int(sysSig)))
}

// Kill is used to terminate the task.
func (h *taskHandle) Kill(killTimeout time.Duration, signal os.Signal) error {
	// Only send signal if killTimeout is set, otherwise stop container
	if killTimeout > 0 {
		if err := h.Signal(signal); err != nil {
			// Container has already been removed.
			if docker.IsErrNotFound(err) {
				h.logger.Debug("attempted to signal nonexistent container")
				return nil
			}

			// Container has already been stopped.
			if IsErrNotRunning(err) {
				h.logger.Debug("attempted to signal a not-running container")
				return nil
			}

			h.logger.Error("failed to signal container while killing", "error", err)
			return fmt.Errorf("Failed to signal container %q while killing: %v", h.containerID, err)
		}

		select {
		case <-h.waitChan:
			return nil
		case <-time.After(killTimeout):
		}
	}

	// Stop the container
	notimeout := 0 * time.Second
	err := h.client.ContainerStop(h.ctx, h.containerID, &notimeout)
	if err != nil {

		// Container has already been removed.
		if docker.IsErrNotFound(err) {
			h.logger.Debug("attempted to stop nonexistent container")
			return nil
		}

		// Container has already been stopped.
		if IsErrNotRunning(err) {
			h.logger.Debug("attempted to stop an not-running container")
			return nil
		}

		h.logger.Error("failed to stop container", "error", err)
		return fmt.Errorf("Failed to stop container %s: %s", h.containerID, err)
	}

	h.logger.Info("stopped container")
	return nil
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

	exitChan, errChan := h.waitClient.ContainerWait(h.ctx, h.containerID, container.WaitConditionNotRunning)

outer:
	for {
		select {
		case <-h.ctx.Done():
			err = h.ctx.Err()

			break outer

		case body, ok := <-exitChan:
			if !ok {
				continue
			}

			exitCode = int(body.StatusCode)

			if exitCode != 0 {
				h.logger.Error("docker container exited with error", "code", exitCode, "error", body.Error)
				err = fmt.Errorf("docker container exited with non-zero exit code: %d", exitCode)
			}

			break outer

		case e, ok := <-errChan:
			if !ok {
				continue
			}

			h.logger.Error("failed to wait for container; already terminated", "error", e)

			err = e

			break outer
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

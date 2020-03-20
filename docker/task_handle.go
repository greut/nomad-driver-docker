package docker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
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

package docker

import (
	//"context"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	//docker "github.com/docker/docker/client"
	cstructs "github.com/hashicorp/nomad/client/structs"
)

const (
	// statsCollectorBackoffBaseline is the baseline time for exponential
	// backoff while calling the docker stats api.
	statsCollectorBackoffBaseline = 5 * time.Second

	// statsCollectorBackoffLimit is the limit of the exponential backoff for
	// calling the docker stats api.
	statsCollectorBackoffLimit = 2 * time.Minute
)

// usageSender wraps a TaskResourceUsage chan such that it supports concurrent
// sending and closing, and backpressures by dropping events if necessary.
type usageSender struct {
	closed   bool
	destChan chan<- *cstructs.TaskResourceUsage
	mu       sync.Mutex
}

// newStatsChanPipe returns a chan wrapped in a struct that supports concurrent
// sending and closing, and the receiver end of the chan.
func newStatsChanPipe() (*usageSender, <-chan *cstructs.TaskResourceUsage) {
	destChan := make(chan *cstructs.TaskResourceUsage, 1)
	return &usageSender{
		destChan: destChan,
	}, destChan

}

// send resource usage to the receiver unless the chan is already full or
// closed.
func (u *usageSender) send(tru *cstructs.TaskResourceUsage) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return
	}

	select {
	case u.destChan <- tru:
	default:
		// Backpressure caused missed interval
	}
}

// close resource usage. Any further sends will be dropped.
func (u *usageSender) close() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		// already closed
		return
	}

	u.closed = true
	close(u.destChan)
}

func dockerStatsCollector(destChan *usageSender, statsChan <-chan *types.ContainerStats, interval time.Duration) {
	var resourceUsage *cstructs.TaskResourceUsage

	// hasSentInitialStats is used so as to emit the first stats received from
	// the docker daemon
	var hasSentInitialStats bool

	// timer is used to send nomad status at the specified interval
	timer := time.NewTimer(interval)
	for {
		select {
		case <-timer.C:
			// it is possible for the timer to go off before the first stats
			// has been emitted from docker
			if resourceUsage == nil {
				continue
			}

			// sending to destCh could block, drop this interval if it does
			destChan.send(resourceUsage)

			timer.Reset(interval)

		case s, ok := <-statsChan:
			// if statsCh is closed stop collection
			if !ok {
				return
			}
			// s should always be set, but check and skip just in case
			if s != nil {
				resourceUsage = nil //dockerStatsToTaskResourceUsage(s)
				// send stats next interation if this is the first time received
				// from docker
				if !hasSentInitialStats {
					timer.Reset(0)
					hasSentInitialStats = true
				}
			}
		}
	}
}

func resourceUsage(s *types.ContainerStats) *cstructs.TaskResourceUsage {
	return &cstructs.TaskResourceUsage{
		ResourceUsage: &cstructs.ResourceUsage{
			MemoryStats: &cstructs.MemoryStats{},
			CpuStats:    &cstructs.CpuStats{},
		},
		Timestamp: time.Now().UTC().UnixNano(),
	}
}

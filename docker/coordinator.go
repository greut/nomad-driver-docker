package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/nomad/structs"
)

// LogEventFn is a callback which allows Drivers to emit task events.
type LogEventFn func(message string, annotations map[string]string)

// coordinatorConfig is used to configure the Docker coordinator.
type coordinatorConfig struct {
	// logger is the logger used by the coordinator
	logger hclog.Logger

	// cleanup marks whether images should be deleted when the reference count
	// is zero
	cleanup bool

	// client is the Docker client
	client *docker.Client

	// removeDelay is the delay between an image's reference count going to
	// zero and the image actually being deleted.
	removeDelay time.Duration
}

// coordinator is used to coordinate actions against images to prevent
// racy deletions. It can be thought of as a reference counter on images.
type coordinator struct {
	*coordinatorConfig

	// imageLock is used to lock access to all images
	imageLock sync.Mutex

	// pullFutures is used to allow multiple callers to pull the same image but
	// only have one request be sent to the registry
	pullFutures map[string]*pullFuture

	// pullLoggers is used to track the LogEventFn for each allo pulling an image.
	// If multiple alloc's are attempting to pull the same image, each will need to
	// register its own LogEventFn with the coordinator.
	pullLoggers map[string][]LogEventFn

	// pullLoggerLock is used to sync access to the pullLoggers map
	pullLoggerLock sync.RWMutex

	// imageRefCount is the reference counter of image IDs
	imageRefCount map[string]map[string]*struct{}

	// deleteFuture is indexed by image ID and has a cancelable delete future
	deleteFuture map[string]context.CancelFunc
}

func newCoordinator(config *coordinatorConfig) *coordinator {
	return &coordinator{
		coordinatorConfig: config,
		pullFutures:       make(map[string]*pullFuture),
		pullLoggers:       make(map[string][]LogEventFn),
		imageRefCount:     make(map[string]map[string]*struct{}),
		deleteFuture:      make(map[string]context.CancelFunc),
	}
}

func (c *coordinator) PullImage(ctx context.Context, image string, callerID string, emitFn LogEventFn) (string, error) {
	c.imageLock.Lock()

	c.registerPullLogger(image, emitFn)
	defer c.clearPullLogger(image)

	future, ok := c.pullFutures[image]
	if !ok {
		future = newPullFuture()
		c.pullFutures[image] = future

		go c.pullImageImpl(ctx, image, future)
	}

	c.imageLock.Unlock()

	select {
	case <-ctx.Done():
		// consume the channel
		<-future.wait()

		return "", structs.NewRecoverableError(
			fmt.Errorf("failed to pull %q. %w", image, ctx.Err()),
			true,
		)
	case <-future.wait():
	}

	id, err := future.result()

	c.imageLock.Lock()
	defer c.imageLock.Unlock()

	if _, ok := c.pullFutures[image]; ok {
		delete(c.pullFutures, image)
	}

	if err == nil && c.cleanup {
		c.incrementImageReferenceImpl(id, image, callerID)
	}

	return id, err
}

func (c *coordinator) pullImageImpl(ctx context.Context, image string, future *pullFuture) {
	closer, err := c.client.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		future.set("", structs.NewRecoverableError(
			fmt.Errorf("failed to pull %q. %w", image, err),
			true,
		))
		return
	}

	defer closer.Close()

	reader := bufio.NewReader(closer)

	sha256 := ""
	line := struct {
		Status string `json:"status"`
		ID     string `json:"id,omitempty"`
	}{}

	for {
		l, _, err := reader.ReadLine()
		if err != nil && len(l) == 0 {
			if line.Status != "" {
				future.set("", fmt.Errorf("failed to pull image: %s. %w", line.Status, err))
			} else {
				future.set("", fmt.Errorf("failed to read image pull operation. %w", err))
			}
			return
		}

		c.logger.Debug("pull event", "line", string(l))

		if err := json.Unmarshal(l, &line); err != nil {
			future.set("", fmt.Errorf("failed to unmarshall JSON message, %q. %w", string(l), err))
			return
		}

		if strings.HasPrefix(line.Status, "Digest: sha256:") {
			sha256 = line.Status[15:]
			break
		}
	}

	c.logger.Debug("image pulled", "sha256", sha256)

	future.set(sha256, nil)
	return
}

func (c *coordinator) registerPullLogger(image string, logger LogEventFn) {
	c.pullLoggerLock.Lock()
	defer c.pullLoggerLock.Unlock()

	if _, ok := c.pullLoggers[image]; ok {
		c.pullLoggers[image] = make([]LogEventFn, 0, 1)
	}

	c.pullLoggers[image] = append(c.pullLoggers[image], logger)
}

func (c *coordinator) clearPullLogger(image string) {
	c.pullLoggerLock.Lock()
	defer c.pullLoggerLock.Unlock()

	delete(c.pullLoggers, image)
}

// incrementImageReferenceImpl ...
//
// It assumes the lock is held
func (c *coordinator) incrementImageReferenceImpl(id, image, callerID string) {
	if cancel, ok := c.deleteFuture[id]; ok {
		c.logger.Debug("cancelling removal of container image", "image", image)
		cancel()
		delete(c.deleteFuture, id)
	}

	references, ok := c.imageRefCount[id]
	if !ok {
		references = make(map[string]*struct{})
		c.imageRefCount[id] = references
	}

	if _, ok := references[callerID]; !ok {
		references[callerID] = nil
		c.logger.Debug("image reference count incremented", "image", image, "id", id, "refcount", len(references))
	}
}

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
			break
		}
	}

	c.logger.Debug("image pulled", "id", image)

	future.set(image, nil)
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

// RemoveImage removes the given image. If there are any errors removing the
// image, the remove is retried internally.
func (c *coordinator) RemoveImage(imageID, callerID string) {
	c.imageLock.Lock()
	defer c.imageLock.Unlock()

	if !c.cleanup {
		c.logger.Debug("not cleanup, skipping")
		return
	}

	references, ok := c.imageRefCount[imageID]
	if !ok {
		c.logger.Warn("RemoveImage on non-referenced counted image id", "image_id", imageID)
		return
	}

	// Decrement the reference count
	delete(references, callerID)
	count := len(references)
	c.logger.Debug("image id reference count decremented", "image_id", imageID, "references", count)

	// Nothing to do
	if count != 0 {
		c.logger.Debug("count is zero")
		return
	}

	// This should never be the case but we safety guard so we don't leak a
	// cancel.
	if cancel, ok := c.deleteFuture[imageID]; ok {
		c.logger.Error("image id has lingering delete future", "image_id", imageID)
		cancel()
	}

	// Setup a future to delete the image
	ctx, cancel := context.WithCancel(context.TODO())
	c.deleteFuture[imageID] = cancel
	go c.removeImageImpl(ctx, imageID)

	// Delete the key from the reference count
	delete(c.imageRefCount, imageID)
}

// removeImageImpl is used to remove an image. It wil wait the specified remove
// delay to remove the image. If the context is cancelled before that the image
// removal will be cancelled.
func (c *coordinator) removeImageImpl(ctx context.Context, id string) {
	c.logger.Debug("removing image impl", "image_id", id)
	// Wait for the delay or a cancellation event
	select {
	case <-ctx.Done():
		// We have been cancelled
		return
	case <-time.After(c.removeDelay):
	}

	c.logger.Debug("removing image lock", "image_id", id)
	// Ensure we are suppose to delete. Do a short check while holding the lock
	// so there can't be interleaving. There is still the smallest chance that
	// the delete occurs after the image has been pulled but before it has been
	// incremented. For handling that we just treat it as a recoverable error in
	// the docker driver.
	c.imageLock.Lock()
	select {
	case <-ctx.Done():
		c.imageLock.Unlock()
		return
	default:
	}
	c.imageLock.Unlock()

	c.logger.Debug("removing image", "image_id", id)

	for i := 0; i < 3; i++ {
		_, err := c.client.ImageRemove(ctx, id, types.ImageRemoveOptions{})
		if err == nil {
			break
		}

		if err != nil {
			c.logger.Debug("unable to cleanup image, does not exist", "image_id", id, "error", err)
		}

		/*
			if derr, ok := err.(*docker.Error); ok && derr.Status == 409 {
				c.logger.Debug("unable to cleanup image, still in use", "image_id", id)
				return
			}
		*/

		// Retry on unknown errors
		c.logger.Debug("failed to remove image", "image_id", id, "attempt", i+1, "error", err)

		select {
		case <-ctx.Done():
			// We have been cancelled
			return
		case <-time.After(3 * time.Second):
		}
	}

	c.logger.Debug("cleanup removed downloaded image", "image_id", id)

	// Cleanup the future from the map and free the context by cancelling it
	c.imageLock.Lock()
	if cancel, ok := c.deleteFuture[id]; ok {
		delete(c.deleteFuture, id)
		cancel()
	}
	c.imageLock.Unlock()
}

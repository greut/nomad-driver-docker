package docker

import (
	"context"
	"fmt"
	"sync"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
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
	imageRefCount map[string]map[string]struct{}

	// deleteFuture is indexed by image ID and has a cancelable delete future
	deleteFuture map[string]context.CancelFunc
}

func newCoordinator(config *coordinatorConfig) *coordinator {
	return &coordinator{
		coordinatorConfig: config,
		pullFutures:       make(map[string]*pullFuture),
		pullLoggers:       make(map[string][]LogEventFn),
		imageRefCount:     make(map[string]map[string]struct{}),
		deleteFuture:      make(map[string]context.CancelFunc),
	}
}

func (c *coordinator) PullImage(image string, callerID string, emitFn LogEventFn, timeout time.Duration) (imageID error, err error) {
	/*

		closer, err := client.ImagePull(d.ctx, config.Image, types.ImagePullOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pull the image %q. %w", config.Image, err)
		}

		defer closer.Close()

		b, err := ioutil.ReadAll(closer)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read image pull operation. %w", err)
		}

		// XXX b is a stream of JSON documents
		d.logger.Debug("image pulled", "output", string(b))


	*/
	return nil, fmt.Errorf("not implemented error %s", image)
}

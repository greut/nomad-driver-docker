package docker

import (
	"context"
)

// pullFuture is a sharable future for retrieving a pulled images ID and any
// error that may have occurred during the pull.
type pullFuture struct {
	waitChan chan struct{}

	err     error
	imageID string
}

// newPullFuture returns a new pull future
func newPullFuture() *pullFuture {
	return &pullFuture{
		waitChan: make(chan struct{}),
	}
}

// wait waits till the future has a result
func (p *pullFuture) wait(ctx context.Context) (*pullFuture, error) {
	select {
	case <-ctx.Done():
		return p, ctx.Err()
	case <-p.waitChan:
		return p, nil
	}
}

// result returns the results of the future and should only ever be called after
// wait returns.
func (p *pullFuture) result() (imageID string, err error) {
	return p.imageID, p.err
}

// set is used to set the results and unblock any waiter. This may only be
// called once.
func (p *pullFuture) set(imageID string, err error) {
	p.imageID = imageID
	p.err = err

	close(p.waitChan)
}

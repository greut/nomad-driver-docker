package docker

import (
	"context"
	"time"

	"github.com/hashicorp/nomad/plugins/drivers"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
)

func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	// start reconciler when we start fingerprinting
	// this is the only method called when the driver is properly launched
	d.reconciler.Start()

	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

func (d *Driver) handleFingerprint(ctx context.Context, ch chan *drivers.Fingerprint) {
	defer close(ch)

	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ticker.Reset(fingerprintPeriod)
			ch <- d.buildFingerprint()
		}
	}
}

func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes:        map[string]*pstructs.Attribute{},
		Health:            drivers.HealthStateHealthy,
		HealthDescription: drivers.DriverHealthy,
	}

	client, _, err := d.dockerClients()
	if err != nil {
		if d.fingerprintSuccessful() {
			d.logger.Info("failed to initialize client", "error", err)
		}
		d.setFingerprintFailure()
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: "Failed to initialize docker client",
		}
	}

	version, err := client.ServerVersion(d.ctx)
	if err != nil {
		if d.fingerprintSuccessful() {
			d.logger.Debug("could not connect to docker daemon", "endpoint", d.config.Endpoint, "error", err)
		}
		d.setFingerprintFailure()

		result := drivers.HealthStateUndetected
		if d.previouslyDetected() {
			result = drivers.HealthStateUnhealthy
		}

		return &drivers.Fingerprint{
			Health:            result,
			HealthDescription: "Failed to connect to docker daemon",
		}
	}

	d.setDetected(true)
	fp.Attributes["driver.docker"] = pstructs.NewBoolAttribute(true)
	fp.Attributes["driver.docker.client"] = pstructs.NewStringAttribute(client.ClientVersion())
	fp.Attributes["driver.docker.version"] = pstructs.NewStringAttribute(version.Version)

	// XXX volumes
	// XXX privileges
	// XXX networks

	if dockerInfo, err := client.Info(d.ctx); err != nil {
		d.logger.Warn("failed to get Docker system info", "error", err)
		d.setFingerprintFailure()
	} else {
		fp.Attributes["driver.docker.os_type"] = pstructs.NewStringAttribute(dockerInfo.OSType)

		// XXX runtimes
		// XXX windows on linux

		d.setFingerprintSuccess()
	}

	return fp
}

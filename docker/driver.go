package docker

import (
	"context"
	"fmt"
	"sync"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-hclog"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/helper"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

const (
	pluginName         = "docker"
	fingerprintPeriod  = 30 * time.Second
	taskHandleVersion  = 1
	dockerLabelAllocID = "com.hashicorp.nomad.alloc_id"
)

var (
	// Version is set at compile time.
	Version = "0.0.0"

	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     Version,
		Name:              pluginName,
	}

	danglingContainersBlock = hclspec.NewObject(map[string]*hclspec.Spec{
		"enabled": hclspec.NewDefault(
			hclspec.NewAttr("enabled", "bool", false),
			hclspec.NewLiteral(`true`),
		),
		"period": hclspec.NewDefault(
			hclspec.NewAttr("period", "string", false),
			hclspec.NewLiteral(`"5m"`),
		),
		"creation_grace": hclspec.NewDefault(
			hclspec.NewAttr("creation_grace", "string", false),
			hclspec.NewLiteral(`"5m"`),
		),
		"dry_run": hclspec.NewDefault(
			hclspec.NewAttr("dry_run", "bool", false),
			hclspec.NewLiteral(`false`),
		),
	})

	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"endpoint": hclspec.NewAttr("endpoint", "string", false),
		"gc": hclspec.NewDefault(
			hclspec.NewBlock("gc", false, hclspec.NewObject(map[string]*hclspec.Spec{
				"image": hclspec.NewDefault(
					hclspec.NewAttr("image", "bool", false),
					hclspec.NewLiteral("true"),
				),
				"image_delay": hclspec.NewDefault(
					hclspec.NewAttr("image_delay", "string", false),
					hclspec.NewLiteral("\"3m\""),
				),
				"container": hclspec.NewDefault(
					hclspec.NewAttr("container", "bool", false),
					hclspec.NewLiteral("true"),
				),
				"dangling_containers": hclspec.NewDefault(
					hclspec.NewBlock("dangling_containers", false, danglingContainersBlock),

					hclspec.NewLiteral(`{
					enabled = true
					period = "5m"
					creation_grace = "5m"
				}`),
				),
			})),
			hclspec.NewLiteral(`{
				image = true
				container = true
				dangling_containers = {
					enabled = true
					period = "5m"
					creation_grace = "5m"
				}
			}`),
		),
	})

	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":  hclspec.NewAttr("image", "string", true),
		"labels": hclspec.NewAttr("labels", "list(map(string))", false),
	})

	capabilities = &drivers.Capabilities{
		SendSignals: true,
	}
)

type Driver struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// client is a docker client with a timetout of 5 minutes. This is for doing
	// all operations with the docker daemon besides which are not long running
	// such as creating, killing containers, etc.
	client            *docker.Client
	waitClient        *docker.Client
	createClientsLock sync.RWMutex

	// config contains the runtime configuration for the driver set by the
	// SetConfig RPC
	config *DriverConfig

	// clientConfig contains a driver specific subset of the Nomad client
	// configuration
	clientConfig *base.ClientDriverConfig

	// ctx is th econtext for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// signalShutdown is called when the driver is shutting down and cancels the
	// ctx passed to any subsystem
	signalShutdown context.CancelFunc

	// log will log to the Nomad agent
	logger hclog.Logger

	// tasks is the in memory datastore mapping taskIDs to taskHandles
	tasks *taskStore

	// coordinator tracks multiple image pulls against the same image
	coordinator *coordinator

	// A tri-state boolean to know if the fingerprinting has happened and
	// whether it has been successful
	fingerprintSuccess *bool
	fingerprintLock    sync.RWMutex

	// A boolean to know if the docker driver has ever been correctly detected
	// for use during fingerprinting.
	detected     bool
	detectedLock sync.RWMutex

	reconciler *reconciler
}

// NewDriver retuns a docker implementation of a driver plugin
func NewDriver(logger hclog.Logger) *Driver {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)

	return &Driver{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &DriverConfig{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

// PluginInfo describes the type and version of a plugin.
func (d *Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the schema for parsing the plugins configuration.
func (d *Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

// SetConfig is used to set the configuration by passing a MessagePack
// encoding of it.
func (d *Driver) SetConfig(c *base.Config) error {
	config := &DriverConfig{}

	if len(c.PluginConfig) != 0 {
		if err := base.MsgPackDecode(c.PluginConfig, &config); err != nil {
			return err
		}
	}

	d.config = config

	if len(d.config.GC.ImageDelay) > 0 {
		dur, err := time.ParseDuration(d.config.GC.ImageDelay)
		if err != nil {
			return fmt.Errorf("failed to parse `image_delay` duration. %w", err)
		}
		d.config.GC.imageDelayDuration = dur
	}

	// XXX parse the duration

	if c.AgentConfig != nil {
		d.clientConfig = c.AgentConfig.Driver
	}

	dockerClient, _, err := d.clients()
	if err != nil {
		return fmt.Errorf("failed to get docker client. %w", err)
	}

	coordinatorConfig := &coordinatorConfig{
		client: dockerClient,
	}

	d.coordinator = newCoordinator(coordinatorConfig)

	d.reconciler = newReconciler(d)

	return nil
}

func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return nil, fmt.Errorf("3 not implemented error")
}

func (d *Driver) RecoverTask(*drivers.TaskHandle) error {
	return fmt.Errorf("4 not implemented error")
}

func (d *Driver) StartTask(*drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	return nil, nil, fmt.Errorf("5 not implemented error")
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	return nil, fmt.Errorf("6 not implemented error")
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	return fmt.Errorf("7 not implemented error")
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	return fmt.Errorf("8 not implemented error")
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	return nil, fmt.Errorf("9 not implemented error")
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *cstructs.TaskResourceUsage, error) {
	return nil, fmt.Errorf("a not implemented error")
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	return fmt.Errorf("c not implemented error")
}

func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, fmt.Errorf("d not implemented error")
}

// clients creates two *docker.Client, one for long running operations and
// the other for shorter operations. In test / dev mode we can use ENV vars to
// connect to the docker daemon. In production mode we will read docker.endpoint
// from the config file.
func (d *Driver) clients() (*docker.Client, *docker.Client, error) {
	d.createClientsLock.Lock()
	defer d.createClientsLock.Unlock()

	if d.client == nil {
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating client from env. %w", err)
		}

		d.client = client
	}

	if d.waitClient == nil {
		// XXX no timeouts
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating wait client from env. %w", err)
		}

		d.waitClient = client
	}

	return d.client, d.waitClient, nil
}

func (d *Driver) setDetected(detected bool) {
	d.detectedLock.Lock()
	defer d.detectedLock.Unlock()

	d.detected = detected
}

func (d *Driver) previouslyDetected() bool {
	d.detectedLock.RLock()
	defer d.detectedLock.RUnlock()

	return d.detected
}

// setFingerprintSuccess marks the driver as having fingerprinted successfully
func (d *Driver) setFingerprintSuccess() {
	d.fingerprintLock.Lock()
	d.fingerprintSuccess = helper.BoolToPtr(true)
	d.fingerprintLock.Unlock()
}

// setFingerprintFailure marks the driver as having failed fingerprinting
func (d *Driver) setFingerprintFailure() {
	d.fingerprintLock.Lock()
	d.fingerprintSuccess = helper.BoolToPtr(false)
	d.fingerprintLock.Unlock()
}

// fingerprintSuccessful returns true if the driver has
// never fingerprinted or has successfully fingerprinted
func (d *Driver) fingerprintSuccessful() bool {
	d.fingerprintLock.Lock()
	defer d.fingerprintLock.Unlock()
	return d.fingerprintSuccess == nil || *d.fingerprintSuccess
}

func (d *Driver) trackedContainers() map[string]bool {
	d.tasks.lock.RLock()
	defer d.tasks.lock.RUnlock()

	r := make(map[string]bool, len(d.tasks.store))
	for _, h := range d.tasks.store {
		r[h.containerID] = true
	}

	return r
}

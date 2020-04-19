package docker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/helper"
	nstructs "github.com/hashicorp/nomad/nomad/structs"
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
	if len(d.config.PullActivityTimeout) > 0 {
		dur, err := time.ParseDuration(d.config.PullActivityTimeout)
		if err != nil {
			return fmt.Errorf("failed to parse 'pull_activity_timeout' duaration: %v", err)
		}
		if dur < pullActivityTimeoutMinimum {
			return fmt.Errorf("pull_activity_timeout is less than minimum, %v", pullActivityTimeoutMinimum)
		}
		d.config.pullActivityTimeoutDuration = dur
	}

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
	return capabilities, nil
}

func (d *Driver) RecoverTask(*drivers.TaskHandle) error {
	return fmt.Errorf("4 not implemented error")
}

func (d *Driver) StartTask(task *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(task.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", task.ID)
	}

	config := new(TaskConfig)
	if err := task.DecodeDriverConfig(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config. %w", err)
	}

	if config.Image == "" {
		return nil, nil, fmt.Errorf("image name required for docker driver")
	}

	client, waitClient, err := d.clients()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain a docker client. %w", err)
	}

	// Pull image
	d.logger.Debug("pulling docker image", "image", config.Image)

	d.eventer.EmitEvent(&drivers.TaskEvent{
		TaskID:    task.ID,
		AllocID:   task.AllocID,
		TaskName:  task.Name,
		Timestamp: time.Now(),
		Message:   "Downloading image",
		Annotations: map[string]string{
			"image": config.Image,
		},
	})

	ctx, cancel := context.WithTimeout(d.ctx, d.config.pullActivityTimeoutDuration)
	defer cancel()

	imageID, err := d.coordinator.PullImage(
		ctx,
		config.Image,
		task.ID,
		d.emitEventFunc(task),
	)

	if err != nil {
		return nil, nil, err
	}

	d.logger.Debug("image pulled", "image_id", imageID)

	// Create container

	containerName := fmt.Sprintf(
		"%s-%s", strings.Replace(task.Name, "/", "_", -1),
		task.AllocID,
	)

	containers, err := client.ContainerList(d.ctx, types.ContainerListOptions{
		Limit:   1,
		Filters: filters.NewArgs(filters.Arg("name", containerName)),
	})

	// Create a new container
	// XXX command + args is a legacy from the Docker plugin (shrugs)
	cmd := make([]string, 0, len(config.Args)+1)
	if config.Command != "" {
		cmd = append(cmd, config.Command)
	}
	if len(config.Args) != 0 {
		cmd = append(cmd, config.Args...)
	}
	d.logger.Debug("container creation", "image", config.Image, "command", cmd)

	// Mounting volumes
	allocDirBind := fmt.Sprintf("%s:%s", task.TaskDir().SharedAllocDir, task.Env[taskenv.AllocDir])
	taskLocalBind := fmt.Sprintf("%s:%s", task.TaskDir().LocalDir, task.Env[taskenv.TaskLocalDir])
	secretDirBind := fmt.Sprintf("%s:%s", task.TaskDir().SecretsDir, task.Env[taskenv.SecretsDir])
	binds := []string{allocDirBind, taskLocalBind, secretDirBind}

	// XXX figure out how to get ENV from the image.
	task.Env["PATH"] = "/bin:/sbin:/usr/bin:/usr/local/bin"
	env := task.EnvList()

	_, err = client.ContainerCreate(
		d.ctx,
		&container.Config{
			Image:  config.Image,
			Cmd:    cmd,
			Labels: config.Labels,
			Env:    env,
		},
		&container.HostConfig{
			Binds: binds,
		},
		&network.NetworkingConfig{},
		containerName,
	)

	if err != nil {
		d.logger.Error("container creation failure", "error", err)
	}

	// Search for the created container
	// XXX does it need a mutex?
	containers, err = client.ContainerList(d.ctx, types.ContainerListOptions{
		Limit:   1,
		Filters: filters.NewArgs(filters.Arg("name", containerName)),
	})

	if len(containers) == 0 {
		return nil, nil, fmt.Errorf("could not find the created container")
	}

	container := &containers[0]

	d.logger.Info("created container", "container_id", container.ID)

	if container.State != "running" {
		if err := client.ContainerStart(d.ctx, container.ID, types.ContainerStartOptions{}); err != nil {
			d.logger.Error("failed to start container", "container_id", container.ID)

			return nil, nil, nstructs.WrapRecoverable(fmt.Sprintf("Failed to start container %s: %s", container.ID, err), err)
		}

		// XXX update "container" using list

		d.logger.Info("started container", "container_id", container.ID)
	} else {
		d.logger.Debug("re-attaching to container", "container_id",
			container.ID, "container_state", container.State)
	}

	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = task

	containerJSON, err := client.ContainerInspect(d.ctx, container.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("container inspection failure. %w", err)
	}

	ip, autoUse := d.detectIP(&containerJSON, config)

	net := &drivers.DriverNetwork{
		PortMap:       config.PortMap,
		IP:            ip,
		AutoAdvertise: autoUse,
	}

	h := &taskHandle{
		ctx:                   d.ctx,
		client:                client,
		waitClient:            waitClient,
		logger:                d.logger.With("container_id", container.ID),
		task:                  task,
		containerID:           container.ID,
		doneChan:              make(chan bool),
		waitChan:              make(chan struct{}),
		removeContainerOnExit: d.config.GC.Container,
	}

	if err := handle.SetDriverState(h.buildState()); err != nil {
		d.logger.Error("error occured after startup, terminating container", "container_id", container.ID, "error", err)
		client.ContainerRemove(d.ctx, container.ID, types.ContainerRemoveOptions{
			Force: true,
		})
		return nil, nil, fmt.Errorf("set driver state failure. %w", err)
	}

	d.tasks.Set(task.ID, h)
	go h.run()

	return handle, net, nil
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, ch, h)

	return ch, nil
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if signal == "" {
		signal = "SIGINT"
	}

	sig, err := signals.Parse(signal)
	if err != nil {
		return fmt.Errorf("failed to parse signal: %v", err)
	}

	return h.Kill(timeout, sig)
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	c, err := h.client.ContainerInspect(h.ctx, h.containerID)
	if err != nil {
		if docker.IsErrNotFound(err) {
			h.logger.Info("container was removed out of band, will proceed with DestroyTask",
				"error", err)
		} else {
			return fmt.Errorf("failed to inspect container state: %s. %w", h.containerID, err)
		}
	} else {
		if c.State.Running {
			if !force {
				return fmt.Errorf("must call StopTask for the given task before Destroy or set force to true")
			}
			if err := h.client.ContainerStop(h.ctx, h.containerID, nil); err != nil {
				h.logger.Warn("failed to stop container during destroy", "error", err)
			}
		}

		if h.removeContainerOnExit {
			if err := h.client.ContainerRemove(h.ctx, h.containerID, types.ContainerRemoveOptions{RemoveVolumes: true, Force: true}); err != nil {
				h.logger.Error("error removing container", "error", err)
			}
		} else {
			h.logger.Debug("not removing container due to config")
		}
	}

	/* XXX TODO
	if err := d.cleanupImage(h); err != nil {
		h.logger.Error("failed to cleanup image after destroying container",
			"error", err)
	}
	*/

	d.tasks.Delete(taskID)
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	container, err := h.client.ContainerInspect(h.ctx, h.containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %q. %w", h.containerID, err)
	}

	startedAt, err := time.Parse(time.RFC3339, container.State.StartedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse startedAt field. %w", err)
	}

	finishedAt, err := time.Parse(time.RFC3339, container.State.FinishedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse startedAt field. %w", err)
	}

	status := &drivers.TaskStatus{
		ID:          h.task.ID,
		Name:        h.task.Name,
		StartedAt:   startedAt,
		CompletedAt: finishedAt,
		DriverAttributes: map[string]string{
			"container_id": container.ID,
		},
		NetworkOverride: h.net,
		ExitResult:      h.ExitResult(),
	}

	status.State = drivers.TaskStateUnknown
	if container.State.Running {
		status.State = drivers.TaskStateRunning
	}
	if container.State.Dead {
		status.State = drivers.TaskStateExited
	}

	return status, nil
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *cstructs.TaskResourceUsage, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return h.Stats(ctx, interval)
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	sig, err := signals.Parse(signal)
	if err != nil {
		return fmt.Errorf("failed to parse signal: %v", err)
	}

	return h.Signal(sig)
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

func (d *Driver) detectIP(c *types.ContainerJSON, config *TaskConfig) (string, bool) {
	ip := ""

	for _, net := range c.NetworkSettings.Networks {
		if net.IPAddress == "" {
			continue
		}

		ip = net.IPAddress
		break
	}

	return ip, false
}

func (d *Driver) emitEventFunc(task *drivers.TaskConfig) LogEventFn {
	return func(msg string, annotations map[string]string) {
		d.eventer.EmitEvent(&drivers.TaskEvent{
			TaskID:      task.ID,
			AllocID:     task.AllocID,
			TaskName:    task.Name,
			Timestamp:   time.Now(),
			Message:     msg,
			Annotations: annotations,
		})
	}
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

func (d *Driver) handleWait(ctx context.Context, ch chan *drivers.ExitResult, h *taskHandle) {
	defer close(ch)

	select {
	case <-h.waitChan:
		ch <- h.ExitResult()
	case <-ctx.Done():
		ch <- &drivers.ExitResult{
			Err: ctx.Err(),
		}
	}
}

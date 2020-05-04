package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/oci/caps"
	"github.com/docker/go-connections/nat"
	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/helper"
	"github.com/hashicorp/nomad/helper/pluginutils/loader"
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

	// Nvidia-container-runtime environment variable names
	nvidiaVisibleDevices = "NVIDIA_VISIBLE_DEVICES"
)

var (
	// Version is set at compile time.
	Version = "0.0.0"

	PluginID = loader.PluginID{
		Name:       pluginName,
		PluginType: base.PluginTypeDriver,
	}

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
		"allow_caps": hclspec.NewDefault(
			hclspec.NewAttr("allow_caps", "list(string)", false),
			hclspec.NewLiteral(`["CHOWN","DAC_OVERRIDE","FSETID","FOWNER","MKNOD","NET_RAW","SETGID","SETUID","SETFCAP","SETPCAP","NET_BIND_SERVICE","SYS_CHROOT","KILL","AUDIT_WRITE"]`),
		),
		"nvidia_runtime": hclspec.NewDefault(
			hclspec.NewAttr("nvidia_runtime", "string", false),
			hclspec.NewLiteral(`"nvidia"`),
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

	// gpuRuntime indicates nvidia-docker runtime availability
	gpuRuntime bool

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

	if len(d.config.PullActivityTimeout) > 0 {
		dur, err := time.ParseDuration(d.config.PullActivityTimeout)
		if err != nil {
			return fmt.Errorf("failed to parse 'pull_activity_timeout' duration: %v", err)
		}
		if dur < pullActivityTimeoutMinimum {
			return fmt.Errorf("pull_activity_timeout is less than minimum, %v", pullActivityTimeoutMinimum)
		}
		d.config.pullActivityTimeoutDuration = dur
	} else {
		d.config.pullActivityTimeoutDuration = pullActivityTimeoutMinimum
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
		logger: d.logger,
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

func (d *Driver) containerCreateConfig(task *drivers.TaskConfig, config *TaskConfig, imageID string) (*types.ContainerCreateConfig, error) {
	if task.Resources == nil {
		// Guard against missing resources. We should never have been able to
		// schedule a job without specifying this.
		d.logger.Error("task.Resources is empty")
		return nil, fmt.Errorf("task.Resources is empty")
	}

	// Create a new container
	// XXX command + args is a legacy from the Docker plugin (shrugs)
	cmd := make([]string, 0, len(config.Args)+1)
	if config.Command != "" {
		cmd = append(cmd, config.Command)
	}
	if len(config.Args) != 0 {
		cmd = append(cmd, config.Args...)
	}
	d.logger.Debug("container creation", "image", config.Image, "imageID", imageID, "command", cmd)

	// ensure that PortMap variables are populated early on
	task.Env = taskenv.SetPortMapEnvs(task.Env, config.PortMap)

	// XXX figure out how to get ENV from the image.
	task.Env["PATH"] = "/bin:/sbin:/usr/bin:/usr/local/bin"
	env := task.EnvList()

	labels := make(map[string]string, len(config.Labels)+1)
	for k, v := range config.Labels {
		labels[k] = v
	}
	labels[dockerLabelAllocID] = task.AllocID

	// Mounting volumes
	allocDirBind := fmt.Sprintf("%s:%s", task.TaskDir().SharedAllocDir, task.Env[taskenv.AllocDir])
	taskLocalBind := fmt.Sprintf("%s:%s", task.TaskDir().LocalDir, task.Env[taskenv.TaskLocalDir])
	secretDirBind := fmt.Sprintf("%s:%s", task.TaskDir().SecretsDir, task.Env[taskenv.SecretsDir])
	binds := []string{allocDirBind, taskLocalBind, secretDirBind}

	securityOpt, err := parseSecurityOpts(config.SecurityOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse security_opt configuration: %v", err)
	}

	containerName := fmt.Sprintf(
		"%s-%s", strings.Replace(task.Name, "/", "_", -1),
		task.AllocID,
	)

	// Setup port mapping and exposed ports
	var exposedPorts nat.PortSet
	var publishedPorts nat.PortMap
	if task.Resources.NomadResources != nil {
		if len(task.Resources.NomadResources.Networks) == 0 {
			if len(config.PortMap) > 0 {
				return nil, fmt.Errorf("trying to map ports but no network interface is available")
			}
		} else {
			// TODO add support for more than one network
			network := task.Resources.NomadResources.Networks[0]

			exposedPorts = make(map[nat.Port]struct{})
			publishedPorts = make(map[nat.Port][]nat.PortBinding)

			for _, port := range network.ReservedPorts {
				// By default we will map the allocated port 1:1 to the container
				containerPortInt := port.Value

				// If the user has mapped a port using port_map we'll change it here
				if mapped, ok := config.PortMap[port.Label]; ok {
					containerPortInt = mapped
				}

				hostPortStr := strconv.Itoa(port.Value)
				containerPort := nat.Port(strconv.Itoa(containerPortInt))

				publishedPorts[containerPort+"/tcp"] = []nat.PortBinding{
					{HostIP: network.IP, HostPort: hostPortStr},
				}
				publishedPorts[containerPort+"/udp"] = []nat.PortBinding{
					{HostIP: network.IP, HostPort: hostPortStr},
				}
				d.logger.Debug("allocated static port", "ip", network.IP, "port", port.Value)

				exposedPorts[containerPort+"/tcp"] = struct{}{}
				exposedPorts[containerPort+"/udp"] = struct{}{}
				d.logger.Debug("exposed port", "port", port.Value)
			}

			for _, port := range network.DynamicPorts {
				// By default we will map the allocated port 1:1 to the container
				containerPortInt := port.Value

				// If the user has mapped a port using port_map we'll change it here
				if mapped, ok := config.PortMap[port.Label]; ok {
					containerPortInt = mapped
				}

				hostPortStr := strconv.Itoa(port.Value)
				containerPort := nat.Port(strconv.Itoa(containerPortInt))

				publishedPorts[containerPort+"/tcp"] = []nat.PortBinding{
					{HostIP: network.IP, HostPort: hostPortStr},
				}
				publishedPorts[containerPort+"/udp"] = []nat.PortBinding{
					{HostIP: network.IP, HostPort: hostPortStr},
				}
				d.logger.Debug("allocated mapped port", "ip", network.IP, "port", port.Value)

				exposedPorts[containerPort+"/tcp"] = struct{}{}
				exposedPorts[containerPort+"/udp"] = struct{}{}
				d.logger.Debug("exposed port", "port", containerPort)
			}
		}
	}

	// set logging
	loggingDriver := config.Logging.Type
	if loggingDriver == "" {
		loggingDriver = config.Logging.Driver
	}

	logConfig := container.LogConfig{
		Type:   loggingDriver,
		Config: config.Logging.Config,
	}

	if logConfig.Type == "" && logConfig.Config == nil {
		d.logger.Trace("no docker log driver provided, defaulting to json-file")
		logConfig.Type = "json-file"
		logConfig.Config = map[string]string{
			"max-file": "2",
			"max-size": "2m",
		}
	}

	// set capabilities
	hostCapsWhitelistConfig := d.config.AllowCaps
	hostCapsWhitelist := make(map[string]*struct{})
	for _, cap := range hostCapsWhitelistConfig {
		cap = strings.ToLower(strings.TrimSpace(cap))
		hostCapsWhitelist[cap] = nil
	}

	if _, ok := hostCapsWhitelist["all"]; !ok {
		effectiveCaps, err := tweakCapabilities(
			strings.Split(dockerBasicCaps, ","),
			config.CapAdd,
			config.CapDrop,
		)
		if err != nil {
			return nil, err
		}

		var missingCaps []string
		for _, cap := range effectiveCaps {
			cap = strings.ToLower(cap)
			if _, ok := hostCapsWhitelist[cap]; !ok {
				missingCaps = append(missingCaps, cap)
			}
		}

		if len(missingCaps) > 0 {
			return nil, fmt.Errorf("docker driver doesn't have the following caps whitelisted on this Nomad agent: %s", missingCaps)
		}
	}

	// set runtime
	runtime := ""
	if _, ok := task.DeviceEnv[nvidiaVisibleDevices]; ok {
		if !d.gpuRuntime {
			return nil, fmt.Errorf("requested docker-runtime %q was not found", d.config.GPURuntimeName)
		}
		runtime = d.config.GPURuntimeName
	}

	// set DNS servers
	dns := make([]string, 0)
	for _, ip := range config.DNSServers {
		if net.ParseIP(ip) != nil {
			dns = append(dns, ip)
		} else {
			d.logger.Error("invalid ip address for container dns server", "ip", ip)
		}
	}

	return &types.ContainerCreateConfig{
		Name: containerName,
		Config: &container.Config{
			Cmd:          cmd,
			Env:          env,
			ExposedPorts: exposedPorts,
			Image:        imageID,
			Labels:       labels,
			MacAddress:   config.MacAddress,
			User:         task.User,
			WorkingDir:   config.WorkDir,
		},
		HostConfig: &container.HostConfig{
			Binds:        binds,
			CapAdd:       config.CapAdd,
			CapDrop:      config.CapDrop,
			DNS:          dns,
			DNSOptions:   config.DNSOptions,
			DNSSearch:    config.DNSSearchDomains,
			LogConfig:    logConfig,
			PortBindings: publishedPorts,
			Runtime:      runtime,
			SecurityOpt:  securityOpt,
			StorageOpt:   config.StorageOpt,
		},
		NetworkingConfig: &network.NetworkingConfig{},
		AdjustCPUShares:  false,
	}, nil
}

func (d *Driver) StartTask(task *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(task.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", task.ID)
	}

	config := new(TaskConfig)
	if err := task.DecodeDriverConfig(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config. %w", err)
	}

	client, waitClient, err := d.clients()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain a docker client. %w", err)
	}

	// Pull image

	if config.Image == "" {
		return nil, nil, fmt.Errorf("image name required for docker driver")
	}

	var imageID string
	if config.LoadImage != "" {
		imageID, err = d.loadImage(config, task)
	} else {
		imageID, err = d.pullImage(config, task)
	}

	if err != nil {
		return nil, nil, err
	}

	// Create container

	containerCreateConfig, err := d.containerCreateConfig(task, config, imageID)
	if err != nil {
		return nil, nil, err
	}

	_, err = client.ContainerCreate(
		d.ctx,
		containerCreateConfig.Config,
		containerCreateConfig.HostConfig,
		containerCreateConfig.NetworkingConfig,
		containerCreateConfig.Name,
	)

	if err != nil {
		d.logger.Error("container creation failure", "error", err)
	}

	// Search for the created container
	// XXX does it need a mutex?
	containers, err := client.ContainerList(d.ctx, types.ContainerListOptions{
		Limit:   1,
		Filters: filters.NewArgs(filters.Arg("name", containerCreateConfig.Name)),
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
		containerImage:        container.Image,
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

func (d *Driver) loadImage(config *TaskConfig, task *drivers.TaskConfig) (string, error) {
	d.logger.Debug("loading docker image", "image", config.LoadImage)

	d.eventer.EmitEvent(&drivers.TaskEvent{
		TaskID:    task.ID,
		AllocID:   task.AllocID,
		TaskName:  task.Name,
		Timestamp: time.Now(),
		Message:   "Loading image",
		Annotations: map[string]string{
			"image": config.LoadImage,
		},
	})

	archive := filepath.Join(task.TaskDir().LocalDir, config.LoadImage)
	d.logger.Debug("loading image from disk", "archive", archive)

	f, err := os.Open(archive)
	if err != nil {
		return "", fmt.Errorf("unable to open image archive: %s. %w", archive, err)
	}
	defer f.Close()

	r, err := d.client.ImageLoad(d.ctx, f, false)
	if err != nil {
		return "", fmt.Errorf("unable to load image archive: %s. %w", archive, err)
	}
	defer r.Body.Close()

	if !r.JSON {
		return "", fmt.Errorf("a JSON body was expected")
	}

	reader := bufio.NewReader(r.Body)

	line := struct {
		Stream string `json:"stream"`
	}{}
	image := ""

	for {
		l, _, err := reader.ReadLine()
		if err != nil && len(l) == 0 {
			if line.Stream != "" {
				return "", fmt.Errorf("failed to load image: %s. %w", line.Stream, err)
			}
			return "", fmt.Errorf("failed to read image load operation. %w", err)
		}

		d.logger.Debug("pull event", "line", string(l))

		if err := json.Unmarshal(l, &line); err != nil {
			return "", fmt.Errorf("failed to unmarshall JSON message, %q. %w", string(l), err)
		}

		if strings.HasPrefix(line.Stream, "Loaded image: ") {
			image = strings.TrimSpace(line.Stream[13:])
			break
		}
	}

	d.logger.Debug("loaded archive", "image", image)

	// XXX Shouldn't this return the SHA256?
	return image, nil
}

func (d *Driver) pullImage(config *TaskConfig, task *drivers.TaskConfig) (string, error) {
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

	return d.coordinator.PullImage(
		ctx,
		config.Image,
		task.ID,
		d.emitEventFunc(task),
	)
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

	if err := d.cleanupImage(h); err != nil {
		h.logger.Error("failed to cleanup image after destroying container",
			"error", err)
	}

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

// cleanupImage removes a Docker image. No error is returned if the image
// doesn't exist or is still in use. Requires the global client to already be
// initialized.
func (d *Driver) cleanupImage(handle *taskHandle) error {
	if !d.config.GC.Image {
		return nil
	}

	d.coordinator.RemoveImage(handle.containerImage, handle.task.ID)

	return nil
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

// takes a local seccomp daemon, reads the file contents for sending to the daemon
// this code modified slightly from the docker CLI code
// https://github.com/docker/cli/blob/8ef8547eb6934b28497d309d21e280bcd25145f5/cli/command/container/opts.go#L840
func parseSecurityOpts(securityOpts []string) ([]string, error) {
	for key, opt := range securityOpts {
		con := strings.SplitN(opt, "=", 2)
		if len(con) == 1 && con[0] != "no-new-privileges" {
			if strings.Contains(opt, ":") {
				con = strings.SplitN(opt, ":", 2)
			} else {
				return securityOpts, fmt.Errorf("invalid security_opt: %q", opt)
			}
		}
		if con[0] == "seccomp" && con[1] != "unconfined" {
			f, err := ioutil.ReadFile(con[1])
			if err != nil {
				return securityOpts, fmt.Errorf("opening seccomp profile (%s) failed: %v", con[1], err)
			}
			b := bytes.NewBuffer(nil)
			if err := json.Compact(b, f); err != nil {
				return securityOpts, fmt.Errorf("compacting json for seccomp profile (%s) failed: %v", con[1], err)
			}
			securityOpts[key] = fmt.Sprintf("seccomp=%s", b.Bytes())
		}
	}

	return securityOpts, nil
}

func tweakCapabilities(basics, adds, drops []string) ([]string, error) {
	// Moby mixes 2 different capabilities formats: prefixed with "CAP_"
	// and not. We do the conversion here to have a consistent,
	// non-prefixed format on the Nomad side.
	for i, cap := range basics {
		basics[i] = "CAP_" + cap
	}

	effectiveCaps, err := caps.TweakCapabilities(basics, adds, drops, nil, false)
	if err != nil {
		return nil, err
	}

	for i, cap := range effectiveCaps {
		effectiveCaps[i] = cap[len("CAP_"):]
	}
	return effectiveCaps, nil
}

package docker

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	tu "github.com/greut/nomad-driver-docker/testutil"
	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/client/taskenv"
	"github.com/hashicorp/nomad/helper/freeport"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
	//"github.com/stretchr/testify/assert"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/helper/pluginutils/loader"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/plugins/base"
	dtestutil "github.com/hashicorp/nomad/plugins/drivers/testutils"
	"github.com/stretchr/testify/require"
)

var (
	// busyboxLongRunningCmd is a busybox command that runs indefinitely, and
	// ideally responds to SIGINT/SIGTERM.  Sadly, busybox:1.29.3 /bin/sleep doesn't.
	busyboxLongRunningCmd = []string{"nc", "-l", "-p", "3000", "127.0.0.1"}
)

// Returns a task with a reserved and dynamic port. The ports are returned
// respectively, and should be reclaimed with freeport.Return at the end of a test.
func dockerTask(t *testing.T) (*drivers.TaskConfig, *TaskConfig, []int) {
	ports := freeport.MustTake(2)
	dockerReserved := ports[0]
	dockerDynamic := ports[1]

	cfg := newTaskConfig("", busyboxLongRunningCmd)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "redis-demo",
		AllocID: uuid.Generate(),
		Env: map[string]string{
			"test": t.Name(),
		},
		DeviceEnv: make(map[string]string),
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Memory: structs.AllocatedMemoryResources{
					MemoryMB: 256,
				},
				Cpu: structs.AllocatedCpuResources{
					CpuShares: 512,
				},
				Networks: []*structs.NetworkResource{
					{
						IP:            "127.0.0.1",
						ReservedPorts: []structs.Port{{Label: "main", Value: dockerReserved}},
						DynamicPorts:  []structs.Port{{Label: "REDIS", Value: dockerDynamic}},
					},
				},
			},
			LinuxResources: &drivers.LinuxResources{
				CPUShares:        512,
				MemoryLimitBytes: 256 * 1024 * 1024,
				PercentTicks:     float64(512) / float64(4096),
			},
		},
	}

	require.NoError(t, task.EncodeConcreteDriverConfig(&cfg))

	return task, cfg, ports
}

// dockerDriverHarness wires up everything needed to launch a task with a docker driver.
// A driver plugin interface and cleanup function is returned
func dockerDriverHarness(t *testing.T, cfg map[string]interface{}) *dtestutil.DriverHarness {
	logger := testlog.HCLogger(t)
	harness := dtestutil.NewDriverHarness(t, NewDriver(logger))
	if cfg == nil {
		cfg = map[string]interface{}{
			"gc": map[string]interface{}{
				"image_delay": "1s",
			},
		}
	}

	plugLoader, err := loader.NewPluginLoader(&loader.PluginLoaderConfig{
		Logger:            logger,
		PluginDir:         "./plugins",
		SupportedVersions: loader.AgentSupportedApiVersions,
		InternalPlugins: map[loader.PluginID]*loader.InternalPluginConfig{
			PluginID: {
				Config: cfg,
				Factory: func(hclog.Logger) interface{} {
					return harness
				},
			},
		},
	})

	require.NoError(t, err)
	instance, err := plugLoader.Dispense(pluginName, base.PluginTypeDriver, nil, logger)
	require.NoError(t, err)
	driver, ok := instance.Plugin().(*dtestutil.DriverHarness)
	if !ok {
		t.Fatal("plugin instance is not a driver... wat?")
	}

	return driver
}

// dockerSetup does all of the basic setup you need to get a running docker
// process up and running for testing. Use like:
//
//	task := taskTemplate()
//	// do custom task configuration
//	client, handle, cleanup := dockerSetup(t, task)
//	defer cleanup()
//	// do test stuff
//
// If there is a problem during setup this function will abort or skip the test
// and indicate the reason.
func dockerSetup(t *testing.T, task *drivers.TaskConfig) (*docker.Client, *dtestutil.DriverHarness, *taskHandle, func()) {
	client := newTestDockerClient(t)
	driver := dockerDriverHarness(t, nil)
	cleanup := driver.MkAllocDir(task, true)

	copyImage(t, task.TaskDir(), "busybox.tar")
	_, _, err := driver.StartTask(task)
	require.NoError(t, err)

	dockerDriver, ok := driver.Impl().(*Driver)
	require.True(t, ok)
	handle, ok := dockerDriver.tasks.Get(task.ID)
	require.True(t, ok)

	return client, driver, handle, func() {
		driver.DestroyTask(task.ID, true)
		cleanup()
	}
}

func newTestDockerClient(t *testing.T) *docker.Client {
	t.Helper()
	tu.DockerCompatible(t)

	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		t.Fatalf("failed to initialize client. %s", err)
	}

	return client
}

// copyFile moves an existing file to the destination
func copyFile(src, dst string, t *testing.T) {
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("copying %v -> %v failed: %v", src, dst, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("copying %v -> %v failed: %v", src, dst, err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Fatalf("copying %v -> %v failed: %v", src, dst, err)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		t.Fatalf("copying %v -> %v failed: %v", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		t.Fatalf("copying %v -> %v failed: %v", src, dst, err)
	}
}

func copyImage(t *testing.T, taskDir *allocdir.TaskDir, image string) {
	dst := filepath.Join(taskDir.LocalDir, image)
	copyFile(filepath.Join("../test-resources/", image), dst, t)
}

func TestDockerDriver_Start_Wait(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := newTaskConfig("", busyboxLongRunningCmd)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "nc-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	// Attempt to wait
	waitChan, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	select {
	case <-waitChan:
		t.Fatalf("wait channel should not have received an exit result")
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
	}
}

func TestDockerDriver_Start_WaitFinish(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := newTaskConfig("", []string{"echo", "hello"})
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "nc-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	// Attempt to wait
	waitChan, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	select {
	case res := <-waitChan:
		if !res.Successful() {
			require.Fail(t, "ExitResult should be successful: %v", res)
		}
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		require.Fail(t, "timeout")
	}
}

// TestDockerDriver_Start_StoppedContainer asserts that Nomad will detect a
// stopped task container, remove it, and start a new container.
//
// See https://github.com/hashicorp/nomad/issues/3419
func TestDockerDriver_Start_StoppedContainer(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := newTaskConfig("", []string{"sleep", "9001"})
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "nc-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	client := newTestDockerClient(t)

	// Create a container of the same name but don't start it. This mimics
	// the case of dockerd getting restarted and stopping containers while
	// Nomad is watching them.
	_, err := client.ContainerCreate(
		context.Background(),
		&container.Config{
			Image: taskCfg.Image,
			Cmd:   []string{"sleep", "9000"},
		},
		&container.HostConfig{},
		&network.NetworkingConfig{},
		strings.Replace(task.ID, "/", "_", -1),
	)

	if err != nil {
		t.Fatalf("container creation failure. %s", err)
	}

	_, _, err = d.StartTask(task)
	defer d.DestroyTask(task.ID, true)
	require.NoError(t, err)

	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))
	require.NoError(t, d.DestroyTask(task.ID, true))
}

func TestDockerDriver_Start_LoadImage(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := newTaskConfig("", []string{"sh", "-c", "echo hello > $NOMAD_TASK_DIR/output"})
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "busybox-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	waitCh, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)
	select {
	case res := <-waitCh:
		if !res.Successful() {
			require.Fail(t, "ExitResult should be successful: %v", res)
		}
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		require.Fail(t, "timeout")
	}

	// Check that data was written to the shared alloc directory.
	outputFile := filepath.Join(task.TaskDir().LocalDir, "output")
	act, err := ioutil.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Couldn't read expected output: %v", err)
	}

	exp := "hello"
	if strings.TrimSpace(string(act)) != exp {
		t.Fatalf("Command outputted %v; want %v", act, exp)
	}
}

// Tests that starting a task without an image fails
func TestDockerDriver_Start_NoImage(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := TaskConfig{
		Command: "echo",
		Args:    []string{"foo"},
	}
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "echo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := d.StartTask(task)
	require.Error(t, err)
	require.Contains(t, err.Error(), "image name required")

	d.DestroyTask(task.ID, true)
}

func TestDockerDriver_Start_BadPull_Recoverable(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := TaskConfig{
		Image:   "127.0.0.1:32121/foo", // bad path
		Command: "echo",
		Args: []string{
			"hello",
		},
	}
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "busybox-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()

	_, _, err := d.StartTask(task)
	require.Error(t, err)

	defer d.DestroyTask(task.ID, true)

	if rerr, ok := err.(*structs.RecoverableError); !ok {
		t.Fatalf("want recoverable error: %+v", err)
	} else if !rerr.IsRecoverable() {
		t.Fatalf("error not recoverable: %+v", err)
	}
}

func TestDockerDriver_Start_Wait_AllocDir(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	// This test requires that the alloc dir be mounted into docker as a volume.
	// Because this cannot happen when docker is run remotely, e.g. when running
	// docker in a VM, we skip this when we detect Docker is being run remotely.
	//if !testutil.DockerIsConnected(t) || dockerIsRemote(t) {
	//	t.Skip("Docker not connected")
	//}

	exp := []byte{'w', 'i', 'n'}
	file := "output.txt"

	taskCfg := newTaskConfig("", []string{
		"sh",
		"-c",
		fmt.Sprintf(`sleep 1; echo -n %s > $%s/%s`,
			string(exp), taskenv.AllocDir, file),
	})
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "busybox-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	// Attempt to wait
	waitCh, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	select {
	case res := <-waitCh:
		if !res.Successful() {
			require.Fail(t, fmt.Sprintf("ExitResult should be successful: %v", res))
		}
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		require.Fail(t, "timeout")
	}

	// Check that data was written to the shared alloc directory.
	outputFile := filepath.Join(task.TaskDir().SharedAllocDir, file)
	act, err := ioutil.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Couldn't read expected output: %v", err)
	}

	if !reflect.DeepEqual(act, exp) {
		t.Fatalf("Command outputted %v; want %v", act, exp)
	}
}

func TestDockerDriver_Start_Kill_Wait(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	taskCfg := newTaskConfig("", busyboxLongRunningCmd)
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "busybox-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	go func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		signal := "SIGINT"
		require.NoError(t, d.StopTask(task.ID, time.Second, signal))
	}(t)

	// Attempt to wait
	waitCh, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	select {
	case res := <-waitCh:
		if res.Successful() {
			require.Fail(t, "ExitResult should err: %v", res)
		}
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		require.Fail(t, "timeout")
	}
}

func TestDockerDriver_Start_KillTimeout(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	timeout := 2 * time.Second
	taskCfg := newTaskConfig("", []string{"sleep", "10"})
	task := &drivers.TaskConfig{
		ID:      uuid.Generate(),
		Name:    "busybox-demo",
		AllocID: uuid.Generate(),
		//Resources: basicResources,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(&taskCfg))

	d := dockerDriverHarness(t, nil)
	cleanup := d.MkAllocDir(task, true)
	defer cleanup()
	copyImage(t, task.TaskDir(), "busybox.tar")

	_, _, err := d.StartTask(task)
	require.NoError(t, err)

	defer d.DestroyTask(task.ID, true)

	var killSent time.Time
	go func() {
		time.Sleep(100 * time.Millisecond)
		killSent = time.Now()
		require.NoError(t, d.StopTask(task.ID, timeout, "SIGUSR1"))
	}()

	// Attempt to wait
	waitCh, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	var killed time.Time
	select {
	case <-waitCh:
		killed = time.Now()
	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		require.Fail(t, "timeout")
	}

	require.True(t, killed.Sub(killSent) > timeout)
}

func TestDockerDriver_StartN(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	require := require.New(t)

	task1, _, ports1 := dockerTask(t)
	defer freeport.Return(ports1)

	task2, _, ports2 := dockerTask(t)
	defer freeport.Return(ports2)

	task3, _, ports3 := dockerTask(t)
	defer freeport.Return(ports3)

	taskList := []*drivers.TaskConfig{task1, task2, task3}

	t.Logf("Starting %d tasks", len(taskList))

	d := dockerDriverHarness(t, nil)
	// Let's spin up a bunch of things
	for _, task := range taskList {
		cleanup := d.MkAllocDir(task, true)
		defer cleanup()
		copyImage(t, task.TaskDir(), "busybox.tar")
		_, _, err := d.StartTask(task)
		require.NoError(err)
	}

	defer d.DestroyTask(task3.ID, true)
	defer d.DestroyTask(task2.ID, true)
	defer d.DestroyTask(task1.ID, true)

	t.Log("All tasks are started. Terminating...")
	for _, task := range taskList {
		require.NoError(d.StopTask(task.ID, time.Second, "SIGINT"))

		// Attempt to wait
		waitCh, err := d.WaitTask(context.Background(), task.ID)
		require.NoError(err)

		select {
		case <-waitCh:
		case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
			require.Fail("timeout waiting on task")
		}
	}

	t.Log("Test complete!")
}

func TestDockerDriver_StartNVersions(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	require := require.New(t)

	task1, cfg1, ports1 := dockerTask(t)
	defer freeport.Return(ports1)
	tcfg1 := newTaskConfig("", []string{"echo", "hello"})
	cfg1.Image = tcfg1.Image
	cfg1.LoadImage = tcfg1.LoadImage
	require.NoError(task1.EncodeConcreteDriverConfig(cfg1))

	task2, cfg2, ports2 := dockerTask(t)
	defer freeport.Return(ports2)
	tcfg2 := newTaskConfig("musl", []string{"echo", "hello"})
	cfg2.Image = tcfg2.Image
	cfg2.LoadImage = tcfg2.LoadImage
	require.NoError(task2.EncodeConcreteDriverConfig(cfg2))

	task3, cfg3, ports3 := dockerTask(t)
	defer freeport.Return(ports3)
	tcfg3 := newTaskConfig("glibc", []string{"echo", "hello"})
	cfg3.Image = tcfg3.Image
	cfg3.LoadImage = tcfg3.LoadImage
	require.NoError(task3.EncodeConcreteDriverConfig(cfg3))

	taskList := []*drivers.TaskConfig{task1, task2, task3}

	t.Logf("Starting %d tasks", len(taskList))
	d := dockerDriverHarness(t, nil)

	// Let's spin up a bunch of things
	for _, task := range taskList {
		cleanup := d.MkAllocDir(task, true)
		defer cleanup()
		copyImage(t, task.TaskDir(), "busybox.tar")
		copyImage(t, task.TaskDir(), "busybox_musl.tar")
		copyImage(t, task.TaskDir(), "busybox_glibc.tar")
		_, _, err := d.StartTask(task)
		require.NoError(err)

		require.NoError(d.WaitUntilStarted(task.ID, 5*time.Second))
	}

	defer d.DestroyTask(task3.ID, true)
	defer d.DestroyTask(task2.ID, true)
	defer d.DestroyTask(task1.ID, true)

	t.Log("All tasks are started. Terminating...")
	for _, task := range taskList {
		require.NoError(d.StopTask(task.ID, time.Second, "SIGINT"))

		// Attempt to wait
		waitCh, err := d.WaitTask(context.Background(), task.ID)
		require.NoError(err)

		select {
		case <-waitCh:
		case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
			require.Fail("timeout waiting on task")
		}
	}

	t.Log("Test complete!")
}

func TestDockerDriver_Labels(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)

	cfg.Labels = map[string]string{
		"label1": "value1",
		"label2": "value2",
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// expect to see 1 additional standard label with the AllocID
	require.Equal(t, len(cfg.Labels)+1, len(container.Config.Labels))
	for k, v := range cfg.Labels {
		require.Equal(t, v, container.Config.Labels[k])
	}
}

func TestDockerDriver_ForcePull(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)

	cfg.ForcePull = true
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()

	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	_, err := client.ContainerInspect(context.TODO(), handle.containerID)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestDockerDriver_ForcePull_RepoDigest(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.LoadImage = ""
	cfg.Image = "library/busybox@sha256:58ac43b2cc92c687a32c8be6278e50a063579655fe3090125dcb2af0ff9e1a64"
	localDigest := "sha256:8ac48589692a53a9b8c2d1ceaa6b402665aa7fe667ba51ccc03002300856d8c7"
	cfg.ForcePull = true
	cfg.Command = busyboxLongRunningCmd[0]
	cfg.Args = busyboxLongRunningCmd[1:]
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)
	require.Equal(t, localDigest, container.Image)
}

func TestDockerDriver_SecurityOptUnconfined(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.SecurityOpt = []string{"seccomp=unconfined"}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	require.Exactly(t, cfg.SecurityOpt, container.HostConfig.SecurityOpt)
}

func TestDockerDriver_SecurityOptFromFile(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.SecurityOpt = []string{"seccomp=../test-resources/seccomp.json"}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)

	require.Contains(t, container.HostConfig.SecurityOpt[0], "reboot")
}

func TestDockerDriver_CreateContainerConfig(t *testing.T) {
	t.Parallel()

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	opt := map[string]string{"size": "120G"}

	cfg.StorageOpt = opt
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	dh := dockerDriverHarness(t, nil)
	driver := dh.Impl().(*Driver)

	c, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
	require.NoError(t, err)

	require.EqualValues(t, opt, c.HostConfig.StorageOpt)
}

func TestDockerDriver_CreateContainerConfig_User(t *testing.T) {
	t.Parallel()

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	task.User = "random-user-1"

	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	dh := dockerDriverHarness(t, nil)
	driver := dh.Impl().(*Driver)

	c, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
	require.NoError(t, err)

	require.Equal(t, task.User, c.Config.User)
}

func TestDockerDriver_CreateContainerConfig_Labels(t *testing.T) {
	t.Parallel()

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	task.AllocID = uuid.Generate()
	task.JobName = "redis-demo-job"

	cfg.Labels = map[string]string{
		"user_label": "user_value",

		// com.hashicorp.nomad. labels are reserved and
		// cannot be overridden
		"com.hashicorp.nomad.alloc_id": "bad_value",
	}

	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	dh := dockerDriverHarness(t, nil)
	driver := dh.Impl().(*Driver)

	c, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
	require.NoError(t, err)

	expectedLabels := map[string]string{
		// user provided labels
		"user_label": "user_value",
		// default labels
		"com.hashicorp.nomad.alloc_id": task.AllocID,
	}

	require.Equal(t, expectedLabels, c.Config.Labels)
}

func TestDockerDriver_CreateContainerConfig_Logging(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		loggingConfig  DockerLogging
		expectedConfig DockerLogging
	}{
		{
			"simple type",
			DockerLogging{Type: "fluentd"},
			DockerLogging{
				Type:   "fluentd",
				Config: map[string]string{},
			},
		},
		{
			"simple driver",
			DockerLogging{Driver: "fluentd"},
			DockerLogging{
				Type:   "fluentd",
				Config: map[string]string{},
			},
		},
		{
			"type takes precedence",
			DockerLogging{
				Type:   "json-file",
				Driver: "fluentd",
			},
			DockerLogging{
				Type:   "json-file",
				Config: map[string]string{},
			},
		},
		{
			"user config takes precedence, even if no type provided",
			DockerLogging{
				Type:   "",
				Config: map[string]string{"max-file": "3", "max-size": "10m"},
			},
			DockerLogging{
				Type:   "",
				Config: map[string]string{"max-file": "3", "max-size": "10m"},
			},
		},
		{
			"defaults to json-file w/ log rotation",
			DockerLogging{
				Type: "",
			},
			DockerLogging{
				Type:   "json-file",
				Config: map[string]string{"max-file": "2", "max-size": "2m"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			task, cfg, ports := dockerTask(t)
			defer freeport.Return(ports)

			cfg.Logging = c.loggingConfig
			require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

			dh := dockerDriverHarness(t, nil)
			driver := dh.Impl().(*Driver)

			cc, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
			require.NoError(t, err)

			require.Equal(t, c.expectedConfig.Type, cc.HostConfig.LogConfig.Type)
			require.Equal(t, c.expectedConfig.Config["max-file"], cc.HostConfig.LogConfig.Config["max-file"])
			require.Equal(t, c.expectedConfig.Config["max-size"], cc.HostConfig.LogConfig.Config["max-size"])
		})
	}
}

func TestDockerDriver_CreateContainerConfig_Runtimes(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}

	testCases := []struct {
		description           string
		gpuRuntimeSet         bool
		expectToReturnError   bool
		expectedRuntime       string
		nvidiaDevicesProvided bool
	}{
		{
			description:           "gpu devices are provided, docker driver was able to detect nvidia-runtime 1",
			gpuRuntimeSet:         true,
			expectToReturnError:   false,
			expectedRuntime:       "nvidia",
			nvidiaDevicesProvided: true,
		},
		{
			description:           "gpu devices are provided, docker driver was able to detect nvidia-runtime 2",
			gpuRuntimeSet:         true,
			expectToReturnError:   false,
			expectedRuntime:       "nvidia-runtime-modified-name",
			nvidiaDevicesProvided: true,
		},
		{
			description:           "no gpu devices provided - no runtime should be set",
			gpuRuntimeSet:         true,
			expectToReturnError:   false,
			expectedRuntime:       "nvidia",
			nvidiaDevicesProvided: false,
		},
		{
			description:           "no gpuRuntime supported by docker driver",
			gpuRuntimeSet:         false,
			expectToReturnError:   true,
			expectedRuntime:       "nvidia",
			nvidiaDevicesProvided: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			task, cfg, ports := dockerTask(t)
			defer freeport.Return(ports)

			dh := dockerDriverHarness(t, nil)
			driver := dh.Impl().(*Driver)

			driver.gpuRuntime = testCase.gpuRuntimeSet
			driver.config.GPURuntimeName = testCase.expectedRuntime
			if testCase.nvidiaDevicesProvided {
				task.DeviceEnv[nvidiaVisibleDevices] = "GPU_UUID_1"
			}

			c, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
			if testCase.expectToReturnError {
				require.NotNil(t, err)
			} else {
				require.NoError(t, err)
				if testCase.nvidiaDevicesProvided {
					require.Equal(t, testCase.expectedRuntime, c.HostConfig.Runtime)
				} else {
					// no nvidia devices provided -> no point to use nvidia runtime
					require.Equal(t, "", c.HostConfig.Runtime)
				}
			}
		})
	}
}

func TestDockerDriver_Capabilities(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	testCases := []struct {
		Name       string
		CapAdd     strslice.StrSlice
		CapDrop    strslice.StrSlice
		Whitelist  string
		StartError string
	}{
		{
			Name:    "default-whitelist-add-allowed",
			CapAdd:  []string{"fowner", "mknod"},
			CapDrop: []string{"all"},
		},
		{
			Name:       "default-whitelist-add-forbidden",
			CapAdd:     []string{"net_admin"},
			StartError: "net_admin",
		},
		{
			Name:    "default-whitelist-drop-existing",
			CapDrop: []string{"fowner", "mknod"},
		},
		{
			Name:      "restrictive-whitelist-drop-all",
			CapDrop:   []string{"all"},
			Whitelist: "fowner,mknod",
		},
		{
			Name:      "restrictive-whitelist-add-allowed",
			CapAdd:    []string{"fowner", "mknod"},
			CapDrop:   []string{"all"},
			Whitelist: "fowner,mknod",
		},
		{
			Name:       "restrictive-whitelist-add-forbidden",
			CapAdd:     []string{"net_admin", "mknod"},
			CapDrop:    []string{"all"},
			Whitelist:  "fowner,mknod",
			StartError: "net_admin",
		},
		{
			Name:      "permissive-whitelist",
			CapAdd:    []string{"net_admin", "mknod"},
			Whitelist: "all",
		},
		{
			Name:      "permissive-whitelist-add-all",
			CapAdd:    []string{"all"},
			Whitelist: "all",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newTestDockerClient(t)
			task, cfg, ports := dockerTask(t)
			defer freeport.Return(ports)

			if len(tc.CapAdd) > 0 {
				cfg.CapAdd = tc.CapAdd
			}
			if len(tc.CapDrop) > 0 {
				cfg.CapDrop = tc.CapDrop
			}
			require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

			d := dockerDriverHarness(t, nil)
			dockerDriver, ok := d.Impl().(*Driver)
			require.True(t, ok)
			if tc.Whitelist != "" {
				dockerDriver.config.AllowCaps = strings.Split(tc.Whitelist, ",")
			}

			cleanup := d.MkAllocDir(task, true)
			defer cleanup()
			copyImage(t, task.TaskDir(), "busybox.tar")

			_, _, err := d.StartTask(task)
			defer d.DestroyTask(task.ID, true)
			if err == nil && tc.StartError != "" {
				t.Fatalf("Expected error in start: %v", tc.StartError)
			} else if err != nil {
				if tc.StartError == "" {
					require.NoError(t, err)
				} else {
					require.Contains(t, err.Error(), tc.StartError)
				}
				return
			}

			handle, ok := dockerDriver.tasks.Get(task.ID)
			require.True(t, ok)

			require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

			container, err := client.ContainerInspect(context.TODO(), handle.containerID)
			require.NoError(t, err)

			require.Exactly(t, tc.CapAdd, container.HostConfig.CapAdd)
			require.Exactly(t, tc.CapDrop, container.HostConfig.CapDrop)
		})
	}
}

func TestDockerDriver_DNS(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.DNSServers = []string{"8.8.8.8", "8.8.4.4"}
	cfg.DNSSearchDomains = []string{"example.com", "example.org", "example.net"}
	cfg.DNSOptions = []string{"ndots:1"}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()

	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)

	require.Exactly(t, cfg.DNSServers, container.HostConfig.DNS)
	require.Exactly(t, cfg.DNSSearchDomains, container.HostConfig.DNSSearch)
	require.Exactly(t, cfg.DNSOptions, container.HostConfig.DNSOptions)
}

func TestDockerDriver_MACAddress(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}

	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.MacAddress = "00:16:3e:00:00:00"
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)

	require.Equal(t, cfg.MacAddress, container.NetworkSettings.MacAddress)
}

func TestDockerDriver_WorkDir(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}

	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.WorkDir = "/some/path"
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)
	require.Equal(t, cfg.WorkDir, filepath.ToSlash(container.Config.WorkingDir))
}

func TestDockerDriver_PortsNoMap(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, _, ports := dockerTask(t)
	defer freeport.Return(ports)
	res := ports[0]
	dyn := ports[1]

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)

	// Verify that the correct ports are EXPOSED
	expectedExposedPorts := nat.PortSet(map[nat.Port]struct{}{
		nat.Port(fmt.Sprintf("%d/tcp", res)): {},
		nat.Port(fmt.Sprintf("%d/udp", res)): {},
		nat.Port(fmt.Sprintf("%d/tcp", dyn)): {},
		nat.Port(fmt.Sprintf("%d/udp", dyn)): {},
	})

	require.Exactly(t, expectedExposedPorts, container.Config.ExposedPorts)

	hostIP := "127.0.0.1"

	// Verify that the correct ports are FORWARDED
	expectedPortBindings := nat.PortMap(map[nat.Port][]nat.PortBinding{
		nat.Port(fmt.Sprintf("%d/tcp", res)): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port(fmt.Sprintf("%d/udp", res)): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port(fmt.Sprintf("%d/tcp", dyn)): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
		nat.Port(fmt.Sprintf("%d/udp", dyn)): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
	})

	require.Exactly(t, expectedPortBindings, container.HostConfig.PortBindings)
}

func TestDockerDriver_PortsMapping(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	res := ports[0]
	dyn := ports[1]
	cfg.PortMap = map[string]int{
		"main":  8080,
		"REDIS": 6379,
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	container, err := client.ContainerInspect(context.TODO(), handle.containerID)
	require.NoError(t, err)

	// Verify that the port environment variables are set
	require.Contains(t, container.Config.Env, "NOMAD_PORT_main=8080")
	require.Contains(t, container.Config.Env, "NOMAD_PORT_REDIS=6379")

	// Verify that the correct ports are EXPOSED
	expectedExposedPorts := nat.PortSet(map[nat.Port]struct{}{
		nat.Port("8080/tcp"): {},
		nat.Port("8080/udp"): {},
		nat.Port("6379/tcp"): {},
		nat.Port("6379/udp"): {},
	})

	require.Exactly(t, expectedExposedPorts, container.Config.ExposedPorts)

	hostIP := "127.0.0.1"

	// Verify that the correct ports are FORWARDED
	expectedPortBindings := nat.PortMap(map[nat.Port][]nat.PortBinding{
		nat.Port("8080/tcp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port("8080/udp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port("6379/tcp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
		nat.Port("6379/udp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
	})

	require.Exactly(t, expectedPortBindings, container.HostConfig.PortBindings)
}

func TestDockerDriver_CreateContainerConfig_PortsMapping(t *testing.T) {
	t.Parallel()

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	res := ports[0]
	dyn := ports[1]
	cfg.PortMap = map[string]int{
		"main":  8080,
		"REDIS": 6379,
	}
	dh := dockerDriverHarness(t, nil)
	driver := dh.Impl().(*Driver)

	c, err := driver.containerCreateConfig(task, cfg, "org/repo:0.1")
	require.NoError(t, err)

	require.Equal(t, "org/repo:0.1", c.Config.Image)
	require.Contains(t, c.Config.Env, "NOMAD_PORT_main=8080")
	require.Contains(t, c.Config.Env, "NOMAD_PORT_REDIS=6379")

	// Verify that the correct ports are FORWARDED
	hostIP := "127.0.0.1"

	expectedPortBindings := nat.PortMap(map[nat.Port][]nat.PortBinding{
		nat.Port("8080/tcp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port("8080/udp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", res)}},
		nat.Port("6379/tcp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
		nat.Port("6379/udp"): {{HostIP: hostIP, HostPort: fmt.Sprintf("%d", dyn)}},
	})

	require.Exactly(t, expectedPortBindings, c.HostConfig.PortBindings)
}

func TestDockerDriver_CleanupContainer(t *testing.T) {
	if !tu.IsCI() {
		t.Parallel()
	}
	tu.DockerCompatible(t)

	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	cfg.Command = "echo"
	cfg.Args = []string{"hello"}
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()

	waitCh, err := d.WaitTask(context.Background(), task.ID)
	require.NoError(t, err)

	select {
	case res := <-waitCh:
		if !res.Successful() {
			t.Fatalf("err: %v", res)
		}

		err = d.DestroyTask(task.ID, false)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		// Ensure that the container isn't present
		_, err := client.ContainerInspect(context.TODO(), handle.containerID)
		if err == nil {
			t.Fatalf("expected to not get container")
		}

	case <-time.After(time.Duration(tu.TestMultiplier()*5) * time.Second):
		t.Fatalf("timeout")
	}
}

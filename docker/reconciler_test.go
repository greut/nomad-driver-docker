package docker

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	//docker "github.com/docker/docker/client"
	tu "github.com/greut/nomad-driver-docker/testutil"
	"github.com/hashicorp/nomad/helper/freeport"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/stretchr/testify/require"
)

func fakeContainerList(t *testing.T) (nomadContainer, nonNomadContainer types.Container) {
	path := "../test-resources/reconciler_containers_list.json"

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	var sampleContainerList []types.Container
	err = json.NewDecoder(f).Decode(&sampleContainerList)
	if err != nil {
		t.Fatalf("failed to decode container list: %v", err)
	}

	return sampleContainerList[0], sampleContainerList[1]
}

func Test_HasMount(t *testing.T) {
	nomadContainer, nonNomadContainer := fakeContainerList(t)

	require.True(t, hasMount(nomadContainer, "/alloc"))
	require.True(t, hasMount(nomadContainer, "/data"))
	require.True(t, hasMount(nomadContainer, "/secrets"))
	require.False(t, hasMount(nomadContainer, "/random"))

	require.False(t, hasMount(nonNomadContainer, "/alloc"))
	require.False(t, hasMount(nonNomadContainer, "/data"))
	require.False(t, hasMount(nonNomadContainer, "/secrets"))
	require.False(t, hasMount(nonNomadContainer, "/random"))
}

func Test_HasNomadName(t *testing.T) {
	nomadContainer, nonNomadContainer := fakeContainerList(t)

	require.True(t, hasNomadName(nomadContainer))
	require.False(t, hasNomadName(nonNomadContainer))
}

// TestDanglingContainerRemoval asserts containers without corresponding tasks
// are removed after the creation grace period.
func TestDanglingContainerRemoval(t *testing.T) {
	tu.DockerCompatible(t)

	// start two containers: one tracked nomad container, and one unrelated container
	task, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)
	require.NoError(t, task.EncodeConcreteDriverConfig(cfg))

	client, d, handle, cleanup := dockerSetup(t, task)
	defer cleanup()
	require.NoError(t, d.WaitUntilStarted(task.ID, 5*time.Second))

	nonNomadContainer, err := client.ContainerCreate(
		context.TODO(),
		&container.Config{
			Image: cfg.Image,
			Cmd:   append([]string{cfg.Command}, cfg.Args...),
		},
		nil,
		nil,
		"mytest-image-"+uuid.Generate(),
	)
	require.NoError(t, err)
	defer client.ContainerRemove(
		context.TODO(),
		nonNomadContainer.ID,
		types.ContainerRemoveOptions{
			Force: true,
		},
	)

	err = client.ContainerStart(context.TODO(), nonNomadContainer.ID, types.ContainerStartOptions{})
	require.NoError(t, err)

	untrackedNomadContainer, err := client.ContainerCreate(
		context.TODO(),
		&container.Config{
			Image: cfg.Image,
			Cmd:   append([]string{cfg.Command}, cfg.Args...),
			Labels: map[string]string{
				dockerLabelAllocID: uuid.Generate(),
			},
		},
		nil,
		nil,
		"mytest-image-"+uuid.Generate(),
	)
	require.NoError(t, err)
	defer client.ContainerRemove(
		context.TODO(),
		untrackedNomadContainer.ID,
		types.ContainerRemoveOptions{
			Force: true,
		},
	)

	err = client.ContainerStart(context.TODO(), untrackedNomadContainer.ID, types.ContainerStartOptions{})
	require.NoError(t, err)

	dd := d.Impl().(*Driver)

	reconciler := newReconciler(dd)
	trackedContainers := map[string]bool{handle.containerID: true}

	tf := reconciler.trackedContainers()
	require.Contains(t, tf, handle.containerID)
	require.NotContains(t, tf, untrackedNomadContainer)
	require.NotContains(t, tf, nonNomadContainer.ID)

	// assert tracked containers should never be untracked
	untracked, err := reconciler.untrackedContainers(trackedContainers, time.Now())
	require.NoError(t, err)
	require.NotContains(t, untracked, handle.containerID)
	require.NotContains(t, untracked, nonNomadContainer.ID)
	require.Contains(t, untracked, untrackedNomadContainer.ID)

	// assert we recognize nomad containers with appropriate cutoff
	untracked, err = reconciler.untrackedContainers(map[string]bool{}, time.Now())
	require.NoError(t, err)
	require.Contains(t, untracked, handle.containerID)
	require.Contains(t, untracked, untrackedNomadContainer.ID)
	require.NotContains(t, untracked, nonNomadContainer.ID)

	// but ignore if creation happened before cutoff
	untracked, err = reconciler.untrackedContainers(map[string]bool{}, time.Now().Add(-1*time.Minute))
	require.NoError(t, err)
	require.NotContains(t, untracked, handle.containerID)
	require.NotContains(t, untracked, untrackedNomadContainer.ID)
	require.NotContains(t, untracked, nonNomadContainer.ID)

	// a full integration tests to assert that containers are removed
	prestineDriver := dockerDriverHarness(t, nil).Impl().(*Driver)
	prestineDriver.config.GC.DanglingContainers = ContainerGCConfig{
		Enabled:               true,
		periodDuration:        1 * time.Second,
		creationGraceDuration: 0 * time.Second,
	}
	nReconciler := newReconciler(prestineDriver)

	require.NoError(t, nReconciler.removeDanglingContainersIteration())

	_, err = client.ContainerInspect(context.TODO(), nonNomadContainer.ID)
	require.NoError(t, err)

	_, err = client.ContainerInspect(context.TODO(), handle.containerID)
	require.Error(t, err)
	//require.Contains(t, err.Error(), NoSuchContainerError)

	_, err = client.ContainerInspect(context.TODO(), untrackedNomadContainer.ID)
	require.Error(t, err)
	//require.Contains(t, err.Error(), NoSuchContainerError)
}

/*
// TestDanglingContainerRemoval_Stopped asserts stopped containers without
// corresponding tasks are not removed even if after creation grace period.
func TestDanglingContainerRemoval_Stopped(t *testing.T) {
	testutil.DockerCompatible(t)

	_, cfg, ports := dockerTask(t)
	defer freeport.Return(ports)

	client := newTestDockerClient(t)
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: "mytest-image-" + uuid.Generate(),
		Config: &docker.Config{
			Image: cfg.Image,
			Cmd:   append([]string{cfg.Command}, cfg.Args...),
			Labels: map[string]string{
				dockerLabelAllocID: uuid.Generate(),
			},
		},
	})
	require.NoError(t, err)
	defer client.RemoveContainer(docker.RemoveContainerOptions{
		ID:    container.ID,
		Force: true,
	})

	err = client.StartContainer(container.ID, nil)
	require.NoError(t, err)

	err = client.StopContainer(container.ID, 60)
	require.NoError(t, err)

	dd := dockerDriverHarness(t, nil).Impl().(*Driver)
	reconciler := newReconciler(dd)

	// assert nomad container is tracked, and we ignore stopped one
	tf := reconciler.trackedContainers()
	require.NotContains(t, tf, container.ID)

	untracked, err := reconciler.untrackedContainers(map[string]bool{}, time.Now())
	require.NoError(t, err)
	require.NotContains(t, untracked, container.ID)

	// if we start container again, it'll be marked as untracked
	require.NoError(t, client.StartContainer(container.ID, nil))

	untracked, err = reconciler.untrackedContainers(map[string]bool{}, time.Now())
	require.NoError(t, err)
	require.Contains(t, untracked, container.ID)
}
*/

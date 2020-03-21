package docker

import "fmt"

func newTaskConfig(variant string, command []string) *TaskConfig {
	image := "busybox:1.29.3"
	if variant != "" {
		image = fmt.Sprintf("%s-%s", image, variant)
	}

	return &TaskConfig{
		Image:   image,
		Command: command[0],
		Args:    command[1:],
	}
}

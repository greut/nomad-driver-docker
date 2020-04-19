package docker

import "fmt"

func newTaskConfig(variant string, command []string) *TaskConfig {
	image := "busybox:1.29.3"
	load := "busybox.tar"

	if variant != "" {
		image = fmt.Sprintf("%s-%s", image, variant)
		load = fmt.Sprintf("busybox_%s.tar", variant)
	}

	return &TaskConfig{
		Image:     image,
		LoadImage: load,
		Command:   command[0],
		Args:      command[1:],
	}
}

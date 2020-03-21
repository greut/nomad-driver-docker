package docker

import (
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
)

type TaskConfig struct {
	Image   string             `codec:"image"`
	Args    []string           `codec:"args"`
	Command string             `codec:"command"`
	Labels  hclutils.MapStrStr `codec:"labels"`
	PortMap hclutils.MapStrInt `codec:"port_map"`
}

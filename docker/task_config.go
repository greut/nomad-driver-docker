package docker

import (
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

var (
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":   hclspec.NewAttr("image", "string", true),
		"command": hclspec.NewAttr("command", "string", true),
		"args":    hclspec.NewAttr("args", "list(string)", true),
		"labels":  hclspec.NewAttr("labels", "list(map(string))", false),
	})
)

type TaskConfig struct {
	Image   string             `codec:"image"`
	Command string             `codec:"command"`
	Args    []string           `codec:"args"`
	Labels  hclutils.MapStrStr `codec:"labels"`
	PortMap hclutils.MapStrInt `codec:"port_map"`
}

package docker

import (
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

var (
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":        hclspec.NewAttr("image", "string", true),
		"command":      hclspec.NewAttr("command", "string", true),
		"args":         hclspec.NewAttr("args", "list(string)", true),
		"force_pull":   hclspec.NewAttr("force_pull", "bool", false),
		"labels":       hclspec.NewAttr("labels", "list(map(string))", false),
		"load":         hclspec.NewAttr("load", "string", false),
		"security_opt": hclspec.NewAttr("security_opt", "list(string)", false),
		"storage_opt":  hclspec.NewBlockAttrs("storage_opt", "string", false),
	})
)

type TaskConfig struct {
	Image       string             `codec:"image"`
	Command     string             `codec:"command"`
	Args        []string           `codec:"args"`
	Labels      hclutils.MapStrStr `codec:"labels"`
	PortMap     hclutils.MapStrInt `codec:"port_map"`
	LoadImage   string             `codec:"load"`
	ForcePull   bool               `codec:"force_pull"`
	SecurityOpt []string           `codec:"security_opt"`
	StorageOpt  map[string]string  `codec:"storage_opt"`
}

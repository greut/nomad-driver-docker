package docker

import (
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

var (
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":              hclspec.NewAttr("image", "string", true),
		"command":            hclspec.NewAttr("command", "string", true),
		"args":               hclspec.NewAttr("args", "list(string)", true),
		"dns_search_domains": hclspec.NewAttr("dns_search_domains", "list(string)", false),
		"dns_options":        hclspec.NewAttr("dns_options", "list(string)", false),
		"dns_servers":        hclspec.NewAttr("dns_servers", "list(string)", false),
		"force_pull":         hclspec.NewAttr("force_pull", "bool", false),
		"labels":             hclspec.NewAttr("labels", "list(map(string))", false),
		"load":               hclspec.NewAttr("load", "string", false),
		"logging": hclspec.NewBlock("logging", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"type":   hclspec.NewAttr("type", "string", false),
			"driver": hclspec.NewAttr("driver", "string", false),
			"config": hclspec.NewAttr("config", "list(map(string))", false),
		})),
		"mac_address":  hclspec.NewAttr("mac_address", "string", false),
		"security_opt": hclspec.NewAttr("security_opt", "list(string)", false),
		"storage_opt":  hclspec.NewBlockAttrs("storage_opt", "string", false),
	})
)

type TaskConfig struct {
	Args             []string           `codec:"args"`
	CapAdd           []string           `codec:"cap_add"`
	CapDrop          []string           `codec:"cap_drop"`
	Command          string             `codec:"command"`
	DNSOptions       []string           `codec:"dns_options"`
	DNSSearchDomains []string           `codec:"dns_search_domains"`
	DNSServers       []string           `codec:"dns_servers"`
	ForcePull        bool               `codec:"force_pull"`
	Image            string             `codec:"image"`
	Labels           hclutils.MapStrStr `codec:"labels"`
	LoadImage        string             `codec:"load"`
	Logging          DockerLogging      `codec:"logging"`
	MacAddress       string             `codec:"mac_address"`
	PortMap          hclutils.MapStrInt `codec:"port_map"`
	SecurityOpt      []string           `codec:"security_opt"`
	StorageOpt       map[string]string  `codec:"storage_opt"`
}

type DockerLogging struct {
	Type   string             `codec:"type"`
	Driver string             `codec:"driver"`
	Config hclutils.MapStrStr `codec:"config"`
}

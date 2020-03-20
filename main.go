package main

import (
	"github.com/greut/nomad-driver-docker/docker"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	plugins.Serve(factory)
}

func factory(log hclog.Logger) interface{} {
	return docker.NewDriver(log)
}

# Nomad driver for Docker

Requires Noma(d): [a Nomad without Docker](https://github.com/greut/nomad/tree/no-docker).

## Goals

The Nomad project seems very hard to maintain as some dependencies are conflicting with each other. Docker appears to be the biggest cause of this state of affair.

The bundle docker provider is built against [fsouza/go-dockerclient](https://github.com/fsouza/go-dockerclient) which predates the [official Docker client](https://pkg.go.dev/github.com/docker/docker/client?tab=doc) (do not *use* the online documentation but a local [godoc](https://github.com/golang/tools/tree/master/godoc) instance).

### Non-goals

- Windows support
- GPU support

## Usage

```hcl
plugin_dir = "/.../nomad-driver-docker/"

plugin "nomad-driver-docker" {}
```

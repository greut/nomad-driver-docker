# Nomad driver for Docker

[![greut/nomad-driver-docker](https://circleci.com/gh/greut/nomad-driver-docker.svg?style=shield)](https://app.circleci.com/pipelines/github/greut/nomad-driver-docker)
[![codecov](https://codecov.io/gh/greut/nomad-driver-docker/branch/master/graph/badge.svg)](https://codecov.io/gh/greut/nomad-driver-docker)

Requires Noma(d): [a Nomad without Docker](https://github.com/greut/nomad/tree/no-docker).

## Goals

The Nomad project seems very hard to maintain as some dependencies are conflicting with each other. Docker appears to be the biggest cause of this state of affair. This projects experiments a standalone driver for Docker.

The bundled docker provider is built against [fsouza/go-dockerclient](https://github.com/fsouza/go-dockerclient) which predates the [official Docker client](https://pkg.go.dev/github.com/docker/docker/client?tab=doc) (do not *use* the online documentation but a local [godoc](https://github.com/golang/tools/tree/master/godoc) instance).

### Non-goals

- Windows support

## Usage

```hcl
plugin_dir = "/.../nomad-driver-docker/"

plugin "nomad-driver-docker" {}
```

# Nomad driver for Docker

Requires Noma(d): [a Nomad without Docker](https://github.com/greut/nomad/tree/no-docker).

## Goals

The Nomad project seems very hard to maintain as some dependencies are conflicting with each other. Docker appears to be the biggest cause of this state of affair.

## Usage

```hcl
plugin_dir = "/.../nomad-driver-docker/"

plugin "nomad-driver-docker" {}
```

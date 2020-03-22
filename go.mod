module github.com/greut/nomad-driver-docker

go 1.14

replace github.com/docker/docker => github.com/docker/engine v1.4.2-0.20200309214505-aa6a9891b09c

// Noma(d): no-docker-msgpack
replace github.com/hashicorp/nomad => github.com/greut/nomad v0.10.3-0.20200322081030-33d55b99e834

// https://github.com/hashicorp/nomad/pull/7378
replace github.com/hashicorp/go-msgpack => github.com/hashicorp/go-msgpack v0.0.0-20191101193846-96ddbed8d05b

// sirupsen renaming
replace github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc7

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/LK4D4/joincontext v0.0.0-20171026170139-1724345da6d5 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/NVIDIA/gpu-monitoring-tools v0.0.0-20200116003318-021662a21098 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/aws/aws-sdk-go v1.29.29 // indirect
	github.com/checkpoint-restore/go-criu v0.0.0-20191125063657-fcdcd07065c5 // indirect
	github.com/containerd/console v0.0.0-20191219165238-8375c3424e4d // indirect
	github.com/containerd/containerd v1.3.3 // indirect
	github.com/containerd/go-cni v0.0.0-20200107172653-c154a49e2c75 // indirect
	github.com/containernetworking/plugins v0.8.5 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.3.5 // indirect
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/hashicorp/consul v1.7.2 // indirect
	github.com/hashicorp/consul-template v0.24.1
	github.com/hashicorp/go-envparse v0.0.0-20190703193109-150b3a2a4611 // indirect
	github.com/hashicorp/go-getter v1.4.1 // indirect
	github.com/hashicorp/go-hclog v0.12.1
	github.com/hashicorp/go-plugin v1.1.0 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl2 v0.0.0-20191002203319-fb75b3253c80 // indirect
	github.com/hashicorp/nomad v0.10.4
	github.com/hashicorp/nomad/api v0.0.0-20200320225748-88bab87afb5e // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000 // indirect
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/opencontainers/selinux v1.4.0 // indirect
	github.com/seccomp/libseccomp-golang v0.9.1 // indirect
	github.com/shirou/gopsutil v2.20.2+incompatible // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2 // indirect
	github.com/zclconf/go-cty v1.3.1 // indirect
	golang.org/x/crypto v0.0.0-20200317142112-1b76d66859c6 // indirect
	golang.org/x/net v0.0.0-20200301022130-244492dfa37a // indirect
	google.golang.org/grpc v1.28.0 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

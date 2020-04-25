module github.com/greut/nomad-driver-docker

go 1.14

// no-docker
replace github.com/hashicorp/nomad => github.com/greut/nomad v0.10.3-0.20200425071612-e406179f122a

// https://github.com/moby/moby/releases/tag/v19.03.8
replace github.com/docker/docker => github.com/moby/moby v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible

// https://github.com/docker/cli/releases/tag/v19.03.8
replace github.com/docker/cli => github.com/docker/cli v0.0.0-20200303215952-eb310fca4956

// sirupsen renaming
replace github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc7

require (
	cloud.google.com/go v0.56.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/DataDog/datadog-go v3.5.0+incompatible // indirect
	github.com/LK4D4/joincontext v0.0.0-20171026170139-1724345da6d5 // indirect
	github.com/Microsoft/go-winio v0.4.15-0.20200113171025-3fe6c5262873 // indirect
	github.com/NVIDIA/gpu-monitoring-tools v0.0.0-20200418030555-757a1b5553f4 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2 // indirect
	github.com/armon/go-metrics v0.3.3 // indirect
	github.com/aws/aws-sdk-go v1.30.9 // indirect
	github.com/checkpoint-restore/go-criu v0.0.0-20191125063657-fcdcd07065c5 // indirect
	github.com/circonus-labs/circonusllhist v0.1.4 // indirect
	github.com/container-storage-interface/spec v1.2.0 // indirect
	github.com/containerd/console v1.0.0 // indirect
	github.com/containerd/containerd v1.3.4 // indirect
	github.com/containerd/go-cni v0.0.0-20200107172653-c154a49e2c75 // indirect
	github.com/containernetworking/plugins v0.8.5 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.4.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0 // indirect
	github.com/hashicorp/consul v1.7.2 // indirect
	github.com/hashicorp/consul-template v0.24.1
	github.com/hashicorp/go-envparse v0.0.0-20200406174449-d9cfd743a15e // indirect
	github.com/hashicorp/go-getter v1.4.1 // indirect
	github.com/hashicorp/go-hclog v0.12.2
	github.com/hashicorp/go-immutable-radix v1.2.0 // indirect
	github.com/hashicorp/go-msgpack v1.1.5 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/hashicorp/go-plugin v1.2.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl2 v0.0.0-20191002203319-fb75b3253c80 // indirect
	github.com/hashicorp/nomad v0.11.0
	github.com/hashicorp/nomad/api v0.0.0-20200417195316-71744bcc2d91 // indirect
	github.com/hashicorp/serf v0.9.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20190923154419-df201c70410d // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/kr/pty v1.1.8 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mattn/go-shellwords v1.0.10 // indirect
	github.com/miekg/dns v1.1.29 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.0 // indirect
	github.com/mitchellh/mapstructure v1.2.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2 // indirect
	github.com/opencontainers/selinux v1.5.1 // indirect
	github.com/pierrec/lz4 v2.5.1+incompatible // indirect
	github.com/prometheus/client_golang v1.5.1 // indirect
	github.com/prometheus/procfs v0.0.11 // indirect
	github.com/seccomp/libseccomp-golang v0.9.1 // indirect
	github.com/shirou/gopsutil v2.20.3+incompatible // indirect
	github.com/sirupsen/logrus v1.5.0 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2 // indirect
	github.com/tv42/httpunix v0.0.0-20191220191345-2ba4b9c3382c // indirect
	github.com/ulikunitz/xz v0.5.7 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/zclconf/go-cty v1.4.0 // indirect
	golang.org/x/crypto v0.0.0-20200414173820-0848c9571904 // indirect
	golang.org/x/sys v0.0.0-20200413165638-669c56c373c4 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	golang.org/x/tools v0.0.0-20200417140056-c07e33ef3290 // indirect
	google.golang.org/api v0.21.0 // indirect
	google.golang.org/genproto v0.0.0-20200417142217-fb6d0575620b // indirect
	google.golang.org/grpc v1.28.1 // indirect
	gopkg.in/square/go-jose.v2 v2.5.0 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

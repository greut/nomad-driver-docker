package docker

import (
	"strconv"
	"strings"
	"time"
)

type DriverConfig struct {
	Endpoint                    string        `codec:"endpoint"`
	GC                          GCConfig      `codec:"gc"`
	AllowCaps                   []string      `codec:"allow_caps"`
	GPURuntimeName              string        `codec:"nvidia_runtime"`
	PullActivityTimeout         string        `codec:"pull_activity_timeout"`
	pullActivityTimeoutDuration time.Duration `codec:"-"`
}

const (
	danglingContainersCreationGraceMinimum = 1 * time.Minute
	pullActivityTimeoutMinimum             = 1 * time.Minute

	// dockerBasicCaps is comma-separated list of Linux capabilities that are
	// allowed by docker by default, as documented in
	// https://docs.docker.com/engine/reference/run/#block-io-bandwidth-blkio-constraint
	dockerBasicCaps = "CHOWN,DAC_OVERRIDE,FSETID,FOWNER,MKNOD,NET_RAW,SETGID," +
		"SETUID,SETFCAP,SETPCAP,NET_BIND_SERVICE,SYS_CHROOT,KILL,AUDIT_WRITE"
)

type GCConfig struct {
	Image              bool              `codec:"image"`
	ImageDelay         string            `codec:"image_delay"`
	imageDelayDuration time.Duration     `codec:"-"`
	Container          bool              `codec:"container"`
	DanglingContainers ContainerGCConfig `codec:"dangling_containers"`
}

// ContainerGCConfig controls the behavior of the GC reconcilier to detects
// dangling nomad containers that aren't tracked due to docker/nomad bugs.
type ContainerGCConfig struct {
	// Enabled controls whether the container reconciler is enabled
	Enabled bool `codec:"enabled"`

	// DryRun indicates that the reconciler should log unexpectedly running containers
	// if found without actually killing them
	DryRun bool `codec:"dry_run"`

	// Period controls the frequency of scanning containers
	Period         string        `codec:"period"`
	periodDuration time.Duration `codec:"-"`

	// CreationGrace is the duration allowed for newly created container
	// to live without being registered as a running task in nomad.
	// A container is treated as leaked if it lived more than a grace duration
	// and haven't been registered in tasks.
	CreationGrace         string        `codec:"creation_grace"`
	creationGraceDuration time.Duration `codec:"-"`
}

func PluginLoader(opts map[string]string) (map[string]interface{}, error) {
	conf := map[string]interface{}{}
	if v, ok := opts["docker.endpoint"]; ok {
		conf["endpoint"] = v
	}

	// dockerd auth
	authConf := map[string]interface{}{}
	if v, ok := opts["docker.auth.config"]; ok {
		authConf["config"] = v
	}
	if v, ok := opts["docker.auth.helper"]; ok {
		authConf["helper"] = v
	}
	conf["auth"] = authConf

	// dockerd tls
	if _, ok := opts["docker.tls.cert"]; ok {
		conf["tls"] = map[string]interface{}{
			"cert": opts["docker.tls.cert"],
			"key":  opts["docker.tls.key"],
			"ca":   opts["docker.tls.ca"],
		}
	}

	// garbage collection
	gcConf := map[string]interface{}{}
	if v, err := strconv.ParseBool(opts["docker.cleanup.image"]); err == nil {
		gcConf["image"] = v
	}
	if v, ok := opts["docker.cleanup.image.delay"]; ok {
		gcConf["image_delay"] = v
	}
	if v, err := strconv.ParseBool(opts["docker.cleanup.container"]); err == nil {
		gcConf["container"] = v
	}
	conf["gc"] = gcConf

	// volume options
	volConf := map[string]interface{}{}
	if v, err := strconv.ParseBool(opts["docker.volumes.enabled"]); err == nil {
		volConf["enabled"] = v
	}
	if v, ok := opts["docker.volumes.selinuxlabel"]; ok {
		volConf["selinuxlabel"] = v
	}
	conf["volumes"] = volConf

	// capabilities
	if v, ok := opts["docker.caps.whitelist"]; ok {
		conf["allow_caps"] = strings.Split(v, ",")
	}

	// privileged containers
	if v, err := strconv.ParseBool(opts["docker.privileged.enabled"]); err == nil {
		conf["allow_privileged"] = v
	}

	// nvidia_runtime
	if v, ok := opts["docker.nvidia_runtime"]; ok {
		conf["nvidia_runtime"] = v
	}

	return conf, nil
}

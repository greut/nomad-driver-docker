GOFILES:=$(shell git ls-files "*.go")

plugins/nomad-driver-docker: $(GOFILES)
	go build -o $@

.PHONY: test
test: plugins/nomad-driver-docker
	go test -v ./docker/...

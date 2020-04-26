GOFILES:=$(shell git ls-files "*.go")

plugins/nomad-driver-docker: $(GOFILES)
	go build -o $@

.PHONY: test
test: plugins/nomad-driver-docker
	gotestsum -f dots -- \
		-cover -coverprofile cover.txt \
		-timeout=15m -v ./docker/...

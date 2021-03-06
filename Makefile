GOFILES:=$(shell git ls-files "*.go")

plugins/nomad-driver-docker: $(GOFILES)
	go build -o $@

.PHONY: test
test: plugins/nomad-driver-docker
	gotestsum -f dots -- \
		-covermode atomic -coverprofile coverage.txt \
		-timeout=15m -v ./docker/...

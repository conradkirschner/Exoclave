# Everything runs in Docker so the toolchain is the same everywhere.
# `make check` is exactly what CI runs.

IMAGE ?= exoclave
DOCKERFILE := docker/Dockerfile

.PHONY: help build check test fmt lint shell run clean

help:
	@echo "build   - build the release image ($(IMAGE))"
	@echo "check   - fmt + clippy + tests, in the build image"
	@echo "shell   - interactive shell in the build environment"
	@echo "run     - run the CLI (ARGS=\"scan --help\")"
	@echo "clean   - remove build cache and images"

build:
	docker build -f $(DOCKERFILE) --target runtime -t $(IMAGE):latest .

# Fails the build if formatting, lints or tests fail. No artifacts produced.
check:
	docker build -f $(DOCKERFILE) --target test -t $(IMAGE):test .

test: check

shell:
	docker build -f $(DOCKERFILE) --target builder -t $(IMAGE):builder .
	docker run --rm -it -v "$(CURDIR)":/src -w /src $(IMAGE):builder sh

# Talks to the adb server on the host, so no USB passthrough is needed.
# Start it first with:  adb -a -P 5037 nodaemon server
ARGS ?= --help
run: build
	docker run --rm -it \
		-e ADB_SERVER_SOCKET=tcp:host.docker.internal:5037 \
		--add-host=host.docker.internal:host-gateway \
		-v "$(CURDIR)/reports":/work \
		$(IMAGE):latest $(ARGS)

clean:
	-docker image rm $(IMAGE):latest $(IMAGE):test $(IMAGE):builder
	docker builder prune -f

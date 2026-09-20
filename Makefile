# Everything runs in Docker so the toolchain is the same everywhere.
# `make check` is exactly what CI runs.

IMAGE ?= exoclave
DOCKERFILE := docker/Dockerfile

.PHONY: help build check test demo windows shell run clean

help:
	@echo "build   - build the release image ($(IMAGE))"
	@echo "check   - fmt + clippy + tests, in the build image"
	@echo "demo    - run the pipeline against a fixture device, no phone needed"
	@echo "windows - cross-compile dist/exoclave.exe for Windows"
	@echo "shell   - interactive shell in the build environment"
	@echo "run     - run the CLI (ARGS=\"scan --help\")"
	@echo "clean   - remove build cache and images"

# No device required: the real detectors against a fixture.
SCENARIO ?= compromised
demo: build
	docker run --rm $(IMAGE):latest demo $(SCENARIO)

# Produces ./dist/exoclave.exe — run it natively against your own adb.
windows:
	docker build -f $(DOCKERFILE) --target windows -o type=local,dest=dist .
	@echo "built: dist/exoclave.exe"

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

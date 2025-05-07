# Makefile
# This file is used to compile various parts of the Brane infrastructure and tooling
#
#

CENTRAL_SERVICES := brane-api brane-drv brane-plr
WORKER_SERVICES := brane-job brane-reg brane-chk
SHARED_SERVICES := brane-prx

BINARY_TARGETS := brane-ctl brane-cli # brane-let   <-- True but we need special treatment (always build as Linux, never as Darwin)

BUILD_DIR := target
IMAGE_DIR := $(BUILD_DIR)/release
BIN_DIR := $(BUILD_DIR)/release

WORKSPACE_MEMBERS := $(sort $(CENTRAL_SERVICES) $(WORKER_SERVICES) $(SHARED_SERVICES))

BUILDX_ARGS := build 
CARGO_BUILD_ARGS := --release
IMAGE_DOCKER_FILE := ./Dockerfile.rls

# Find the architecture of this machine
ifndef RUST_ARCH
	SARCH := $(shell uname -m)
	ifeq ($(SARCH),amd64)
		RUST_ARCH := x86_64
	else ifeq ($(SARCH),x86_64)
		RUST_ARCH := x86_64
	else ifeq ($(SARCH),x86-64)
		RUST_ARCH := x86_64
	else ifeq ($(SARCH),aarch64)
		RUST_ARCH := aarch64
	else ifeq ($(SARCH),arm64)
		RUST_ARCH := aarch64
	else
		RUST_ARCH := UNKNOWN
	endif
endif

# Find the group ID of the Docker socket
# This is necessary to give `brane-job` the right permissions for accessing it. I know.
SOCK_GID := $(id -g)
ifeq ($(shell uname),Darwin)
	SOCK_GID := $(shell stat -f '%g' /var/run/docker.sock)
else ifeq ($(shell uname),Linux)
	SOCK_GID := $(shell id -g "$(shell stat -C '%G' /var/run/docker.sock)")
endif

# The binaries we can build in either debug or release mode
ifeq ($(PROFILE),debug)
	CARGO_BUILD_ARGS := $(filter-out --release,$(CARGO_BUILD_ARGS))
	IMAGE_DOCKER_FILE := ./Dockerfile.dev
	IMAGE_DIR := $(BUILD_DIR)/debug
	BIN_DIR := $(BUILD_DIR)/debug
endif

# Sometimes docker buildx can take a cached version while there are actually some changes. With
# `FORCE` you can make sure it is rebuild anyway.
ifeq ($(FORCE),1)
	BUILDX_ARGS += --no-cache
endif

# Add a way to select what buildx builder to use
ifdef BUILDX_BUILDER
	BUILDX_ARGS += --builder $(BUILDX_BUILDER)
endif

# Universal targets
.PHONY: all
all: $(WORKSPACE_MEMBERS)

.PHONY: binaries
binaries: $(BINARY_TARGETS)

.PHONY: images
images: $(WORKSPACE_MEMBERS)

.PHONY: worker-images
worker-images: $(WORKER_SERVICES) $(SHARED_SERVICES)

.PHONY: central-images
central-images: $(CENTRAL_SERVICES) $(SHARED_SERVICES)

# Compilation of images
# Building of images relies heavily on docker buildx. This is due to the dynamic linking requirements of Brane
# This way we can compile Brane in a similar/identical environment as we will end up running them.
.PHONY: $(WORKSPACE_MEMBERS)
$(WORKSPACE_MEMBERS): $(IMAGE_DIR)
	@echo "Building $@"
	docker buildx $(BUILDX_ARGS) --output type="docker,dest=$(IMAGE_DIR)/$@.tar" --file $(IMAGE_DOCKER_FILE) --target $@ --build-arg "USERID=$(shell id -u)" --build-arg "SOCK_GROUPID=$(SOCK_GID)" .

# Compilation of binaries
.PHONY: $(BINARY_TARGETS)
brane-let: $(BIN_DIR)
	@echo "Building $@"
	cargo build $(CARGO_BUILD_ARGS) --target $(RUST_ARCH)-unknown-linux-musl --package $@
$(BINARY_TARGETS): $(BIN_DIR)
	@echo "Building $@"
	cargo build $(CARGO_BUILD_ARGS) --package $@

# Compilation of branelet
.PHONY: brane-let-builder
brane-let-builder:
	@echo "Building brane-let builder container"
	docker buildx build --load -t brane-let-builder:latest -f Dockerfile.let --build-arg "USERID=$(shell id -u)" --build-arg "GROUPID=$(shell id -g)" .

.PHONY: brane-let-docker
brane-let-docker: brane-let-builder $(BIN_DIR)
	@echo "Building brane-let in a Docker container"
	docker run -it --rm -v "$(shell pwd)/target/release:/output" brane-let-builder:latest

# Directory creation
# It is important that we flag this directory as a CACHETAG.DIR. Various backup solutions for example will otherwise backup 
# the directory. This might seem nice, but these artifacts can be very large in size and should be reproducible anyway.
.PHONY: $(BUILD_DIR)
$(BUILD_DIR):
	mkdir $(BUILD_DIR) || echo "Directory $(BUILD_DIR) already exists"
	[ -f "$(BUILD_DIR)/CACHEDIR.TAG" ] || echo "Signature: 8a477f597d28d172789f06886806bc55" > "$(BUILD_DIR)/CACHEDIR.TAG"

.PHONY: $(IMAGE_DIR)
$(IMAGE_DIR): $(BUILD_DIR)
	mkdir $(IMAGE_DIR) || echo "Directory $(IMAGE_DIR) already exists"

.PHONY: $(BIN_DIR)
$(BIN_DIR): $(BUILD_DIR)
	mkdir $(BIN_DIR) || echo "Directory $(BIN_DIR) already exists"

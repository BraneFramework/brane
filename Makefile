# Makefile
# This file is used to compile various parts of the Brane infrastructure and tooling
#
#
CENTRAL_SERVICES := brane-api brane-drv brane-plr
WORKER_SERVICES := brane-job brane-reg brane-chk
PROXY_SERVICES :=
SHARED_SERVICES := brane-prx

BINARY_TARGETS := brane-ctl brane-cli brane-let brane-cc

DYNAMIC_LIBRARES := brane-cli-c

BUILD_DIR := target
IMAGE_DIR := $(BUILD_DIR)/debug
BIN_DIR := $(BUILD_DIR)/debug
LIB_DIR := $(BUILD_DIR)/debug

WORKSPACE_MEMBERS := $(sort $(CENTRAL_SERVICES) $(WORKER_SERVICES) $(SHARED_SERVICES))

BUILDX_ARGS := build 
CARGO_BUILD_ARGS := 
IMAGE_DOCKER_FILE := ./Dockerfile.dev

# The binaries we can build in either debug or release mode
ifeq ($(PROFILE),release)
	CARGO_BUILD_ARGS += --release
	IMAGE_DOCKER_FILE := ./Dockerfile.rls
	IMAGE_DIR := $(BUILD_DIR)/release
	BIN_DIR := $(BUILD_DIR)/release
	LIB_DIR := $(BUILD_DIR)/release
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

.PHONY: proxy-images
proxy-images: $(PROXY_SERVICES) $(SHARED_SERVICES)

.PHONY: dynamic-libraries
dynamic-libraries: $(DYNAMIC_LIBRARES)

# Compilation of images
# Building of images relies heavily on docker buildx. This is due to the dynamic linking requirements of Brane
# This way we can compile Brane in a similar/identical environment as we will end up running them.
.PHONY: $(WORKSPACE_MEMBERS)
$(WORKSPACE_MEMBERS): $(IMAGE_DIR)
	@echo "Building $@"
	docker buildx $(BUILDX_ARGS) --output type="docker,dest=$(IMAGE_DIR)/$@.tar" --file $(IMAGE_DOCKER_FILE) --target $@ .

# Compilation of binaries
.PHONY: $(BINARY_TARGETS)
$(BINARY_TARGETS): $(BIN_DIR)
	@echo "Building $@"
	cargo build $(CARGO_BUILD_ARGS) --package $@

# Compilation of dynamic libraries
.PHONY: $(DYNAMIC_LIBRARES)
$(DYNAMIC_LIBRARES): $(LIB_DIR)
	@echo "Building $@"
	cargo build $(CARGO_BUILD_ARGS) --package $@

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

.PHONY: $(LIB_DIR)
$(BIN_DIR): $(BUILD_DIR)
	mkdir $(BIN_DIR) || echo "Directory $(BIN_DIR) already exists"

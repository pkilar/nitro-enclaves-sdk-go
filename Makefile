# Builds cmd/nsm-check and runs it where there is an NSM: in a Nitro Enclave,
# from an Enclave Image File (EIF), or in QEMU, against its emulated NSM.
# `make help` lists the targets. README.md, under "Checking an Enclave's NSM",
# says what the machine needs and how to read the result.

GO        ?= go
DOCKER    ?= docker
NITRO_CLI ?= nitro-cli

# nitro-cli assembles an EIF around the kernel and init installed on the
# machine it runs on, so an EIF can only be built for that machine's
# architecture.
HOST_ARCH := $(shell uname -m | sed 's/^x86_64$$/amd64/; s/^aarch64$$/arm64/')
ARCH      ?= $(HOST_ARCH)

# What `make run` gives the enclave, taken from the pool the parent instance's
# allocator reserved. On an x86 instance with hyper-threading the vCPU count
# must be even.
CPU_COUNT ?= 2
MEMORY    ?= 512

# PCR_WRITES=1 adds the checks that extend and lock PCRs. They get an image and
# an EIF of their own, because the command an enclave runs is fixed in its EIF.
PCR_WRITES ?=

pcr_writes := $(filter 1 true yes,$(PCR_WRITES))
name       := nsm-check$(if $(pcr_writes),-pcr-writes)
stage      := $(if $(pcr_writes),pcr-writes,read-only)

BUILD_DIR := build
BINARY    := $(BUILD_DIR)/bin/nsm-check-$(ARCH)
IMAGE     := $(name):$(ARCH)
EIF       := $(BUILD_DIR)/$(name)-$(ARCH).eif
LOG       := $(BUILD_DIR)/$(name)-$(ARCH).console.log

# `make qemu` boots the kernel and the NSM driver that nitro-cli puts in an
# EIF, so it takes them from where nitro-cli keeps them.
BLOBS        ?= $(or $(NITRO_CLI_BLOBS),/usr/share/nitro_enclaves/blobs)
QEMU         ?= qemu-system-x86_64
QEMU_TIMEOUT ?= 120

QEMU_DIR := $(BUILD_DIR)/qemu
QEMU_LOG := $(BUILD_DIR)/$(name)-$(ARCH).qemu.log

# The last line nsm-check prints when every check passed: passedLine in
# cmd/nsm-check/main.go. An enclave has no exit code to give its parent, so
# `make run` looks for this line in the console output.
PASSED := nsm-check: all checks passed

# $(call verdict,<log>) prints PASS or FAIL for a console log, and fails the
# recipe unless nsm-check reported success in it.
define verdict
@echo
@if grep -q '$(PASSED)' $(1); then \
	echo "PASS: the NSM passed every check. Console output: $(1)"; \
else \
	echo "FAIL: nsm-check did not report success. Console output: $(1)"; \
	exit 1; \
fi
endef

.DEFAULT_GOAL := build
.PHONY: build image eif run terminate qemu clean help check-arch check-qemu

build: ## Compile nsm-check for linux/ARCH into build/bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -ldflags='-s -w' \
		-o $(BINARY) ./cmd/nsm-check

image: build ## Build the container image that holds the binary
	$(DOCKER) build --platform linux/$(ARCH) --build-arg TARGETARCH=$(ARCH) \
		--target $(stage) --file cmd/nsm-check/Dockerfile --tag $(IMAGE) $(BUILD_DIR)/bin

eif: check-arch image ## Build the Enclave Image File from the image
	$(NITRO_CLI) build-enclave --docker-uri $(IMAGE) --output-file $(EIF)

run: ## Run the EIF in an enclave and report PASS or FAIL (builds the EIF if it is missing)
	@test -f $(EIF) || $(MAKE) --no-print-directory eif
	$(NITRO_CLI) run-enclave --eif-path $(EIF) --enclave-name $(name) \
		--cpu-count $(CPU_COUNT) --memory $(MEMORY) --attach-console 2>&1 | tee $(LOG)
	$(call verdict,$(LOG))

terminate: ## Terminate the enclave, should it still be running
	$(NITRO_CLI) terminate-enclave --enclave-name $(name)

# The guest is the enclave's kernel with an initramfs of three files: the
# init from internal/qemuinit, the NSM driver, and the nsm-check binary that
# `make eif` would ship. Resetting the guest ends the run, hence -no-reboot.
qemu: check-qemu build ## Run nsm-check in QEMU against its emulated NSM (x86-64 only, needs no AWS)
	rm -rf $(QEMU_DIR)
	mkdir -p $(QEMU_DIR)/root/dev
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' \
		-o $(QEMU_DIR)/root/init ./internal/qemuinit
	cp $(BINARY) $(QEMU_DIR)/root/nsm-check
	cp $(BLOBS)/nsm.ko $(QEMU_DIR)/root/nsm.ko
	cd $(QEMU_DIR)/root && find . | cpio -o -H newc --quiet | gzip > ../initrd.gz
	timeout $(QEMU_TIMEOUT) $(QEMU) -M microvm,acpi=off -accel kvm -accel tcg -cpu max -m 256 \
		-display none -nodefaults -no-reboot -serial stdio \
		-kernel $(BLOBS)/bzImage -initrd $(QEMU_DIR)/initrd.gz \
		-append "console=ttyS0 reboot=k panic=-1 pci=off$(if $(pcr_writes), nsm_check_args=-pcr-writes)" \
		-device virtio-nsm-device,module-id=i-0123456789abcdef0-enc0123456789abcde 2>&1 | tee $(QEMU_LOG)
	$(call verdict,$(QEMU_LOG))

clean: ## Remove build/
	rm -rf $(BUILD_DIR)

help: ## List the targets and the variables they take
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / { printf "  %-10s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo
	@echo "Variables, with their current values:"
	@echo "  ARCH=$(ARCH)  CPU_COUNT=$(CPU_COUNT)  MEMORY=$(MEMORY)  PCR_WRITES=$(PCR_WRITES)"
	@echo "  PCR_WRITES=1 adds the checks that extend and lock PCRs."

check-qemu:
	@if [ "$(ARCH)" != "amd64" ]; then \
		echo "make qemu needs ARCH=amd64: QEMU emulates the NSM for x86-64 guests only."; \
		exit 1; \
	fi
	@if [ ! -f $(BLOBS)/bzImage ] || [ ! -f $(BLOBS)/nsm.ko ]; then \
		echo "No bzImage and nsm.ko in $(BLOBS)."; \
		echo "Set NITRO_CLI_BLOBS to the directory that holds nitro-cli's x86_64 blobs."; \
		exit 1; \
	fi
	@if ! $(QEMU) -device help 2>/dev/null | grep -q virtio-nsm-device; then \
		echo "$(QEMU) is missing, or has no virtio-nsm-device."; \
		echo "It takes QEMU 9.2 or later, built with the NSM device."; \
		exit 1; \
	fi
	@command -v cpio >/dev/null || { echo "cpio is not installed."; exit 1; }

check-arch:
	@if [ "$(ARCH)" != "$(HOST_ARCH)" ]; then \
		echo "nitro-cli can only build an EIF for this machine's architecture ($(HOST_ARCH)), not $(ARCH)."; \
		echo "Build it on a machine of that architecture."; \
		exit 1; \
	fi

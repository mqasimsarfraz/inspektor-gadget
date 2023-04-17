.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager nrigadget


TARGET_ARCH ?= $(shell go env GOHOSTARCH)

PODMAN_BUILDTAGS = exclude_graphdriver_btrfs exclude_graphdriver_devicemapper containers_image_openpgp
BUILDTAGS ?= $(PODMAN_BUILDTAGS)

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-tags "$(BUILDTAGS)" \
		-o bin/gadgettracermanager \
		./gadgettracermanager/

# Hooks

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-tags "$(BUILDTAGS)" \
		-o bin/ocihookgadget \
		./hooks/oci/main.go

.PHONY: nrigadget
nrigadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-tags "$(BUILDTAGS)" \
		-o bin/nrigadget \
		./hooks/nri/main.go

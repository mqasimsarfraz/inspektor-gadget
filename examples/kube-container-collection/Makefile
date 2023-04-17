CONTAINER_REPO ?= ghcr.io/inspektor-gadget/inspektor-gadget
IMAGE_TAG ?= $(shell ../../tools/image-tag branch)

PODMAN_BUILDTAGS = exclude_graphdriver_btrfs exclude_graphdriver_devicemapper containers_image_openpgp
BUILDTAGS ?= $(PODMAN_BUILDTAGS)

kube-container-collection: main.go
	go build -o kube-container-collection main.go

kube-container-collection-static: main.go
	go build -o kube-container-collection-static -ldflags '-w -extldflags "-static"' -tags "$(BUILDTAGS)" main.go

build-container:
	DOCKER_BUILDKIT=1 docker build -t $(CONTAINER_REPO)-kube-container-collection:$(IMAGE_TAG) -f Dockerfile ../..

install:
	sed "s|image: .*:latest|image: $(CONTAINER_REPO)-kube-container-collection:$(IMAGE_TAG)|" deploy.yaml | kubectl apply -f -

uninstall:
	kubectl delete -f deploy.yaml

clean:
	rm -f kube-container-collection kube-container-collection-static

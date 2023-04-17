FROM ghcr.io/inspektor-gadget/ig-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s

ARG BUILDTAGS=undefined
ENV BUILDTAGS=${BUILDTAGS}

RUN go test -tags "${BUILDTAGS}" -c -o ig-integration.test ./...

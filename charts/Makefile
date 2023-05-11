HELM ?= helm
HELM_DOCS_IMAGE ?= jnorwood/helm-docs:v1.11.0
BUILD_DIR ?= bin
OUTPUT_DIR ?= $(BUILD_DIR)
CHART_DIR := $(BUILD_DIR)/gadget
CHART_VERSION := 0.1.0
IMAGE_TAG ?= $(shell ../tools/image-tag branch)

clean:
	rm -rf $(BUILD_DIR)

build: clean
	@echo "Building chart:"
	mkdir -p $(BUILD_DIR)
	cp -r gadget $(BUILD_DIR)
	cp -r ../pkg/resources/crd/bases $(CHART_DIR)/crds
	mv $(CHART_DIR)/Chart.yaml.tmpl $(CHART_DIR)/Chart.yaml
	sed -i "s/%VERSION%/$(CHART_VERSION)/g" $(CHART_DIR)/Chart.yaml
	sed -i "s/%APP_VERSION%/$(IMAGE_TAG)/g" $(CHART_DIR)/Chart.yaml
	@echo "Preparing docs"
	docker run --user $(shell id -u):$(shell id -g) -v $(shell pwd)/$(CHART_DIR):/helm-docs $(HELM_DOCS_IMAGE) -s file
	@echo "Charts available at: $(CHART_DIR)"

# install uses 'helm upgrade --install' to make chart installation idempotent,
# also helm upgrade does not update CRDs so we need to apply them separately
install: build
	$(HELM) upgrade --install gadget $(CHART_DIR) --namespace gadget --create-namespace
	kubectl apply -f $(CHART_DIR)/crds

uninstall:
	$(HELM) uninstall gadget --namespace gadget
	kubectl delete -f $(CHART_DIR)/crds

lint: build
	$(HELM) lint $(CHART_DIR)

template: build
	$(HELM) template gadget $(CHART_DIR) --namespace gadget --skip-crds | tee $(OUTPUT_DIR)/deploy.yaml

package: build
	$(HELM) package $(CHART_DIR) -d $(BUILD_DIR)
	mv $(BUILD_DIR)/gadget-$(CHART_VERSION).tgz $(BUILD_DIR)/gadget-$(IMAGE_TAG).tgz

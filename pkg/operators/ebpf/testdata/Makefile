ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig

TEST_ARTIFACTS = \
	empty \
	#

all: $(TEST_ARTIFACTS)

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest --gadget-category observer $@
	@sudo $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	#@sudo $(IG) image remove $@:latest

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm $$ARTIFACT.tar; \
	done

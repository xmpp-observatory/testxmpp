scss_files = $(filter-out testxmpp/web/scss/_%.scss,$(wildcard testxmpp/web/scss/*.scss))
scss_includes = $(filter testxmpp/web/scss/_%.scss,$(wildcard testxmpp/web/scss/*.scss))
generated_css_files = $(patsubst testxmpp/web/scss/%.scss,testxmpp/web/static/css/%.css,$(scss_files))
images = $(wildcard docker/*.Dockerfile)
image_targets = $(patsubst docker/%.Dockerfile,%-image,$(images))
repository = testxmpp

PYTHON3 ?= python3
SCSSC ?= $(PYTHON3) -m scss --load-path testxmpp/web/scss/

all: build_css images

images: $(image_targets)

$(image_targets): %-image: docker/%.Dockerfile
	docker build -t $(repository)/$(patsubst %-image,%,$@):latest -f docker/$(patsubst %-image,%,$@).Dockerfile .

build_css: $(generated_css_files)

$(generated_css_files): testxmpp/web/static/css/%.css: testxmpp/web/scss/%.scss $(scss_includes)
	mkdir -p testxmpp/web/static/css/
	$(SCSSC) -o "$@" "$<"

clean:
	rm -f $(generated_css_files)

.PHONY: build_css clean images testssl-image coordinator-image web-image

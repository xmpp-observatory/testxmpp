scss_files = $(filter-out testxmpp/web/scss/_%.scss,$(wildcard testxmpp/web/scss/*.scss))
scss_includes = $(filter testxmpp/web/scss/_%.scss,$(wildcard testxmpp/web/scss/*.scss))
generated_css_files = $(patsubst testxmpp/web/scss/%.scss,testxmpp/web/static/css/%.css,$(scss_files))

PYTHON3 ?= python3
SCSSC ?= $(PYTHON3) -m scss --load-path testxmpp/web/scss/

all: build_css

build_css: $(generated_css_files)

$(generated_css_files): testxmpp/web/static/css/%.css: testxmpp/web/scss/%.scss $(scss_includes)
	mkdir -p testxmpp/web/static/css/
	$(SCSSC) -o "$@" "$<"

clean:
	rm -f $(generated_css_files)

.PHONY: build_css clean update_translations compile_translations

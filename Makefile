ifeq ($(CMAKE),)
CMAKE := cmake
endif

.PHONY: all
all: build/Makefile
	@$(MAKE) --no-print-directory -C build

%: build/Makefile
	@$(MAKE) --no-print-directory -C build $@

build/Makefile: | build
	@cd build && $(CMAKE) $(CMAKE_ARGS) ..

build:
	@mkdir -p $@

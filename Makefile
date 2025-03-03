ifeq ($(CMAKE),)
CMAKE := cmake
endif

ifeq ($(CLANG_FORMAT),)
CLANG_FORMAT := clang-format
endif

ifeq ($(RUN_CLANG_TIDY),)
RUN_CLANG_TIDY := run-clang-tidy
endif


SRC_DIR = "$(shell pwd)/src"
INC_DIR = "$(shell pwd)/include"

SOURCE_DIR = "$(SRC_DIR)" "$(INC_DIR)"
SOURCE_REGEX = '.*\.\(cpp\|hpp\|c\|h\)'


.PHONY: all
all: build/Makefile
	@$(MAKE) --no-print-directory -C build

%: build/Makefile
	@$(MAKE) --no-print-directory -C build $@

build/Makefile: | build
	@cd build && $(CMAKE) $(CMAKE_ARGS) ..

build:
	@mkdir -p $@

.PHONY: format
format:
	@find $(SOURCE_DIR) -type f -regex $(SOURCE_REGEX) -print0 | xargs -0 $(CLANG_FORMAT) --dry-run

.PHONY: format-fix
format-fix:
	@find $(SOURCE_DIR) -type f -regex $(SOURCE_REGEX) -print0 | xargs -0 $(CLANG_FORMAT) -i

.PHONY: tidy
tidy: all
	$(RUN_CLANG_TIDY) -p build -quiet -j $(shell nproc) -header-filter=$(SOURCE_DIR) $(SOURCE_DIR)

.PHONY: tidy-fix
tidy-fix: all
	$(RUN_CLANG_TIDY) -p build -quiet -fix -j $(shell nproc) -header-filter=$(SOURCE_DIR) $(SOURCE_DIR)

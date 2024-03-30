TARGETS := $(patsubst %.c,%.o,$(wildcard *.c))

CFLAGS = -Wno-error 
CFLAGS += -Wno-unknown-attributes
CFLAGS += -Wno-deprecated-declarations
CINCLUDE = -I$(shell pwd)/../../include

LLC ?= llc
CLANG ?= clang

OUTPUT_DIR ?= .output

all: $(TARGETS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	@rm -rf $(OUTPUT_DIR)

$(TARGETS): %.o: %.c | $(OUTPUT_DIR)
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(CFLAGS) $(CINCLUDE) -c $(filter %.c,$^) -o $(OUTPUT_DIR)/$@

$(OUTPUT_DIR):
	@mkdir $(OUTPUT_DIR)

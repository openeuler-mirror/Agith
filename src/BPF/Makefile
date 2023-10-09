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
	@$(CLANG) -S $(CFLAGS) $(CINCLUDE) -D__TARGET_ARCH_x86 \
	    -O2 -emit-llvm -c $<
	@$(LLC) -march=bpf -filetype=obj -o $(OUTPUT_DIR)/$@ ${@:.o=.ll}
	@rm ${@:.o=.ll}

$(OUTPUT_DIR):
	@mkdir $(OUTPUT_DIR)

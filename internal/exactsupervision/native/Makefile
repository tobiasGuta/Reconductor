# Independent Linux-only native build. No Go build/test depends on this file.
# All outputs stay outside the checkout; no install/setuid/file-capability rule.
CC ?= cc
OUT ?= /tmp/reconductor-exact-cleanup-build
WARN = -std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow -Wformat=2 \
       -Wstrict-prototypes -Wmissing-prototypes -Wvla
HARDEN = -O2 -fstack-protector-strong -fPIE -fno-ident \
         -ffile-prefix-map=$(CURDIR)=native
LINK = -Wl,-z,relro,-z,now,-z,noexecstack,--build-id=sha1

.PHONY: all test sanitize analyze static
all: $(OUT)/exact-cleanup-dev

$(OUT):
	mkdir -p $(OUT)

$(OUT)/exact-cleanup-dev: cleanup.c validate.c validate.h | $(OUT)
	$(CC) $(WARN) $(HARDEN) -pie $(LINK) cleanup.c validate.c -o $@

$(OUT)/validate-test: validate.c validate.h validate_test.c | $(OUT)
	$(CC) $(WARN) $(HARDEN) -pie $(LINK) validate.c validate_test.c -o $@

test: $(OUT)/validate-test $(OUT)/exact-cleanup-dev
	$(OUT)/validate-test
	@$(OUT)/exact-cleanup-dev rejected-argument; test $$? -eq 1

sanitize: | $(OUT)
	$(CC) $(WARN) -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
		validate.c validate_test.c -o $(OUT)/validate-sanitize
	$(OUT)/validate-sanitize

analyze: | $(OUT)
	$(CC) $(WARN) $(HARDEN) -fanalyzer -c cleanup.c -o $(OUT)/cleanup-analysis.o
	$(CC) $(WARN) $(HARDEN) -fanalyzer -c validate.c -o $(OUT)/validate-analysis.o

# Release artifact: requires the builder's static libc, never vendored here.
# Failure is explicit; there is no dynamic fallback under this artifact name.
static: | $(OUT)
	$(CC) $(WARN) $(HARDEN) -static-pie $(LINK) cleanup.c validate.c -o $(OUT)/exact-cleanup-static
	readelf -l $(OUT)/exact-cleanup-static > $(OUT)/static-program-headers.txt
	readelf -d $(OUT)/exact-cleanup-static > $(OUT)/static-dynamic-info.txt
	@! grep -q INTERP $(OUT)/static-program-headers.txt
	@! grep -q NEEDED $(OUT)/static-dynamic-info.txt

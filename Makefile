CARGO            ?= cargo
CARGO_DENY       ?= cargo deny
PYTHON           ?= python3
CARGO_TARGET_DIR ?= target
BINDIR           ?= bin
export CARGO_TARGET_DIR

DOCKER          ?= docker
ARCH_IMAGE      ?= pds-arch-build
ARCH_DOCKERFILE ?= packaging/arch/Dockerfile

.PHONY: all build pds pdsd test compat clippy vet fmt fmt-check check advisories licenses arch-pkg clean

all: build

build:
	$(CARGO) build --locked --release --bins
	mkdir -p $(BINDIR)
	cp $(CARGO_TARGET_DIR)/release/pds $(CARGO_TARGET_DIR)/release/pdsd $(BINDIR)/

pds pdsd: build

test:
	$(CARGO) test --locked

compat: build
	PDS_BIN="$(abspath $(BINDIR)/pds)" PDSD_BIN="$(abspath $(BINDIR)/pdsd)" $(PYTHON) tests/compat.py

clippy:
	$(CARGO) clippy --locked --all-targets -- -D warnings

vet: clippy

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

check: fmt-check clippy test compat advisories licenses

advisories:
	$(CARGO_DENY) --locked check advisories

licenses:
	$(CARGO_DENY) --locked check licenses

# Build in Arch Linux and copy the package to the repository root.
arch-pkg:
	$(DOCKER) build -f $(ARCH_DOCKERFILE) -t $(ARCH_IMAGE) .
	cid=$$($(DOCKER) create $(ARCH_IMAGE)) && \
		trap "$(DOCKER) rm -f $$cid >/dev/null" EXIT && \
		$(DOCKER) cp $$cid:/home/build/out/. .

clean:
	$(CARGO) clean
	rm -rf $(BINDIR)

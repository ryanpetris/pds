# PDS build & quality targets. All builds are CGO-free (pure Go).
export CGO_ENABLED := 0

GO     ?= go
BINDIR ?= bin

# Arch package build (Docker).
DOCKER          ?= docker
ARCH_IMAGE      ?= pds-arch-build
ARCH_DOCKERFILE ?= packaging/arch/Dockerfile

.PHONY: all build pds pdsd test vet fmt check arch-pkg clean

all: build

build: pds pdsd

pds:
	$(GO) build -o $(BINDIR)/pds ./cmd/pds

pdsd:
	$(GO) build -o $(BINDIR)/pdsd ./cmd/pdsd

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# Full quality gate: vet and tests.
check: vet test

# Build the Arch package in a clean archlinux:base-devel container (only Docker
# is needed on the host) and copy the resulting pds-*.pkg.tar.zst to the repo
# root. The build context is the repo root; see packaging/arch/Dockerfile.
arch-pkg:
	$(DOCKER) build -f $(ARCH_DOCKERFILE) -t $(ARCH_IMAGE) .
	cid=$$($(DOCKER) create $(ARCH_IMAGE)) && \
		trap "$(DOCKER) rm -f $$cid >/dev/null" EXIT && \
		$(DOCKER) cp $$cid:/home/build/out/. .

clean:
	rm -rf $(BINDIR)

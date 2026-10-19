GO ?= go
BIN := bin
CLAUDE_DIR ?= $(if $(CLAUDE_CONFIG_DIR),$(CLAUDE_CONFIG_DIR),$(HOME)/.claude)

.PHONY: all build relay-linux test race vet limits e2e install install-skill clean

all: vet test build

build:
	$(GO) build -o $(BIN)/ ./cmd/...

# The relay for a Linux host, static, which is the deployment guide's step
# 1 and what auu-ca kit takes: ARCH=arm64 for an ARM host.
ARCH ?= amd64
relay-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -o $(BIN)/linux_$(ARCH)/auu-relay ./cmd/auu-relay

test:
	$(GO) test ./...

race:
	$(GO) test -race -count=1 -timeout 60m ./...

# The limit tests on their own: every TestLimit in the tree, which the
# ledger in internal/limits names beside the site each one shows.
limits:
	$(GO) test ./... -run '^TestLimit' -count=1

# The container suite: the deployment guide in four containers and a matrix
# of what goes wrong in the wild, with a report. Needs Docker; see
# docker/testing/README.md.
e2e:
	docker/testing/run.sh

# gofmt over the module's own directories, not the whole tree: a git-ignored
# directory of the maintainers', never part of the module, may hold archived
# Go files (earlier sessions' probes and overlays) that gofmt would read,
# while go vet stops at their own go.mod.
vet:
	@out="$$(gofmt -l cmd internal docker skill *.go)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

install:
	$(GO) install ./cmd/...

# The three skills, each in its own directory with the shared reference
# beside it: a skill directory has to stand alone, so the reference is
# copied rather than linked.
SKILLS := auu-connect auu-setup auu-relay

install-skill:
	@for s in $(SKILLS); do \
		mkdir -p "$(CLAUDE_DIR)/skills/$$s"; \
		cp "skill/$$s/SKILL.md" "$(CLAUDE_DIR)/skills/$$s/SKILL.md"; \
		cp skill/reference.md "$(CLAUDE_DIR)/skills/$$s/reference.md"; \
		echo "installed $$s to $(CLAUDE_DIR)/skills/$$s"; \
	done

clean:
	rm -rf $(BIN)

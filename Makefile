GO ?= go
BIN := bin
CLAUDE_DIR ?= $(if $(CLAUDE_CONFIG_DIR),$(CLAUDE_CONFIG_DIR),$(HOME)/.claude)

.PHONY: all build relay-linux test race vet e2e install install-skill clean

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
	$(GO) test -race -count=1 ./...

# The container suite: the deployment guide in four containers and a matrix
# of what goes wrong in the wild, with a report. Needs Docker; see
# docker/testing/README.md.
e2e:
	docker/testing/run.sh

vet:
	@out="$$(gofmt -l . )"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

install:
	$(GO) install ./cmd/...

# The three skills, each in its own directory with the shared reference
# beside it: a skill directory has to stand alone, so the reference is
# copied rather than linked.
SKILLS := connect auu-setup auu-relay

install-skill:
	@for s in $(SKILLS); do \
		mkdir -p "$(CLAUDE_DIR)/skills/$$s"; \
		cp "skill/$$s/SKILL.md" "$(CLAUDE_DIR)/skills/$$s/SKILL.md"; \
		cp skill/reference.md "$(CLAUDE_DIR)/skills/$$s/reference.md"; \
		echo "installed $$s to $(CLAUDE_DIR)/skills/$$s"; \
	done

clean:
	rm -rf $(BIN)

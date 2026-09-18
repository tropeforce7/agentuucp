# syntax=docker/dockerfile:1
#
# One image for every machine in the container suite: the relay, the
# operator, and the two users. It is built once from the repository at the
# root of the build context; the entrypoint decides which machine a
# container is. Nothing here is a deployment artifact: the four binaries are
# built exactly as docs/deploy-linux.md builds them, static, and put where
# the guide puts them; the forge (see forge/main.go) exists only so a test
# can issue certificates dated in the past, and upstream (upstream/main.go)
# stands in for api.anthropic.com behind the key-holding proxy.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/ ./cmd/... ./docker/testing/forge ./docker/testing/upstream

FROM debian:13-slim
# runuser and flock come with util-linux, pkill with procps; sqlite3 is what the guide's backup
# line uses and what the matrix vandalises rows with; git is what 'auu serve'
# makes a channel's worktree with, so family S needs it on the users'
# machines.
RUN apt-get update \
 && apt-get install -y --no-install-recommends util-linux procps sqlite3 git \
 && rm -rf /var/lib/apt/lists/*
# The relay's user, as the guide creates it, and three people: the operator
# (called "you", as the guide addresses them) and two users.
RUN useradd --system --home-dir /var/lib/auu --no-create-home \
      --shell /usr/sbin/nologin --user-group auu \
 && useradd --create-home --uid 1000 --shell /bin/bash you \
 && useradd --create-home --uid 1001 --shell /bin/bash alice \
 && useradd --create-home --uid 1002 --shell /bin/bash bob \
 && install -d -m 0755 /etc/auu /etc/auu/delivered
COPY --from=build /out/auu /out/auu-admin /out/auu-ca /out/auu-relay /out/forge /out/upstream /usr/local/bin/
COPY docker/testing/entrypoint-relay.sh docker/testing/entrypoint-user.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint-relay.sh /usr/local/bin/entrypoint-user.sh

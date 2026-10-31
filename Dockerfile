# syntax=docker/dockerfile:1
#
# myOwl — production image (multi-arch: linux/amd64, linux/arm64)
#
#   docker build -t myowl .
#   docker build --build-arg VERSION=1.2.3 -t myowl:1.2.3 .
#
# The UI and the Go binary are built on the build platform and cross-compiled
# (pure Go, CGO disabled), so multi-arch builds are fast; only the tiny runtime
# stage runs on the target architecture.
#
# Runtime privileges (see README "Docker" + docker-compose.yml):
#   --network host   see the host's real interfaces, connections and listening ports
#   --pid host       see host processes (top processes, connection owners)
#   --cap-add NET_ADMIN   one-click "Block IP" via nftables/iptables
#   --cap-add NET_RAW     passive packet counting
#   (optional) SYS_PTRACE map sockets to processes owned by other users
# The container runs as root by default because reading host logs
# (/var/log/auth.log is root:adm 0640) and changing the host firewall need it.
# For a reduced, read-mostly mode run it as the bundled unprivileged user:
#   --user 10001:4      (uid myowl, gid 4 = adm so host logs stay readable)
# Blocking IPs is then disabled; everything else keeps working.

ARG NODE_VERSION=24
ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.22

# ---- web UI (static export) ----
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS web
WORKDIR /src/web
ENV NEXT_TELEMETRY_DISABLED=1
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN corepack install && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# ---- Go agent (cross-compiled) ----
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS agent
WORKDIR /src/agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
COPY --from=web /src/web/out/ ./internal/webui/dist/
COPY VERSION.md /src/VERSION.md
ARG VERSION=""
ARG TARGETOS=linux
ARG TARGETARCH
RUN v="${VERSION:-$(sed -n 's/^version:[[:space:]]*//p' /src/VERSION.md | head -n1)}"; \
    v="${v#v}"; echo "building myOwl ${v} for ${TARGETOS}/${TARGETARCH}"; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${v}" -o /out/myowl ./cmd/myowl

# ---- runtime ----
# Alpine (not distroless) so nftables/iptables are available for IP blocking.
FROM alpine:${ALPINE_VERSION}
ARG VERSION=""
ARG REVISION=""
ARG SOURCE="https://github.com/OWNER/myowl"
LABEL org.opencontainers.image.title="myOwl" \
      org.opencontainers.image.description="Self-hosted VPS security monitor with a live attack map" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="myOwl contributors"
RUN apk add --no-cache ca-certificates tzdata nftables iptables \
 && addgroup -S -g 10001 myowl \
 && adduser -S -D -H -u 10001 -G myowl -s /sbin/nologin myowl \
 && mkdir -p /etc/myowl /var/lib/myowl \
 && chown myowl:myowl /var/lib/myowl && chmod 0750 /var/lib/myowl
COPY --from=agent /out/myowl /usr/local/bin/myowl
COPY --chmod=0644 config.example.yaml /etc/myowl/config.yaml
ENV MYOWL_CONFIG=/etc/myowl/config.yaml
VOLUME ["/var/lib/myowl"]
EXPOSE 8787
# Uses the configured listen address (0.0.0.0 -> 127.0.0.1) and TLS setting.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/myowl", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/myowl"]
CMD ["--config", "/etc/myowl/config.yaml"]

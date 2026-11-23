# Rebuild only when the versioned CI environment changes, never for a PR checkout.
FROM docker:29.6-cli@sha256:be132a9f282288de4afaf63379dff75711fda0147c6b72a9df44e51841402144 AS clients
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS go
FROM node:26.13.0-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS node
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS tools
ARG TARGETARCH
ARG DEBIAN_MIRROR=https://repo.huaweicloud.com
ARG ENVIRONMENT_VERSION=2026-11-19.1
ENV PATH=/opt/pnpm:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOCACHE=/opt/gocache GOPATH=/root/go GOPROXY=https://goproxy.cn CGO_ENABLED=0 NPM_CONFIG_REGISTRY=https://registry.npmmirror.com PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
# Bootstrap HTTPS with the fixed SDK public bundle. The slim base has no
# ca-certificates package to configure OpenSSL default trust paths yet.
COPY --from=go /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i "s#https\?://deb.debian.org#${DEBIAN_MIRROR}#g" /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::https::CAInfo=/etc/ssl/certs/ca-certificates.crt update -qq && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CAInfo=/etc/ssl/certs/ca-certificates.crt install -y -qq --no-install-recommends git python3 python3-yaml openssl ripgrep postgresql-client libstdc++6 libatomic1 curl ca-certificates zstd && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
COPY --from=node /usr/local/ /usr/local/
COPY --from=clients /usr/local/bin/docker /usr/local/bin/docker
COPY --from=clients /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/
COPY scripts/install-pnpm.mjs /opt/ci/install-pnpm.mjs
RUN node /opt/ci/install-pnpm.mjs && rm /tmp/pnpm.tgz && mkdir -p /opt/ci-browser && cd /opt/ci-browser && npm install --registry=https://registry.npmmirror.com @playwright/test@1.65.0 && node node_modules/playwright/cli.js install --with-deps chromium
COPY scripts/install-duckdb.py /opt/ci/install-duckdb.py
RUN python3 /opt/ci/install-duckdb.py /opt/ci/duckdb
LABEL org.opencontainers.image.version=$ENVIRONMENT_VERSION

# Multiarch job image: the container resolver selects the actual Linux host ISA.
FROM tools AS runner
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends qemu-system-x86 qemu-system-arm qemu-utils e2fsprogs && rm -rf /var/lib/apt/lists/*

# Target Linux guest contains tools and a kernel, never business source/results.
FROM tools AS guest
ARG TARGETARCH
ARG GUEST_KERNEL=7.2.12
ARG GUEST_KERNEL_PACKAGE_VERSION=7.2.12-1~bpo13+1
ARG GUEST_LINUX_BASE_VERSION=4.17~bpo13+1
# Keep the disposable guest on an explicit official backports kernel. The 6.12
# guest Oopsed in delayed-dequeue/migration under the unchanged cgroup limits.
RUN printf 'Types: deb\nURIs: %s/debian\nSuites: trixie-backports\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "$DEBIAN_MIRROR" > /etc/apt/sources.list.d/guest-kernel.sources && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "linux-base=${GUEST_LINUX_BASE_VERSION}" "linux-image-${GUEST_KERNEL}+deb13-${TARGETARCH}=${GUEST_KERNEL_PACKAGE_VERSION}" initramfs-tools docker.io iproute2 iptables kmod procps busybox-static && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /export && cp "/boot/vmlinuz-${GUEST_KERNEL}+deb13-${TARGETARCH}" /export/vmlinuz && cp "/boot/initrd.img-${GUEST_KERNEL}+deb13-${TARGETARCH}" /export/initrd.img

# Treat target files as data; tar and compression execute on the build platform.
FROM --platform=$BUILDPLATFORM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS guest-pack
ARG TARGETARCH
ARG ENVIRONMENT_VERSION=2026-11-19.1
RUN --mount=type=bind,from=guest,target=/guest,ro mkdir -p /export && cp /guest/export/vmlinuz /guest/export/initrd.img /export/ && tar -C /guest --exclude=./export --exclude=./proc --exclude=./sys --exclude=./dev --exclude=./boot -czf /export/rootfs.tar.gz .
RUN cd /export && printf '{"schema_version":1,"version":"%s","architecture":"%s"}\n' "$ENVIRONMENT_VERSION" "$TARGETARCH" > environment.json && sha256sum vmlinuz initrd.img rootfs.tar.gz > SHA256SUMS && tar -cf guest.tar environment.json SHA256SUMS vmlinuz initrd.img rootfs.tar.gz
FROM scratch AS guest-image
COPY --from=guest-pack /export/guest.tar /guest.tar

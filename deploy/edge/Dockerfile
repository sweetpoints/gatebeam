ARG WEB_STAGE=web-build
FROM --platform=$BUILDPLATFORM node:26.13.0-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS web-build
COPY scripts/install-pnpm.mjs /install-pnpm.mjs
RUN node /install-pnpm.mjs && rm /tmp/pnpm.tgz
ENV PATH="/opt/pnpm:${PATH}" PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false NODE_OPTIONS="--max-old-space-size=1024"
WORKDIR /workspace
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
ARG WEB_INSTALL_TIMEOUT=120
RUN case "$WEB_INSTALL_TIMEOUT" in 120|1440) ;; *) exit 2;; esac && timeout "$WEB_INSTALL_TIMEOUT" pnpm install --frozen-lockfile --store-dir /opt/pnpm-store
# Copy source inputs explicitly: the acceptance guest already has node_modules
# and browser dependencies. Importing those would pollute this clean install
# with unrelated generated files.
COPY web/index.html web/tsconfig.json web/vite.config.ts web/playwright.config.ts ./
COPY web/src/ ./src/
COPY web/tests/ ./tests/
ARG WEB_CHECK_TIMEOUT=90
RUN case "$WEB_CHECK_TIMEOUT" in 90|1080) ;; *) exit 2;; esac && timeout "$WEB_CHECK_TIMEOUT" node node_modules/vue-tsc/bin/vue-tsc.js --noEmit && timeout "$WEB_CHECK_TIMEOUT" node node_modules/vite/bin/vite.js build

# CI builds web assets once in its pinned native tool environment.
FROM scratch AS web-prebuilt
COPY .work/build/web-dist/ /workspace/dist/
FROM ${WEB_STAGE} AS web

# Build the static Go binary with scripts/build-edge.sh; the runtime never
# includes Go tooling, a Docker socket, or an executor command protocol.
FROM nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606 AS edge
COPY --chown=101:101 .work/build/gatebeam /usr/local/bin/gatebeam
COPY --chown=101:101 .work/build/gatebeam-admin /usr/local/bin/gatebeam-admin
# Execute only compiled offline contracts/help; no DB or initialization required.
RUN ["/usr/local/bin/gatebeam", "--runtime-contract"]
RUN ["/usr/local/bin/gatebeam-admin", "--help"]
RUN mkdir -p /var/lib/gatebeam/capsules/api /var/lib/gatebeam/capsules/edge /var/lib/gatebeam/capsules/worker /var/lib/gatebeam/capsules/ca /var/lib/gatebeam/backups /var/lib/gatebeam/logs /var/lib/gatebeam/releases /var/lib/gatebeam/acme && chmod -R 700 /var/lib/gatebeam /var/lib/gatebeam/logs /var/lib/gatebeam/releases /var/lib/gatebeam/acme && chown -R 101:101 /var/lib/gatebeam
USER 101:101
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/gatebeam"]
CMD ["--config", "/run/gatebeam/edge.json"]

FROM scratch AS api
COPY --from=edge --chown=101:101 --chmod=0700 /var/lib/gatebeam/capsules/api /var/lib/gatebeam/capsules/api
COPY --from=edge /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=edge /usr/local/bin/gatebeam /usr/local/bin/gatebeam
COPY --from=edge /usr/local/bin/gatebeam-admin /usr/local/bin/gatebeam-admin
COPY --from=web /workspace/dist /app/web/dist
WORKDIR /app
USER 101:101
ENTRYPOINT ["/usr/local/bin/gatebeam"]
CMD ["--config", "/run/gatebeam/api.json"]

FROM scratch AS worker
COPY --from=edge --chown=101:101 --chmod=0700 /var/lib/gatebeam/capsules/worker /var/lib/gatebeam/capsules/worker
COPY --from=edge --chown=101:101 /var/lib/gatebeam/backups /var/lib/gatebeam/backups
COPY --from=edge --chown=101:101 /var/lib/gatebeam/logs /var/lib/gatebeam/logs
COPY --from=edge --chown=101:101 /var/lib/gatebeam/logs /var/lib/gatebeam/spool
COPY --from=edge --chown=101:101 /var/lib/gatebeam/logs /run/query
COPY --from=edge --chown=101:101 /var/lib/gatebeam/acme /var/lib/gatebeam/acme
COPY --from=edge /usr/local/bin/gatebeam /usr/local/bin/gatebeam
COPY --from=edge /usr/local/bin/gatebeam-admin /usr/local/bin/gatebeam-admin
COPY --from=edge /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 101:101
ENTRYPOINT ["/usr/local/bin/gatebeam"]
CMD ["--config", "/run/gatebeam/worker.json"]

FROM scratch AS ca
COPY --from=edge /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chown=101:101 .work/build/gatebeam-ca /usr/local/bin/gatebeam-ca
USER 101:101
ENTRYPOINT ["/usr/local/bin/gatebeam-ca"]
CMD ["serve", "-config", "/run/gatebeam-ca/serve.json"]

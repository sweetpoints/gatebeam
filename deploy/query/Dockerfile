ARG QUERY_TOOLS_STAGE=tools-build
# The fixed CLI and matching signed extension are provisioned at image build;
# the running service has no installer or Go/CGO DuckDB driver.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS tools-build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY scripts/install-duckdb.py /build/install-duckdb.py
RUN python3 /build/install-duckdb.py /opt/duckdb

FROM scratch AS tools-prebuilt
COPY .work/build/query-tools/duckdb /opt/duckdb/duckdb
COPY .work/build/query-tools/httpfs.duckdb_extension /opt/duckdb/httpfs.duckdb_extension
COPY .work/build/query-tools/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
FROM ${QUERY_TOOLS_STAGE} AS tools

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
COPY --from=tools /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=tools /opt/duckdb/duckdb /usr/local/bin/duckdb
COPY --from=tools /opt/duckdb/httpfs.duckdb_extension /opt/duckdb/httpfs.duckdb_extension
COPY .work/build/gatebeam /usr/local/bin/gatebeam
RUN mkdir -p /run/query && chown 101:101 /run/query
USER 101:101
ENTRYPOINT ["/usr/local/bin/gatebeam"]
CMD ["--config", "/run/gatebeam/query.json"]

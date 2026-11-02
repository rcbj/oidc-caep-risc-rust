# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM rust:1-bookworm AS test
WORKDIR /src
COPY . .
RUN cargo test

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
# Only what the demo binary compiles from (demo/main.rs, and demo/public through
# include_str!), so a new trust chain does not rebuild it.
COPY demo/main.rs demo/main.rs
COPY demo/public demo/public
RUN cargo build --release --bin demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/demo /app/oidc-caep-risc-demo
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch; rebuild after running the
# install script against a different iya-sts. .dockerignore admits that one
# file from demo/generated (never the client secret). A COPY of the demo
# DIRECTORY succeeds with or without it, so a fresh clone and CI still build;
# naming the file, or a glob that matches nothing, fails the build.
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/oidc-caep-risc-demo"]

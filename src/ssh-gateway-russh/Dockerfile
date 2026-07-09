# Build context is the repo root (like apps/runner/Dockerfile and
# apps/ssh-gateway/Dockerfile), not this directory: boxlite-ssh-gateway is a
# member of the top-level Cargo workspace and path-depends on
# ../session-frame, and cargo needs every workspace member's Cargo.toml
# present to resolve the workspace graph even though only these two crates
# get compiled.
FROM rust:1-slim-bookworm AS build

# ring (russh's crypto backend) compiles pregenerated assembly via a C
# compiler at build time — the slim base doesn't ship one.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /boxlite

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/boxlite/target \
    cargo build --release --locked -p boxlite-ssh-gateway \
    && cp target/release/boxlite-ssh-gateway /usr/local/bin/boxlite-ssh-gateway

FROM debian:bookworm-slim AS ssh-gateway

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --host-key-path's parent must exist (GatewayConfig::validate checks it);
# not a persisted volume yet, so the key regenerates on every task restart.
RUN mkdir -p /var/lib/boxlite-ssh-gateway

WORKDIR /usr/local/bin

COPY --from=build /usr/local/bin/boxlite-ssh-gateway boxlite-ssh-gateway

EXPOSE 2222

ENTRYPOINT ["boxlite-ssh-gateway"]

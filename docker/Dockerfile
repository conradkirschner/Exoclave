# syntax=docker/dockerfile:1.7
# Reproducible build chain for exoclave.
#
# The whole toolchain lives here so a contributor needs nothing but Docker —
# no Rust install, no MSVC, no platform-specific setup. `make check` runs the
# same commands CI does.
#
# Note on USB: a Linux container cannot claim a USB device on Windows or macOS.
# The runtime stage therefore ships the adb *client* and expects to reach an adb
# *server* running on the host:
#
#     host:      adb -a -P 5037 nodaemon server
#     container: ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
#
# That avoids USB passthrough entirely and keeps the container unprivileged.

ARG RUST_VERSION=1

# ---------------------------------------------------------------- builder ----
FROM rust:${RUST_VERSION}-alpine AS builder

# musl-dev provides the C runtime bits the linker needs for static binaries.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

# BuildKit cache mounts keep the registry and target dir warm between builds
# without baking them into a layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --workspace \
 && mkdir -p /out \
 && cp target/release/exoclave /out/exoclave

# ------------------------------------------------------------------- test ----
# Separate stage so `docker build --target test` runs the suite in the same
# environment the release binary is built in.
FROM builder AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo fmt --all -- --check \
 && cargo clippy --workspace --all-targets -- -D warnings \
 && cargo test --workspace

# ---------------------------------------------------------------- runtime ----
FROM alpine:3.21 AS runtime

# android-tools supplies the adb client used to reach the host's adb server.
RUN apk add --no-cache android-tools ca-certificates \
 && adduser -D -u 10001 scanner

COPY --from=builder /out/exoclave /usr/local/bin/exoclave

USER scanner
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/exoclave"]
CMD ["--help"]

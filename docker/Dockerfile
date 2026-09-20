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

# --------------------------------------------------------- windows binary ----
# Cross-compiles a native exoclave.exe. On Windows the usual reason to want
# this is that a Linux container cannot claim a USB device, so running on the
# host is simpler than wiring up an adb server over TCP.
FROM rust:${RUST_VERSION}-slim-bookworm AS windows-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends mingw-w64 \
 && rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

WORKDIR /src
COPY . .

# `rustup target add` must run *after* the source is in place. rust-toolchain.toml
# pins `channel = "stable"`, which is a different toolchain from the pinned
# version the base image ships as default — adding the target beforehand would
# attach it to the wrong one, and the build fails with "can't find crate for `core`".
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    rustup target add x86_64-pc-windows-gnu \
 && cargo build --release --target x86_64-pc-windows-gnu \
      -p ps-cli -p ps-gui --features ps-gui/desktop \
 && mkdir -p /out \
 && cp target/x86_64-pc-windows-gnu/release/exoclave.exe /out/exoclave.exe \
 && cp target/x86_64-pc-windows-gnu/release/exoclave-gui.exe /out/exoclave-gui.exe

# Export-only stage: `docker build --target windows -o type=local,dest=dist`
# drops both binaries into ./dist with no image left behind.
FROM scratch AS windows
COPY --from=windows-builder /out/exoclave.exe /exoclave.exe
COPY --from=windows-builder /out/exoclave-gui.exe /exoclave-gui.exe

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

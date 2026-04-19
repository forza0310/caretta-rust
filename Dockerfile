# syntax=docker/dockerfile:1.7

FROM rust:nightly-bookworm AS builder

WORKDIR /workspace

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        lld \
        pkg-config \
        libelf-dev \
        ca-certificates \
        binutils \
        tzdata \
    && ln -snf /usr/share/zoneinfo/PRC /etc/localtime \
    && echo PRC > /etc/timezone \
    && rustup component add rust-src \
    && cargo install --locked bpf-linker \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Build the Rust binary inside the image so the resulting executable is linked against the
# same libc that will be available in the runtime stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release -p caretta \
    && strip /workspace/target/release/caretta \
    && mv /workspace/target/release/caretta /tmp/caretta \
    && cargo clean \
    && apt-get purge -y --auto-remove \
        clang \
        llvm \
        lld \
        pkg-config \
        libelf-dev \
        ca-certificates \
        binutils \
        tzdata \
    && rm -rf /var/lib/apt/lists/* /usr/local/cargo/registry /usr/local/cargo/git

FROM debian:bookworm-slim AS runtime

ENV TZ=PRC \
    RUST_LOG=info

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
    && ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /tmp/caretta /app/caretta

EXPOSE 7117

ENTRYPOINT ["/app/caretta"]

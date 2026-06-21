# syntax=docker/dockerfile:1.7

# 与 caretta 主镜像不同:这是非特权、无 eBPF 的单实例控制面 collector,用 stable
# 工具链即可(无 nightly / bpf-linker)。
FROM rust:1.94-slim AS builder

WORKDIR /workspace

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && ln -snf /usr/share/zoneinfo/PRC /etc/localtime \
    && echo PRC > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release -p caretta-k8s-state

RUN strip /workspace/target/release/caretta-k8s-state \
    && mv /workspace/target/release/caretta-k8s-state /tmp/caretta-k8s-state \
    && cargo clean \
    && rm -rf /var/lib/apt/lists/* /usr/local/cargo/registry /usr/local/cargo/git

FROM debian:trixie-slim AS runtime

ENV TZ=PRC \
    RUST_LOG=info

RUN ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /tmp/caretta-k8s-state /app/caretta-k8s-state

EXPOSE 7118

ENTRYPOINT ["/app/caretta-k8s-state"]

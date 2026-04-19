FROM debian:bookworm-slim

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

# The CI workflow builds the Rust binary and places it under target/release/caretta.
# This Dockerfile only packages that already-built artifact into the runtime image.
COPY ./target/release/caretta /app/caretta

EXPOSE 7117

ENTRYPOINT ["/app/caretta"]

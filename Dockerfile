FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p mqx-server --bin mqextended \
    && install -m 0755 target/release/mqextended /usr/local/bin/mqextended

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/mqextended /usr/local/bin/mqextended
USER 65532:65532
ENTRYPOINT ["mqextended"]

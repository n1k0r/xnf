FROM ubuntu:hirsute
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    cargo \
    make \
    clang-11 \
    libelf-dev \
    zlib1g-dev
RUN cargo install cargo-deb

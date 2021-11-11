FROM ubuntu:latest

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
        git \
        build-essential \
        ca-certificates \
        cmake \
        libuv1-dev \
        libzmq3-dev \
        libsodium-dev \
        libpgm-dev \
        libnorm-dev \
        libgss-dev

ADD . /usr/src/p2pool
WORKDIR /usr/src/p2pool
RUN git submodule update --init --recursive && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j$(nproc)

# ---

FROM ubuntu:latest
COPY --from=0 /usr/src/p2pool/build/p2pool /

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
    libzmq5 \
    libuv1 \
      && \
    apt-get clean

RUN groupadd -r p2pool -g 1000 && \
    useradd -u 1000 -r -g p2pool -s /sbin/nologin -c "p2pool user" p2pool
RUN mkdir -p /home/p2pool/.p2pool && \
    chown p2pool.p2pool /home/p2pool /home/p2pool/.p2pool
USER p2pool

EXPOSE 3333
EXPOSE 37889

VOLUME /home/p2pool/.p2pool

WORKDIR /home/p2pool/.p2pool
ENTRYPOINT ["/p2pool"]

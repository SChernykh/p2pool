FROM ubuntu:22.04

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
        git \
        build-essential \
        ca-certificates \
        cmake \
        libuv1-dev \
        libssl-dev \
        libhwloc-dev

WORKDIR /usr/src
RUN git clone https://github.com/xmrig/xmrig.git && \
    mkdir xmrig/build && \
    cd xmrig/build && \
    cmake .. && \
    make -j$(nproc)

# ---

FROM ubuntu:22.04

COPY --from=0 /usr/src/xmrig/build/xmrig /

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
    libssl3 \
    libcrypto++8 \
    libhwloc15 \
      && \
    apt-get clean

WORKDIR /
ENTRYPOINT ["/xmrig"]

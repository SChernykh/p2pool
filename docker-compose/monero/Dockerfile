FROM ubuntu:latest
ARG MONERO_GIT_TAG="latest"

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
        git \
        ca-certificates \
        build-essential \
        pkg-config \
        cmake \
        libuv1-dev \
        libzmq3-dev \
        libsodium-dev \
        libpgm-dev \
        libnorm-dev \
        libgss-dev \
        libssl-dev \
        libzmq3-dev \
        libunbound-dev \
        libsodium-dev \
        libunwind8-dev \
        liblzma-dev \
        libreadline6-dev \
        libldns-dev \
        libexpat1-dev \
        libpgm-dev \
        qttools5-dev-tools \
        libhidapi-dev \
        libusb-1.0-0-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libudev-dev \
        libboost-chrono-dev \
        libboost-date-time-dev \
        libboost-filesystem-dev \
        libboost-locale-dev \
        libboost-program-options-dev \
        libboost-regex-dev \
        libboost-serialization-dev \
        libboost-system-dev \
        libboost-thread-dev \
        ccache \
        doxygen \
        graphviz

WORKDIR /usr/src
RUN git clone --recursive https://github.com/monero-project/monero && \
    cd monero && \
    if [ "x$MONERO_GIT_TAG" = "xlatest" ]; then MONERO_GIT_TAG=$(git describe --tags $(git rev-list --tags --max-count=1)); fi && \
    git checkout $MONERO_GIT_TAG && \
    git submodule sync && git submodule update --init --force --recursive && \
    make release-static -j$(nproc)

# ---

FROM ubuntu:latest

COPY --from=0 /usr/src/monero/build/Linux/*/release/bin/* /

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
    libgssapi-krb5-2 \
      && \
    apt-get clean

RUN groupadd -r monero -g 1000 && \
    useradd -u 1000 -r -g monero -s /sbin/nologin -c "monero node user" monero
RUN mkdir -p /home/monero/.bitmonero && \
    chown monero.monero /home/monero /home/monero/.bitmonero
USER monero

EXPOSE 18080 18081 18083

VOLUME /home/monero/.bitmonero

WORKDIR /home/monero
ENTRYPOINT ["/monerod"]

# Multistage docker build, requires docker 17.05

# builder stage
FROM ubuntu:20.04 as builder
ARG MONERO_GIT_TAG="latest"

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
        automake \
        autotools-dev \
        bsdmainutils \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        git \
        libtool \
        pkg-config \
        gperf


WORKDIR /src
RUN git clone --recursive https://github.com/monero-project/monero && \
    cd monero && \
    if [ "x$MONERO_GIT_TAG" = "xlatest" ]; then MONERO_GIT_TAG=$(git describe --tags $(git rev-list --tags --max-count=1)); fi && \
    git checkout $MONERO_GIT_TAG && \
    git submodule sync && git submodule update --init --force --recursive && \
    make -j$(nproc) depends target=$(contrib/depends/config.guess)

# ---

# runtime stage
FROM ubuntu:20.04

COPY --from=0 /src/monero/build/*/release/bin /usr/local/bin/

RUN set -e && \
    apt-get update -q -y --no-install-recommends && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -q -y --no-install-recommends \
      ca-certificates \
      netcat \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt

RUN groupadd -r monero -g 1000 && \
    adduser --uid 1000 --gid 1000 --system --disabled-password monero && \
	mkdir -p /home/monero/.bitmonero && \
	chown -R monero:monero /home/monero/.bitmonero

USER monero
WORKDIR /home/monero

EXPOSE 18080 18081 18083
VOLUME /home/monero/.bitmonero

ENTRYPOINT ["/usr/local/bin/monerod"]

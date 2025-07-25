FROM p2pool_build_ubuntu
ARG P2POOL_VERSION
ADD p2pool_macos_aarch64.sh /p2pool/
RUN /p2pool/p2pool_macos_aarch64.sh p2pool-${P2POOL_VERSION}-macos-aarch64 ${P2POOL_VERSION}

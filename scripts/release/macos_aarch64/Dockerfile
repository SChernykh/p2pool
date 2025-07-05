FROM p2pool_build_ubuntu
ARG P2POOL_VERSION BUILD_TIMESTAMP
ADD p2pool_macos_aarch64.sh zutil.patch /p2pool/
RUN /p2pool/p2pool_macos_aarch64.sh p2pool-${P2POOL_VERSION}-macos-aarch64 ${BUILD_TIMESTAMP} ${P2POOL_VERSION}

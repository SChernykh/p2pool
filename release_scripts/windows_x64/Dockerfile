FROM p2pool_build_ubuntu
ARG P2POOL_VERSION BUILD_TIMESTAMP
ADD p2pool.tar p2pool_windows_x64.sh intrin-impl.patch /p2pool/
RUN /p2pool/p2pool_windows_x64.sh p2pool-${P2POOL_VERSION}-windows-x64 ${BUILD_TIMESTAMP}

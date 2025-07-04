FROM p2pool_build_ubuntu
ARG P2POOL_VERSION BUILD_TIMESTAMP
ADD p2pool.tar p2pool_freebsd_x64.sh /p2pool/
RUN /p2pool/p2pool_freebsd_x64.sh p2pool-${P2POOL_VERSION}-freebsd-x64 ${BUILD_TIMESTAMP}

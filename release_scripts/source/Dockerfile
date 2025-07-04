FROM p2pool_build_ubuntu
ARG P2POOL_VERSION BUILD_TIMESTAMP
ADD p2pool_source.sh /root
RUN /root/p2pool_source.sh ${P2POOL_VERSION} ${BUILD_TIMESTAMP}

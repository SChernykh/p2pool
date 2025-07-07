FROM p2pool_compiler_tests_ubuntu
ARG P2POOL_VERSION GCC_VERSION
ADD test.sh test2.sh /p2pool/
RUN /p2pool/test.sh ${P2POOL_VERSION} ${GCC_VERSION}

FROM quay.io/pypa/manylinux_2_28_x86_64 AS build

ARG LIBSODIUM_VERSION=1.0.22
ARG MBEDTLS_VERSION=3.6.4
ARG PYTHON_TAGS="cp310-cp310 cp311-cp311 cp312-cp312 cp313-cp313 cp314-cp314 cp314-cp314t"

ENV PREFIX=/opt/onionlink-deps
ENV PKG_CONFIG_PATH=/opt/onionlink-deps/lib/pkgconfig:/opt/onionlink-deps/lib64/pkgconfig
ENV CMAKE_PREFIX_PATH=/opt/onionlink-deps

RUN dnf install -y cmake ninja-build pkgconf-pkg-config wget tar gzip make gcc gcc-c++ perl \
    && dnf clean all

WORKDIR /tmp/deps

RUN wget -O libsodium.tar.gz \
        "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" \
    && tar -xzf libsodium.tar.gz \
    && cd "libsodium-${LIBSODIUM_VERSION}" \
    && ./configure --prefix="${PREFIX}" --enable-shared --disable-static \
    && make -j"$(nproc)" \
    && make install

RUN wget -O mbedtls.tar.gz \
        "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2" \
    && tar -xjf mbedtls.tar.gz \
    && cmake -S "mbedtls-${MBEDTLS_VERSION}" -B mbedtls-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DENABLE_TESTING=OFF \
        -DENABLE_PROGRAMS=OFF \
        -DUSE_SHARED_MBEDTLS_LIBRARY=ON \
        -DUSE_STATIC_MBEDTLS_LIBRARY=OFF \
    && cmake --build mbedtls-build --parallel \
    && cmake --install mbedtls-build

ENV LD_LIBRARY_PATH=/opt/onionlink-deps/lib:/opt/onionlink-deps/lib64

WORKDIR /src
COPY . .

RUN mkdir -p /wheelhouse /tmp/raw-wheels \
    && for tag in ${PYTHON_TAGS}; do \
        python="/opt/python/${tag}/bin/python"; \
        "${python}" -m pip install --upgrade pip build auditwheel; \
        "${python}" -m pip wheel . --no-deps --wheel-dir /tmp/raw-wheels; \
      done \
    && for wheel in /tmp/raw-wheels/*.whl; do \
        auditwheel repair "$wheel" --plat manylinux_2_28_x86_64 --wheel-dir /wheelhouse; \
      done

FROM scratch AS wheels
COPY --from=build /wheelhouse /

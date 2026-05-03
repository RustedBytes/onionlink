FROM alpine:3.22 AS build

ARG LIBSODIUM_VERSION=1.0.22

RUN apk add --no-cache \
    build-base \
    ca-certificates \
    cmake \
    mbedtls-dev \
    pkgconf \
    wget

RUN wget -O /tmp/libsodium.tar.gz \
    "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" \
    && tar -xzf /tmp/libsodium.tar.gz -C /tmp \
    && cd "/tmp/libsodium-${LIBSODIUM_VERSION}" \
    && ./configure --prefix=/usr/local --disable-shared --enable-static \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/libsodium*

WORKDIR /src

COPY CMakeLists.txt ./
COPY src ./src

RUN cmake -S . -B /build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /build --parallel

FROM alpine:3.22

RUN apk add --no-cache \
    ca-certificates \
    libstdc++ \
    mbedtls

COPY --from=build /build/onionlink /usr/local/bin/onionlink

ENTRYPOINT ["onionlink"]
CMD ["--help"]

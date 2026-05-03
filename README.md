# onionlink

`onionlink` is a small C++20 Tor v3 onion-service client built with libsodium and mbedTLS. It talks directly to Tor relays, builds the minimum circuits needed for v3 onion-service access, and can exchange raw bytes or a simple HTTP request with the service.

Security and anonymity are explicit non-goals. This is a protocol experiment and interoperability tool, not a replacement for Tor Browser, Arti, or the Tor daemon.

## What It Implements

- Downloads and parses the live microdescriptor consensus.
- Hydrates relay microdescriptors to obtain Ed25519 identities and ntor keys.
- Derives the v3 onion-service blinded key and subcredential.
- Selects HSDirs and fetches the v3 descriptor over a guarded `EXTEND2` circuit.
- Decrypts unprotected v3 onion-service descriptors.
- Parses introduction points, including link specifiers, intro ntor keys, auth keys, and service encryption keys.
- Establishes a rendezvous point over a guarded `EXTEND2` circuit.
- Sends `INTRODUCE1` over a guarded intro-point circuit.
- Completes hs-ntor from `RENDEZVOUS2`.
- Opens a stream to `:<port>` and sends/receives relay data.

## Dependencies

- CMake 3.20 or newer
- A C++20 compiler
- `pkg-config`
- libsodium
- mbedTLS

On Arch Linux:

```sh
sudo pacman -S base-devel cmake libsodium mbedtls
```

On Debian/Ubuntu-style systems:

```sh
sudo apt install build-essential cmake pkg-config libsodium-dev libmbedtls-dev
```

## Build

```sh
cmake -S . -B build
cmake --build build
```

Or build the container image:

```sh
docker build -t onionlink .
```

## Usage

```sh
./build/onionlink <service-v3-address>.onion <port> [options]
```

Fetch `/` over HTTP from the container:

```sh
docker run --rm onionlink \
  archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion 80 \
  --http-get / \
  --verbose
```

Send raw text:

```sh
./build/onionlink <service-v3-address>.onion 1234 --send "hello"
```

Forward standard input:

```sh
printf 'hello\n' | ./build/onionlink <service-v3-address>.onion 1234 --stdin
```

## Options

- `--bootstrap host:port` selects the HTTP directory cache used for bootstrap.
  The default is `128.31.0.39:9131`.
- `--consensus-file path` uses a local microdescriptor consensus instead of downloading one.
- `--timeout-ms n` sets TCP/TLS read timeouts. The default is `30000`.
- `--http-get [path]` sends a simple HTTP/1.0 GET after connecting. If `path` is omitted, `/` is used.
- `--send text` sends raw text after the stream opens.
- `--stdin` forwards standard input after the stream opens.
- `--verbose` prints bootstrap, descriptor, intro, and rendezvous progress.

If no send mode is provided, `--http-get /` is used by default.

## Limitations

The implementation intentionally omits substantial parts of a real Tor client:

- no consensus, directory, relay, descriptor, or certificate signature validation;
- no relay-family, guard, path-bias, or anonymity-aware path selection;
- no bridges, pluggable transports, proxies, IPv6 dialing, or DNS helpers;
- no onion-service client authorization;
- no proof-of-work support for protected services;
- no authenticated SENDMEs or modern congestion-control behavior;
- no stream isolation, SOCKS server, circuit pooling, or persistent state;
- no traffic shaping or padding.

The client uses direct TLS connections to selected relays and short guarded circuits only where current relays require them, such as HSDir descriptor fetches, rendezvous establishment, and intro-point delivery.

## Notes

The default bootstrap source is a public Tor directory authority/cache endpoint.
Live behavior depends on relay reachability, descriptor availability, and the onion service accepting a connection at the requested port.

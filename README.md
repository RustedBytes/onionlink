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

Build Linux Python wheels with Docker:

```sh
docker build --target wheels --output type=local,dest=dist .
```

This writes Python 3.10+ manylinux wheels into `dist/`. The wheel build is
Linux-only and uses `auditwheel` to bundle libsodium and mbedTLS into the wheel.

Build a wheel directly on a Linux host with the native dependencies installed:

```sh
python -m pip wheel . -w dist
```

## Python Client

The Python package exposes an OOP session API. A `Session` downloads the
microdescriptor consensus and hydrates relay microdescriptors once, then reuses
that directory state for multiple onion-service requests. Request methods release
the Python GIL while doing network work, so one initialized session can be used
from `asyncio.to_thread`, a `ThreadPoolExecutor`, or regular worker threads.

```python
from concurrent.futures import ThreadPoolExecutor

from onionlink import Session

session = Session(timeout_ms=30_000, verbose=False)

def fetch(onion: str) -> bytes:
    return session.get(onion, port=80, path="/").body

onions = [
    "archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion",
]

with ThreadPoolExecutor(max_workers=4) as pool:
    for body in pool.map(fetch, onions):
        print(body[:200])
```

Raw request bytes are also supported:

```python
from onionlink import Session

session = Session(bootstrap="128.31.0.39:9131", timeout_ms=30_000)
response = session.raw_request(
    "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion",
    1234,
    b"hello\n",
)
```

Use `request()` for full HTTP control:

```python
from onionlink import Session

session = Session(timeout_ms=30_000)
response = session.request(
    "POST",
    "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion",
    port=80,
    path="/api/items",
    params={"trace": "1"},
    headers={"Accept": "application/json"},
    json={"name": "test"},
    response_limit=8 * 1024 * 1024,
)

response.raise_for_status()
print(response.status_code, response.header("content-type"))
print(response.text)
```

`Session` constructor arguments:

- `bootstrap`: HTTP directory cache as `host:port`.
- `consensus_file`: optional local `consensus-microdesc` file.
- `timeout_ms`: TCP/TLS read timeout.
- `verbose`: print native bootstrap and rendezvous progress to stderr.

Request methods:

- `request(method, onion, *, port=80, path="/", params=None, headers=None, body=None, data=None, json=None, form=None, host=None, http_version="HTTP/1.0", response_limit=4194304) -> Response`
- `get/head/post/put/patch/delete/options(onion, **request_options) -> Response`
- `raw_request(onion, port, payload=b"", response_limit=4194304) -> bytes`

`Response` exposes `status_code`, `reason`, `headers`, `body`, `raw`,
`http_version`, `ok`, `text`, `encoding`, `header(name)`, and
`raise_for_status()`.

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

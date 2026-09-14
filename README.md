<p align="center">
  <img src="assets/logo.png" alt="frogurl logo" width="420">
</p>

<h1 align="center">frogurl</h1>

<p align="center">
  <strong>A small, auditable HTTP/HTTPS command-line client written in C.</strong>
</p>

<p align="center">
  Familiar curl-style options, modern TLS through OpenSSL, streaming I/O, redirects, proxies, compression, and a tiny implementation focused only on the web protocols most people actually use.
</p>

---

## Overview

`frogurl` is a lightweight command-line HTTP/HTTPS client for users who want a smaller and easier-to-audit alternative for common web requests.

It deliberately focuses on **HTTP/1.1 and HTTPS** instead of trying to reproduce curl's very large protocol and feature surface.

The implementation uses:

- **libc / POSIX sockets** for networking and system I/O
- **OpenSSL** for TLS, certificate verification, SNI, and hostname/IP validation
- **zlib** for optional gzip/deflate decompression

The result is a compact native client that remains useful for real downloads, API calls, scripts, uploads, proxies, and everyday command-line work.

> `frogurl` is not a drop-in replacement for every curl feature.  
> It aims to cover the common HTTP/HTTPS workflow with substantially less code and complexity.

---

## Features

### HTTP and networking

- HTTP/1.1
- IPv4 and IPv6
- GET, HEAD, POST, PUT, PATCH, DELETE
- Arbitrary request methods with `-X` / `--request`
- DNS resolution through the system resolver
- Connection and socket I/O timeouts
- Streaming request and response bodies
- Responses handled through:
  - `Content-Length`
  - `Transfer-Encoding: chunked`
  - connection-close framing

### HTTPS / TLS

- HTTPS through OpenSSL
- TLS certificate verification enabled by default
- SNI support
- Hostname and IP-address verification
- System CA store
- Custom CA bundle with `--cacert`
- `-k` / `--insecure` for explicitly disabling peer verification

### Requests

- Custom headers with `-H` / `--header`
- Inline request bodies with `-d` / `--data`
- Binary, file, or stdin request bodies with `--data-binary`
- File uploads with `-T` / `--upload-file`
- Custom User-Agent with `-A` / `--user-agent`
- Basic authentication with `-u` / `--user`
- Fail on HTTP status >= 400 with `-f` / `--fail`

### Downloads and output

- Write response body to stdout
- Save to a specific path with `-o` / `--output`
- Preserve the remote filename with `-O` / `--remote-name`
- Automatic streaming: response bodies are not buffered in full
- Suitable for files much larger than available RAM
- Optional response headers in output with `-i` / `--include`

### Redirects

- Follow redirects with `-L` / `--location`
- Relative `Location:` resolution
- Configurable redirect limit
- Redirect behavior compatible with common curl expectations
- Credentials are not intentionally exposed to a different origin during redirect handling

### Compression

- gzip and deflate negotiation with `--compressed`
- Streaming decompression through zlib

### Proxy support

- HTTP proxy support
- HTTPS targets tunneled through an HTTP proxy using `CONNECT`
- Proxy Basic authentication with `--proxy-user`

### Progress meter

- Automatic progress display for interactive file downloads
- curl-compatible `-#` / `--progress-bar`
- Disable with:
  - `-s` / `--silent`
  - `--no-progress-meter`
- Known-size downloads display:
  - percentage
  - transferred bytes
  - transfer speed
  - ETA
- Unknown-size/chunked transfers display:
  - transferred bytes
  - transfer speed

### Script-friendly output

- `--status`
- `--meta`
- `--json-meta`
- Verbose HTTP/TLS tracing with `-v` / `--verbose`

---

## curl-style command-line options

`frogurl` intentionally keeps familiar option names for the features it implements.

| Purpose | Short option | Long option |
|---|---:|---|
| Request method | `-X` | `--request` |
| HEAD request | `-I` | `--head` |
| Request header | `-H` | `--header` |
| Form-style/raw data | `-d` | `--data` |
| Binary body |  | `--data-binary` |
| Upload file | `-T` | `--upload-file` |
| Output file | `-o` | `--output` |
| Remote filename | `-O` | `--remote-name` |
| Follow redirects | `-L` | `--location` |
| Proxy | `-x` | `--proxy` |
| Origin auth | `-u` | `--user` |
| Insecure TLS | `-k` | `--insecure` |
| Include headers | `-i` | `--include` |
| User-Agent | `-A` | `--user-agent` |
| Fail on HTTP errors | `-f` | `--fail` |
| Silent mode | `-s` | `--silent` |
| Verbose mode | `-v` | `--verbose` |
| Progress bar | `-#` | `--progress-bar` |

Additional supported long options include:

- `--cacert`
- `--compressed`
- `--connect-timeout`
- `--max-redirs`
- `--proxy-user`
- `--no-progress-meter`
- `--status`
- `--meta`
- `--json-meta`

---

## Dependencies

On Debian/Ubuntu:

```sh
sudo apt install clang lld make pkg-config libssl-dev zlib1g-dev
```

The runtime uses the system's shared OpenSSL, zlib, and libc libraries.

---

## Build

Normal build:

```sh
make
```

Size-oriented release build:

```sh
make release
```

The exact binary size depends on compiler version, linker, stripping, LTO, enabled hardening, and the target system.

---

## Quick start

Fetch a page:

```sh
frogurl https://example.com
```

Download a file and preserve its remote name:

```sh
frogurl -LO https://example.com/archive.tar.gz
```

Show only response headers:

```sh
frogurl -I https://example.com
```

Follow redirects:

```sh
frogurl -L https://example.com/redirect
```

Download with the progress bar:

```sh
frogurl -# -LO https://example.com/archive.tar.gz
```

---

## Request examples

### Custom headers

```sh
frogurl \
  -H 'Accept: application/json' \
  https://example.com/api
```

### POST data

```sh
frogurl \
  -d 'frog=green' \
  https://example.com/form
```

### JSON request

```sh
frogurl \
  -H 'Content-Type: application/json' \
  -d '{"frog":"green","status":"alive"}' \
  https://example.com/api
```

### Binary POST body

```sh
frogurl \
  --data-binary @payload.bin \
  -X POST \
  https://example.com/upload
```

### Upload a file

```sh
frogurl \
  -T image.iso \
  https://example.com/upload/image.iso
```

### Read request body from stdin

```sh
printf '%s' '{"hello":"frog"}' |
  frogurl \
    -H 'Content-Type: application/json' \
    --data-binary @- \
    -X POST \
    https://example.com/api
```

---

## Download examples

### Save to a chosen path

```sh
frogurl \
  -o archive.tar.gz \
  https://example.com/download
```

### Preserve the remote filename

```sh
frogurl \
  -O \
  https://example.com/archive.tar.gz
```

### Follow redirects and preserve filename

```sh
frogurl \
  -LO \
  https://example.com/archive.tar.gz
```

### Request compressed content

```sh
frogurl \
  --compressed \
  https://example.com
```

---

## Authentication

Basic authentication:

```sh
frogurl \
  -u user:password \
  https://example.com/private
```

`frogurl` also supports Basic proxy authentication through `--proxy-user`.

The verbose trace redacts `Authorization` and `Proxy-Authorization` values instead of printing credentials directly.

---

## Proxy examples

HTTP through an HTTP proxy:

```sh
frogurl \
  -x http://127.0.0.1:8080 \
  http://example.com
```

HTTPS through an HTTP proxy:

```sh
frogurl \
  -x http://127.0.0.1:8080 \
  https://example.com
```

For HTTPS targets, `frogurl` establishes an HTTP `CONNECT` tunnel and then performs TLS to the destination through that tunnel.

HTTPS proxy URLs themselves are currently not supported.

---

## TLS and certificates

Certificate verification is enabled by default.

Normal verified request:

```sh
frogurl https://example.com
```

Use a custom CA bundle:

```sh
frogurl \
  --cacert ./ca-bundle.pem \
  https://example.com
```

Disable verification explicitly:

```sh
frogurl -k https://example.com
```

> `-k` / `--insecure` disables peer verification and should only be used intentionally, for example with a local development endpoint or a known self-signed test certificate.

TLS cryptography and X.509 processing are delegated to OpenSSL rather than being reimplemented inside `frogurl`.

---

## Progress meter

When downloading to a file using `-o` or `-O` from an interactive terminal, `frogurl` shows a progress meter automatically.

Force the curl-style progress bar:

```sh
frogurl -# -LO https://example.com/archive.tar.gz
```

For a known transfer size, the display includes progress, bytes, speed, and ETA.

Example:

```text
frogurl [=================>          ]  63%  1.27 GiB / 2.00 GiB  24.8 MiB/s  ETA 00:30
```

For chunked responses or transfers without a known total size, `frogurl` still reports transferred bytes and current speed.

Disable the meter:

```sh
frogurl --no-progress-meter -O https://example.com/archive.tar.gz
```

or:

```sh
frogurl -s -O https://example.com/archive.tar.gz
```

---

## Metadata and scripting

Print only the HTTP status code:

```sh
frogurl --status https://example.com
```

Show compact response metadata:

```sh
frogurl --meta https://example.com
```

Emit metadata as JSON:

```sh
frogurl --json-meta https://example.com
```

This makes `frogurl` convenient in shell scripts where parsing human-oriented verbose output would be undesirable.

---

## Verbose mode

Use `-v` / `--verbose` to inspect the HTTP/TLS exchange:

```sh
frogurl -v https://example.com
```

Sensitive authentication headers are redacted in the verbose trace.

---

## Design

The program is intentionally small and straightforward.

Conceptually, a request flows through:

```text
CLI
 │
 ▼
URL parsing
 │
 ▼
DNS resolution
 │
 ▼
TCP connection
 │
 ├── HTTP ──────────────────────────────┐
 │                                     │
 └── HTTPS → OpenSSL TLS handshake ────┤
                                       ▼
                               HTTP/1.1 request
                                       │
                                       ▼
                               response headers
                                       │
                         ┌─────────────┼─────────────┐
                         ▼             ▼             ▼
                 Content-Length    chunked       connection-close
                         │             │             │
                         └─────────────┴─────────────┘
                                       │
                              optional decompression
                                       │
                                       ▼
                              stdout / output file
```

Response bodies are processed as streams rather than accumulated into one large memory buffer.

This keeps memory use mostly independent of download size.

---

## Scope

`frogurl` intentionally does **not** try to implement every protocol or feature available in curl.

Currently out of scope:

- FTP
- SFTP
- SCP
- SMTP
- IMAP
- HTTP/2
- HTTP/3
- QUIC
- NTLM
- Kerberos
- PAC
- DoH
- WebSockets
- persistent cookie jars

The narrow scope is intentional: fewer protocols and fewer compatibility layers mean a smaller codebase that is easier to inspect, build, and understand.

---

## Security notes

`frogurl` is a network-facing C program, so input received from remote servers must always be treated as untrusted.

Current security-oriented behavior includes:

- TLS delegated to OpenSSL
- certificate verification enabled by default
- hostname/IP verification for HTTPS
- system CA trust by default
- explicit `-k` required to disable certificate checks
- authorization values redacted from verbose output
- streaming response handling rather than blindly allocating based on remote object size
- bounded redirect handling

For security-sensitive deployments, building and testing with compiler sanitizers and fuzzing the URL, HTTP-header, redirect, chunked-transfer, and decompression paths is recommended.

---

## Why frogurl?

`curl` is an extraordinarily capable tool with decades of protocol support and compatibility.

`frogurl` has a different goal:

> **Do the common HTTP/HTTPS jobs well, with less code and less surface area.**

It is intended for:

- small Linux environments
- shell scripts
- downloading release artifacts
- simple API interaction
- embedded or minimal userlands where shared dependencies are available
- users who prefer a compact implementation they can read and audit

If you need curl's full protocol matrix, use curl.

If you mostly need the web, `frogurl` may be enough.

---

## License

MIT. See `LICENSE`.

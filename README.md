# frogurl

A small, auditable HTTP/HTTPS command-line client written in C.

`frogurl` intentionally focuses on HTTP rather than trying to reproduce curl's large protocol surface.
It uses libc for POSIX networking, OpenSSL for TLS, and zlib for optional gzip/deflate decoding.

## Features

- HTTP/1.1 over IPv4 and IPv6
- HTTPS with OpenSSL, SNI, hostname/IP verification, default CA store, `--cacert`, and `-k`
- GET, HEAD, POST, PUT, PATCH, DELETE, or arbitrary methods via `-X`
- Request headers (`-H`), inline data (`-d`), binary/file/stdin bodies (`--data-binary`), uploads (`-T`)
- Streaming downloads: response bodies are never buffered in full
- `Content-Length`, connection-close bodies, and chunked transfer decoding
- gzip/deflate negotiation and streaming decompression (`--compressed`)
- Redirect following (`-L`) with relative `Location:` resolution
- HTTP proxy support; HTTPS targets tunnel through an HTTP proxy using CONNECT
- Basic origin auth (`-u`) and proxy Basic auth (`--proxy-user`)
- Output to stdout, `-o FILE`, or `-O`
- Connect and socket I/O timeouts
- Verbose HTTP/TLS trace (`-v`)
- Script-friendly `--status`, `--meta`, and `--json-meta`
- `-f` failure mode for HTTP >= 400

## Dependencies

On Debian/Ubuntu:

```sh
sudo apt install clang lld make pkg-config libssl-dev zlib1g-dev
```

## Build

```sh
make
```

Size-oriented build:

```sh
make release
```

## Examples

```sh
frogurl https://example.com
frogurl -LO https://example.com/archive.tar.gz
frogurl -I https://example.com
frogurl -H 'Accept: application/json' https://example.com/api
frogurl -d 'frog=green' https://example.com/form
frogurl --data-binary @payload.bin -X POST https://example.com/upload
frogurl -T image.iso https://example.com/upload/image.iso
frogurl --compressed https://example.com
frogurl -L --json-meta https://example.com/redirect
frogurl -x http://127.0.0.1:8080 https://example.com
```

## Scope

This is deliberately **not** libcurl and does not implement FTP, SFTP, SCP, SMTP, IMAP, HTTP/2,
HTTP/3/QUIC, NTLM, Kerberos, PAC, DoH, WebSockets, or a persistent cookie jar.

HTTPS proxy URLs (`https://proxy/...`) are currently not supported. An `http://` proxy can proxy normal
HTTP requests and tunnel HTTPS targets with CONNECT.

## Security notes

TLS is delegated to OpenSSL rather than reimplemented. Certificate verification is on by default.
`-k/--insecure` disables peer verification and should only be used intentionally.

The verbose trace redacts `Authorization` and `Proxy-Authorization` values.

## License

MIT. See `LICENSE`.

## Progress meter

When downloading to a file with `-o` or `-O` from an interactive terminal, frogurl shows a progress bar automatically.
Use curl-compatible `-#` / `--progress-bar` to force it, `-s` / `--silent` or `--no-progress-meter` to disable it.

```sh
frogurl -# -LO https://example.com/archive.tar.gz
```

Known-length transfers show percentage, bytes, speed and ETA. Chunked/unknown-length transfers show bytes and speed.

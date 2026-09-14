# frogurl 1.2 — implementation and security review

Review date: 2026-09-14. Input: the user-supplied `frogurl.zip` source package.
The included v1.2 executable was built from the updated sources in this archive.

## FTP implementation

`src/ftp.c` implements streaming, binary passive FTP downloads (RETR) and uploads
(STOR). It supports anonymous or explicit login, EPSV over IPv4/IPv6, PASV fallback
on IPv4, percent-encoded path components, SIZE when available, file/stdin uploads,
progress and final transfer metadata. The network and progress code is shared
with HTTP. FTP adds no library dependency.

The data connection uses the actual control connection peer. An advertised PASV
IP cannot redirect it to another host. Ports are parsed with overflow checks.
Decoded NUL, CR, LF, other control characters, DEL and Telnet IAC in command
arguments are rejected before connecting. Multiline replies are bounded. Success
requires completion code 226 or 250 and, when known, the expected byte count.

This is a defined subset: no FTPS/SFTP, active mode, FTP proxy support, listing,
ASCII transfers, resume, raw FTP commands or automatic filename selection for
uploads to a directory URL. See README for accepted options and URL semantics.

## Issues corrected

| Area | Original behavior / impact | Change and validation |
| --- | --- | --- |
| HTTP status output | `output_headers()` used the untruncated `snprintf` return length to write a 512-byte stack buffer. A long remote reason phrase with `-i`/`-I` could disclose stack bytes or crash. | Allocate the full status line and write its actual length. A 2,000-character reason reproduces wrong output on the original and exact output on v1.2. ASan checks the case. |
| HTTP request injection | CR/LF in `-H`, `-A` or `-X` could create additional request lines/headers when arguments came from untrusted input. | Validate header names, method tokens and field values. The original accepted an injected header; v1.2 rejects it. |
| Protocol line parsing | Embedded NUL could make string-based parsing/accounting disagree with received bytes; partial lines and invalid control bytes were insufficiently checked. | Reject NUL, invalid controls and malformed CR sequences; fail partial lines; honor maximum line length. Binary line mutation tests cover 5,000 inputs. |
| HTTP framing | Partial numeric lengths, duplicate/conflicting length headers, unsupported transfer-encoding chains and non-hex chunk syntax could be accepted or misinterpreted. | Strict bounded decimal/hex parsing, duplicate/conflict rejection, supported-encoding checks and trailer validation. Request Content-Length must match its body; empty chunked requests are encoded correctly. |
| Resource bounds | Interim HTTP replies, trailers and CONNECT header sequences could be unbounded; large header counts caused excessive list processing. | HTTP headers: 1 MiB and 1,024 lines per block; at most 15 interim responses before the final response; trailers and CONNECT headers: 64 KiB; FTP replies: 64 KiB with 8 KiB lines. |
| Compressed response integrity | Truncated gzip/deflate streams could return success; extra gzip members or trailing bytes could be lost. | Require a complete compressed stream, validate checksums, decode concatenated gzip members, reject invalid/trailing/truncated data. Truncated gzip reproduced as success on the original and failure on v1.2. |
| Redirect credentials | Custom Cookie and Host values could cross an origin boundary. Custom Proxy-Authorization could reach a direct origin or an HTTPS tunnel endpoint. | Strip Authorization, Cookie and custom Host across origin changes; regenerate Host. Proxy-Authorization is limited to a plain HTTP proxy request. Redact outbound Cookie traces. |
| Redirect output filename | `-O` chose the basename from the final redirected URL, allowing the server to select another local filename. | Pin HTTP `-O` to the original URL basename. A temporary-file reproduction shows the original overwrote `victim`; v1.2 leaves it intact and writes `wanted`. |
| Automatic output links | Automatic `-O` output could follow a symlink or write through a hard link. | Open without following symlinks, inspect the opened inode, require a regular file with one link, then truncate. HTTP and FTP tests verify victim files remain unchanged. |
| TLS I/O | WANT_READ/WANT_WRITE retry loops could outlive socket timeouts. An unclean TLS EOF could be accepted on some error paths/library versions. | Nonblocking I/O with poll deadlines for TLS handshake/read/write and plain socket I/O. Require proper TLS closure for EOF-delimited TLS responses. Stalled handshake, body and upload tests terminate. |
| HTTPS proxy CONNECT | The authority omitted the port when the target used default HTTPS port 443. | Always send host:port, including bracketed IPv6. A local CONNECT/TLS fixture checks `localhost:443`. |
| URL and numeric parsing | Out-of-range ports, invalid/unbracketed IPv6, non-finite timeouts and malformed numeric arguments were accepted. Relative URL normalization could change repeated slashes or trailing dot-segment semantics. | Strict parsing, canonical numeric ports, finite timeouts and IPv6 validation. Preserve repeated HTTP slashes and correct dot-segment/query resolution. |
| Redirect bodies | A stdin upload could be retried after 301/302 without rewind; body headers could survive a redirect that changed the method to GET. | Reject every redirect requiring stdin replay; strip body-related headers when dropping the body. Block HTTP-to-FTP redirects. |
| Upload source changes | A file length measured before upload could differ from the opened file, or a growing file could send more than advertised. | Check the opened regular file's size, cap sent bytes to the expected size and reject size changes/truncation. FTP opens its source before connecting. This does not snapshot file contents. |
| Output/metadata | Combining HTTP metadata and an output filename skipped the download. Output-close errors were ignored. | Download to the requested file while printing metadata to stdout; propagate close/write errors. Failed progress displays do not claim 100% success. |
| Build/API checks | Build depended on pkg-config and a hardcoded Clang release command. Error-pointer handling was inconsistent. | GCC/Clang support, standard linker fallback, explicit error-pointer checks; PIE, stack protection, FORTIFY, full RELRO and non-executable stack retained in release builds. |

The stack disclosure and redirect-selected filename issues have direct remote-input
triggers. Request injection depends on passing untrusted text as command-line
options. These are review findings, not assigned CVEs or formal severity scores.

## Validation

- The 12 checks shipped in `tests/run_tests.py` pass.
- All 39 test methods in `tests/test_protocols.py` pass; several contain multiple
  malformed-input and option subcases.
- The final release and AddressSanitizer/UndefinedBehaviorSanitizer builds are
  tested independently using local HTTP, HTTPS, CONNECT and FTP fixtures.
- The parser mutation smoke test passes 50,000 generated cases and 5,000 binary
  line inputs with ASan/UBSan. This is deterministic mutation testing, not a
  coverage-guided fuzzing campaign.
- GCC 13 `-fanalyzer` completed for every translation unit without diagnostics.
- Four focused reproductions were run on both the original and updated code:
  long status output, header injection, truncated gzip, and redirect-controlled
  local filenames. All four fail the safety/correctness check on the original
  and pass on v1.2.
- TLS tests verify trusted certificate/IP, wrong hostname, untrusted certificate,
  explicit `-k`, clean fixed-length responses, unclean EOF, and timeouts.
- IPv6 loopback FTP was available and passed; it was not skipped.

The `validation/` directory records successful release/sanitizer tests, parser
mutation results, static-analysis results and the original/new comparison.

LeakSanitizer cannot inspect process threads in this execution environment, so
`ASAN_OPTIONS=detect_leaks=0` was required. Address and undefined-behavior checks
remained active. No claim of runtime leak-check coverage is made.

## Remaining limits

This review and these tests do not establish the absence of all vulnerabilities.
Testing used local fixtures; interoperability with every real FTP server, proxy,
TLS backend and operating system has not been established. External system
libraries and their advisory/patch status are outside this source audit.

Plain FTP sends passwords and data without encryption. Synchronous DNS resolution
is not covered by the TCP connect timeout. Socket timeouts are per operation,
not a total transfer deadline; local stdin reads have no socket timeout. There is
no total download or decompression-output quota. Partial output files can remain
after failure. Explicit `-o` paths retain normal symlink-following behavior.

The parser intentionally rejects ambiguous framing and unsupported protocol
features; this can reject permissive/nonconforming servers. Source compatibility
is POSIX/Linux-focused; the shipped binary is Linux x86_64 and dynamically linked.

## Protocol references

Implementation decisions were checked against the original specifications:
[RFC 959 — FTP](https://www.rfc-editor.org/rfc/rfc959),
[RFC 2428 — EPSV](https://www.rfc-editor.org/rfc/rfc2428),
[RFC 3659 — SIZE](https://www.rfc-editor.org/rfc/rfc3659),
[RFC 1738 — FTP URL components](https://www.rfc-editor.org/rfc/rfc1738),
[RFC 3986 — URI resolution](https://www.rfc-editor.org/rfc/rfc3986), and
[RFC 9112 — HTTP/1.1 framing](https://www.rfc-editor.org/rfc/rfc9112).
The `//directory/file` absolute-path shorthand is a documented convenience;
encoded `%2F` directory components implement explicit absolute FTP paths.

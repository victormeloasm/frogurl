#include "frogurl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/err.h>

static char *fmt_err(const char *fmt, ...) {
    if (!fmt) die("frogurl: missing diagnostic format");
    va_list ap;
    va_start(ap, fmt);
    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (n < 0) { va_end(ap); return xstrdup("diagnostic formatting failed"); }
    char *s = xmalloc((size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

static long long io_deadline(int ms) {
    return ms > 0 ? monotonic_ms() + ms : 0;
}

static int wait_socket(int fd, short events, long long deadline) {
    for (;;) {
        long long left = deadline ? deadline - monotonic_ms() : -1;
        if (deadline && left <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd pfd = { .fd = fd, .events = events };
        int rc = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (rc > 0) return 0;
        if (!rc) { errno = ETIMEDOUT; return -1; }
        if (errno != EINTR) return -1;
    }
}

static int tcp_connect(const char *host, const char *port, int timeout_ms, int verbose, char **err) {
    struct addrinfo hints, *res = NULL, *it;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        *err = fmt_err("DNS resolution failed for %s:%s: %s", host, port, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    int last_errno = ECONNREFUSED;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            last_errno = errno;
            close(fd); fd = -1; continue;
        }

        if (verbose) {
            char hbuf[128], sbuf[32];
            if (getnameinfo(it->ai_addr, it->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                fprintf(stderr, "* Trying %s:%s...\n", hbuf, sbuf);
        }

        int rc = connect(fd, it->ai_addr, it->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            last_errno = errno;
            close(fd); fd = -1; continue;
        }
        if (rc < 0) {
            rc = wait_socket(fd, POLLOUT, io_deadline(timeout_ms));
            if (rc < 0) {
                last_errno = errno;
                close(fd); fd = -1; continue;
            }
            int soerr = 0; socklen_t sl = sizeof(soerr);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr) {
                last_errno = soerr ? soerr : errno;
                close(fd); fd = -1; continue;
            }
        }

        if (verbose) fprintf(stderr, "* Connected to %s:%s\n", host, port);
        break;
    }

    freeaddrinfo(res);
    if (fd < 0) *err = fmt_err("connection to %s:%s failed: %s", host, port, strerror(last_errno));
    return fd;
}

static int tls_start(Connection *c, const char *host, const Options *opt, char **err) {
    c->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ssl_ctx) { *err = xstrdup("SSL_CTX_new failed"); return -1; }

    if (SSL_CTX_set_min_proto_version(c->ssl_ctx, TLS1_2_VERSION) != 1) {
        *err = xstrdup("cannot set TLS minimum version"); return -1;
    }
    if (opt->insecure) {
        SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (opt->cacert) {
            if (SSL_CTX_load_verify_locations(c->ssl_ctx, opt->cacert, NULL) != 1) {
                *err = fmt_err("failed to load CA file: %s", opt->cacert);
                return -1;
            }
        } else if (SSL_CTX_set_default_verify_paths(c->ssl_ctx) != 1) {
            *err = xstrdup("failed to load default CA paths");
            return -1;
        }
    }

    c->ssl = SSL_new(c->ssl_ctx);
    if (!c->ssl) { *err = xstrdup("SSL_new failed"); return -1; }
    unsigned char ip[16];
    int is_ip = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;
    if (SSL_set_fd(c->ssl, c->fd) != 1 || (!is_ip && SSL_set_tlsext_host_name(c->ssl, host) != 1)) {
        *err = xstrdup("cannot configure TLS connection"); return -1;
    }

    if (!opt->insecure) {
        unsigned char tmp[16];
        X509_VERIFY_PARAM *param = SSL_get0_param(c->ssl);
        if (inet_pton(AF_INET, host, tmp) == 1 || inet_pton(AF_INET6, host, tmp) == 1) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, host) != 1) {
                *err = xstrdup("failed to set TLS IP verification target");
                return -1;
            }
        } else if (SSL_set1_host(c->ssl, host) != 1) {
            *err = xstrdup("failed to set TLS hostname verification target");
            return -1;
        }
    }

    if (opt->verbose) fprintf(stderr, "* TLS handshake with %s...\n", host);
    long long deadline = io_deadline(c->io_timeout_ms);
    for (;;) {
        ERR_clear_error();
        int rc = SSL_connect(c->ssl);
        if (rc == 1) break;
        int e = SSL_get_error(c->ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(c->fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline)) continue;
            *err = xstrdup("TLS handshake timed out or failed"); return -1;
        }
        unsigned long detail = ERR_get_error();
        const char *msg = detail ? ERR_reason_error_string(detail) : NULL;
        *err = fmt_err("TLS error: %s", msg ? msg : "handshake failed"); return -1;
    }
    c->tls = 1;
    if (opt->verbose) {
        X509 *cert = SSL_get1_peer_certificate(c->ssl);
        fprintf(stderr, "* TLS %s / %s\n", SSL_get_version(c->ssl), SSL_get_cipher(c->ssl));
        if (cert) {
            char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            if (subj) { fprintf(stderr, "* Server certificate: %s\n", subj); OPENSSL_free(subj); }
            X509_free(cert);
        }
    }
    return 0;
}

ssize_t conn_read_raw(Connection *c, void *buf, size_t len) {
    if (!len) return 0;
    long long deadline = io_deadline(c->io_timeout_ms);
    for (;;) {
        short event = POLLIN;
        if (!c->tls) {
            ssize_t n = recv(c->fd, buf, len, 0);
            if (n >= 0) return n;
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        } else {
            ERR_clear_error();
            int n = SSL_read(c->ssl, buf, (int)(len > INT_MAX ? INT_MAX : len));
            if (n > 0) return n;
            int e = SSL_get_error(c->ssl, n);
            if (e == SSL_ERROR_ZERO_RETURN) return 0;
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                /* An unclean TLS EOF must not mark a truncated download successful. */
                errno = EIO; return -1;
            }
            event = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        }
        if (wait_socket(c->fd, event, deadline)) return -1;
    }
}

int conn_write_all(Connection *c, const void *buf, size_t len) {
    const unsigned char *p = buf;
    long long deadline = io_deadline(c->io_timeout_ms);
    while (len) {
        ssize_t n;
        short event = POLLOUT;
        if (!c->tls) {
            n = send(c->fd, p, len, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            if (!n) { errno = EIO; return -1; }
        } else {
            ERR_clear_error();
            n = SSL_write(c->ssl, p, (int)(len > INT_MAX ? INT_MAX : len));
            if (n <= 0) {
                int e = SSL_get_error(c->ssl, (int)n);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) { errno = EIO; return -1; }
                event = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            }
        }
        if (n > 0) { p += (size_t)n; len -= (size_t)n; }
        else if (wait_socket(c->fd, event, deadline)) return -1;
    }
    return 0;
}

ssize_t conn_read(Connection *c, void *buf, size_t len) {
    unsigned char *out = buf;
    size_t got = 0;
    if (c->rpos < c->rlen) {
        size_t avail = c->rlen - c->rpos;
        size_t take = avail < len ? avail : len;
        memcpy(out, c->rbuf + c->rpos, take);
        c->rpos += take;
        out += take; len -= take; got += take;
        return (ssize_t)got;
    }
    ssize_t n = conn_read_raw(c, out, len);
    if (n < 0) return got ? (ssize_t)got : -1;
    return (ssize_t)(got + (size_t)n);
}

int conn_read_line(Connection *c, char **line, size_t max_len) {
    *line = NULL;
    size_t cap = max_len < 127 ? max_len + 1 : 128, n = 0;
    char *s = xmalloc(cap);
    for (;;) {
        if (c->rpos == c->rlen) {
            ssize_t r = conn_read_raw(c, c->rbuf, sizeof(c->rbuf));
            if (r <= 0) { free(s); if (r == 0 && n) { errno = EPROTO; return -1; } return r == 0 ? 0 : -1; }
            c->rpos = 0; c->rlen = (size_t)r;
        }
        unsigned char ch = c->rbuf[c->rpos++];
        if ((ch < 32 && ch != '\r' && ch != '\n' && ch != '\t') || ch == 127 ||
            (n && s[n-1] == '\r' && ch != '\n')) { free(s); errno = EPROTO; return -1; }
        if (n + 1 >= cap) {
            cap *= 2;
            if (cap > max_len + 1) cap = max_len + 1;
            if (n + 1 >= cap) { free(s); errno = EMSGSIZE; return -1; }
            s = realloc(s, cap);
            if (!s) die("frogurl: out of memory");
        }
        s[n++] = ch;
        if (ch == '\n') break;
        if (n >= max_len) { free(s); errno = EMSGSIZE; return -1; }
    }
    s[n] = 0;
    *line = s;
    return 1;
}

static int proxy_connect_tunnel(Connection *c, const Url *target, const Options *opt, char **err) {
    size_t host_len = strlen(target->host) + strlen(target->port) + 4;
    char *host = xmalloc(host_len);
    snprintf(host, host_len, strchr(target->host, ':') ? "[%s]:%s" : "%s:%s", target->host, target->port);
    char *auth = NULL;
    if (opt->proxy_auth) auth = base64_basic(opt->proxy_auth);
    size_t cap = strlen(host) * 2 + (auth ? strlen(auth) : 0) + 256;
    char *req = xmalloc(cap);
    int n = snprintf(req, cap,
        "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n%s%s%s\r\n",
        host, host,
        auth ? "Proxy-Authorization: Basic " : "",
        auth ? auth : "",
        auth ? "\r\n" : "");
    if (n < 0 || (size_t)n >= cap || conn_write_all(c, req, (size_t)n) != 0) {
        *err = xstrdup("failed to send proxy CONNECT request");
        free(host); free(auth); free(req); return -1;
    }
    if (opt->verbose) fprintf(stderr, "> CONNECT %s HTTP/1.1\n", host);
    free(host); free(auth); free(req);

    char *line = NULL;
    int rr = conn_read_line(c, &line, 65536);
    if (rr <= 0) { *err = xstrdup("proxy closed connection during CONNECT"); return -1; }
    int status = 0;
    if (parse_http_status(line, &status) != 0) {
        *err = xstrdup("invalid proxy CONNECT response"); free(line); return -1;
    }
    if (opt->verbose) fprintf(stderr, "< %s", line);
    free(line);
    size_t header_bytes = 0;
    for (;;) {
        line = NULL;
        rr = conn_read_line(c, &line, 65536);
        if (rr <= 0) { *err = xstrdup("truncated proxy CONNECT response"); return -1; }
        header_bytes += strlen(line);
        if (header_bytes > 65536) { free(line); *err = xstrdup("proxy CONNECT headers too large"); return -1; }
        if (opt->verbose) fprintf(stderr, "< %s", line);
        int blank = !strcmp(line, "\r\n") || !strcmp(line, "\n");
        free(line);
        if (blank) break;
    }
    if (status < 200 || status >= 300) {
        *err = fmt_err("proxy CONNECT failed with HTTP %d", status);
        return -1;
    }
    if (c->rpos != c->rlen) { *err = xstrdup("unexpected bytes after CONNECT headers"); return -1; }
    c->rpos = c->rlen = 0;
    return 0;
}

int conn_open(Connection *c, const Url *target, const Url *proxy, const Options *opt, char **err) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->verbose = opt->verbose;
    c->io_timeout_ms = opt->io_timeout_ms;
    if (!err) { errno = EINVAL; return -1; }
    *err = NULL;

    if (proxy && (proxy->https || proxy->ftp)) {
        *err = xstrdup("HTTPS proxies are not supported; use an http:// proxy (HTTPS targets use CONNECT)");
        return -1;
    }

    const Url *peer = proxy ? proxy : target;
    c->fd = tcp_connect(peer->host, peer->port, opt->connect_timeout_ms, opt->verbose, err);
    if (c->fd < 0) return -1;

    if (proxy && target->https) {
        if (proxy_connect_tunnel(c, target, opt, err) != 0) { conn_close(c); return -1; }
    }
    if (target->https) {
        if (tls_start(c, target->host, opt, err) != 0) { conn_close(c); return -1; }
    }
    return 0;
}

/* Ignore the host advertised by PASV: pin data to the actual control peer. */
int conn_open_peer(Connection *c, const Connection *control, unsigned port, const Options *opt, char **err) {
    memset(c, 0, sizeof(*c)); c->fd = -1; c->io_timeout_ms = opt->io_timeout_ms;
    if (!err) { errno = EINVAL; return -1; }
    *err = NULL;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    char host[128], service[6];
    if (!port || port > 65535 || getpeername(control->fd, (struct sockaddr *)&addr, &len) ||
        getnameinfo((struct sockaddr *)&addr, len, host, sizeof(host), NULL, 0, NI_NUMERICHOST)) {
        *err = xstrdup("cannot determine FTP control peer"); return -1;
    }
    snprintf(service, sizeof(service), "%u", port);
    c->fd = tcp_connect(host, service, opt->connect_timeout_ms, opt->verbose, err);
    return c->fd < 0 ? -1 : 0;
}

void conn_close(Connection *c) {
    if (!c) return;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ssl_ctx) SSL_CTX_free(c->ssl_ctx);
    if (c->fd >= 0) close(c->fd);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

#include "frogurl.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

typedef struct {
    char *p;
    size_t n;
    size_t cap;
} StrBuf;

static void sb_init(StrBuf *b) {
    b->cap = 1024;
    b->n = 0;
    b->p = xmalloc(b->cap);
    b->p[0] = 0;
}

static void sb_need(StrBuf *b, size_t add) {
    if (b->n + add + 1 <= b->cap) return;
    while (b->n + add + 1 > b->cap) b->cap *= 2;
    b->p = realloc(b->p, b->cap);
    if (!b->p) die("frogurl: out of memory");
}

static void sb_addn(StrBuf *b, const char *s, size_t n) {
    sb_need(b, n);
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void sb_add(StrBuf *b, const char *s) { sb_addn(b, s, strlen(s)); }

static void sb_printf(StrBuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (n < 0) { va_end(ap); return; }
    sb_need(b, (size_t)n);
    vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)n;
}

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

Header *header_add(Header **list, const char *name, const char *value) {
    Header *h = xcalloc(1, sizeof(*h));
    h->name = xstrdup(name);
    h->value = xstrdup(value);
    if (!*list) *list = h;
    else {
        Header *p = *list;
        while (p->next) p = p->next;
        p->next = h;
    }
    return h;
}

const char *header_get(const Header *list, const char *name) {
    for (; list; list = list->next) if (strieq(list->name, name)) return list->value;
    return NULL;
}

int header_exists(const Header *list, const char *name) { return header_get(list, name) != NULL; }

void headers_free(Header *h) {
    while (h) {
        Header *n = h->next;
        free(h->name); free(h->value); free(h);
        h = n;
    }
}

void response_free(Response *r) {
    if (!r) return;
    free(r->reason);
    free(r->location);
    free(r->content_type);
    free(r->server);
    headers_free(r->headers);
    memset(r, 0, sizeof(*r));
}

static int contains_token_ci(const char *s, const char *tok) {
    size_t tn = strlen(tok);
    while (*s) {
        while (*s && (isspace((unsigned char)*s) || *s == ',')) ++s;
        const char *e = s;
        while (*e && *e != ',' && *e != ';') ++e;
        const char *t = e;
        while (t > s && isspace((unsigned char)t[-1])) --t;
        if ((size_t)(t - s) == tn) {
            size_t i;
            for (i = 0; i < tn; ++i)
                if (tolower((unsigned char)s[i]) != tolower((unsigned char)tok[i])) break;
            if (i == tn) return 1;
        }
        s = *e ? e + 1 : e;
    }
    return 0;
}

static int parse_status_and_headers(Connection *c, Response *r, const Options *opt, char **err) {
    for (unsigned interim = 0;; ++interim) {
        if (interim >= 16) { *err = xstrdup("too many interim HTTP responses"); return -1; }
        char *line = NULL;
        int rr = conn_read_line(c, &line, 65536);
        if (rr <= 0) { *err = xstrdup("server closed connection before response status"); return -1; }
        if (opt->verbose) fprintf(stderr, "< %s", line);

        int status = 0;
        if (parse_http_status(line, &status)) {
            free(line); *err = xstrdup("invalid HTTP status line"); return -1;
        }
        char *reason = trim_dup(line + 12);
        free(line);

        Header *headers = NULL;
        size_t header_bytes = 0, header_count = 0;
        for (;;) {
            line = NULL;
            rr = conn_read_line(c, &line, 65536);
            if (rr <= 0) { free(line); headers_free(headers); free(reason); *err = xstrdup("truncated HTTP headers"); return -1; }
            header_bytes += strlen(line);
            if (header_bytes > 1024 * 1024 || ++header_count > 1024) {
                free(line); headers_free(headers); free(reason);
                *err = xstrdup("HTTP response headers exceed size/count limit");
                return -1;
            }
            if (opt->verbose) fprintf(stderr, "< %s", line);
            if (!strcmp(line, "\r\n") || !strcmp(line, "\n")) { free(line); break; }
            char *colon = strchr(line, ':');
            if (colon) *colon = 0;
            if (!colon || !valid_token(line)) {
                free(line); headers_free(headers); free(reason);
                *err = xstrdup("invalid HTTP header name"); return -1;
            }
            char *name = xstrdup(line);
            char *value = trim_dup(colon + 1);
            size_t vn = strlen(value);
            while (vn && (value[vn - 1] == '\r' || value[vn - 1] == '\n')) value[--vn] = 0;
            if (!valid_field_value(value)) {
                free(name); free(value); free(line); headers_free(headers); free(reason);
                *err = xstrdup("invalid HTTP header value"); return -1;
            }
            header_add(&headers, name, value);
            free(name); free(value); free(line);
        }

        if (status >= 100 && status < 200 && status != 101) {
            if (opt->verbose) fprintf(stderr, "* Ignoring interim HTTP %d response\n", status);
            headers_free(headers);
            free(reason);
            continue;
        }

        r->status = status;
        r->reason = reason;
        r->headers = headers;
        break;
    }

    if (r->status == 101) { *err = xstrdup("HTTP protocol upgrades are not supported"); return -1; }
    const char *v;
    unsigned cl = 0, te = 0, ce = 0;
    for (Header *h = r->headers; h; h = h->next) {
        cl += strieq(h->name, "Content-Length");
        te += strieq(h->name, "Transfer-Encoding");
        ce += strieq(h->name, "Content-Encoding");
    }
    if (cl > 1 || te > 1 || ce > 1 || (cl && te)) {
        *err = xstrdup("ambiguous or duplicate HTTP framing/encoding headers"); return -1;
    }
    if ((v = header_get(r->headers, "Content-Length"))) {
        unsigned long long n;
        if (parse_decimal(v, LLONG_MAX, &n)) { *err = xstrdup("invalid HTTP Content-Length"); return -1; }
        r->content_length = (long long)n; r->has_content_length = 1;
    }
    if ((v = header_get(r->headers, "Transfer-Encoding"))) {
        if (!strieq(v, "chunked")) { *err = xstrdup("unsupported HTTP Transfer-Encoding"); return -1; }
        r->chunked = 1;
    }
    if ((v = header_get(r->headers, "Content-Encoding"))) {
        r->gzip = strieq(v, "gzip"); r->deflate = strieq(v, "deflate");
        if (opt->compressed && !r->gzip && !r->deflate && !strieq(v, "identity")) {
            *err = xstrdup("unsupported HTTP Content-Encoding"); return -1;
        }
    }
    if ((v = header_get(r->headers, "Connection"))) r->connection_close = contains_token_ci(v, "close");
    if ((v = header_get(r->headers, "Location"))) r->location = xstrdup(v);
    if ((v = header_get(r->headers, "Content-Type"))) r->content_type = xstrdup(v);
    if ((v = header_get(r->headers, "Server"))) r->server = xstrdup(v);
    return 0;
}

static int send_file_body(Connection *c, const char *path, int chunked, off_t expected, char **err) {
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) { *err = fmt_err("cannot open request body file '%s': %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != expected) {
        close(fd); *err = xstrdup("request body file changed before upload"); return -1;
    }
    off_t sent = 0;
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            *err = fmt_err("read failed on '%s': %s", path, strerror(errno));
            close(fd); return -1;
        }
        if (!n) break;
        if (n > expected - sent) { close(fd); *err = xstrdup("request body file grew during upload"); return -1; }
        sent += n;
        if (chunked) {
            char head[32];
            int hn = snprintf(head, sizeof(head), "%zx\r\n", (size_t)n);
            if (conn_write_all(c, head, (size_t)hn) || conn_write_all(c, buf, (size_t)n) || conn_write_all(c, "\r\n", 2)) {
                *err = xstrdup("failed while sending chunked request body"); close(fd); return -1;
            }
        } else if (conn_write_all(c, buf, (size_t)n)) {
            *err = xstrdup("failed while sending request body"); close(fd); return -1;
        }
    }
    close(fd);
    if (sent != expected) { *err = xstrdup("request body file shrank during upload"); return -1; }
    if (chunked && conn_write_all(c, "0\r\n\r\n", 5)) { *err = xstrdup("failed to finish chunked request body"); return -1; }
    return 0;
}

static int send_stdin_body(Connection *c, char **err) {
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            *err = fmt_err("stdin read failed: %s", strerror(errno)); return -1;
        }
        if (!n) break;
        char head[32];
        int hn = snprintf(head, sizeof(head), "%zx\r\n", (size_t)n);
        if (conn_write_all(c, head, (size_t)hn) || conn_write_all(c, buf, (size_t)n) || conn_write_all(c, "\r\n", 2)) {
            *err = xstrdup("failed while sending stdin request body"); return -1;
        }
    }
    if (conn_write_all(c, "0\r\n\r\n", 5)) { *err = xstrdup("failed to finish stdin request body"); return -1; }
    return 0;
}

static int send_request(Connection *c, const Url *u, const Url *proxy, const Options *opt, const char *method, char **err) {
    unsigned cl = 0, te = 0, host_count = 0;
    for (Header *h = opt->headers; h; h = h->next) {
        cl += strieq(h->name, "Content-Length");
        te += strieq(h->name, "Transfer-Encoding");
        host_count += strieq(h->name, "Host");
    }
    if (!opt->strip_body_headers) {
        const char *length = header_get(opt->headers, "Content-Length");
        const char *encoding = header_get(opt->headers, "Transfer-Encoding");
        unsigned long long n = 0;
        if (cl > 1 || te > 1 || (cl && te) ||
            (length && (parse_decimal(length, LLONG_MAX, &n) ||
              (opt->body.type == BODY_NONE ? n != 0 : (!opt->body.length_known || n != (unsigned long long)opt->body.length)))) ||
            (encoding && (!strieq(encoding, "chunked") || opt->body.type == BODY_NONE))) {
            *err = xstrdup("invalid or conflicting request body framing headers"); return -1;
        }
    }
    if (host_count > 1) { *err = xstrdup("duplicate Host header"); return -1; }
    char *host = url_host_header(u);
    char *absolute = NULL;
    const char *target = u->path;
    if (proxy && !u->https) {
        absolute = url_to_string(u);
        target = absolute;
    }

    StrBuf b;
    sb_init(&b);
    sb_printf(&b, "%s %s HTTP/1.1\r\n", method, target);
    if (opt->strip_authorization || !header_exists(opt->headers, "Host")) sb_printf(&b, "Host: %s\r\n", host);
    if (!header_exists(opt->headers, "User-Agent")) sb_printf(&b, "User-Agent: %s\r\n", opt->user_agent ? opt->user_agent : "frogurl/1.2");
    if (!header_exists(opt->headers, "Accept")) sb_add(&b, "Accept: */*\r\n");
    if (!header_exists(opt->headers, "Connection")) sb_add(&b, "Connection: close\r\n");
    if (opt->compressed && !header_exists(opt->headers, "Accept-Encoding")) sb_add(&b, "Accept-Encoding: gzip, deflate\r\n");

    char *auth = NULL;
    if (!opt->strip_authorization && opt->basic_auth && !header_exists(opt->headers, "Authorization")) {
        auth = base64_basic(opt->basic_auth);
        sb_printf(&b, "Authorization: Basic %s\r\n", auth);
    }
    char *pauth = NULL;
    if (proxy && !u->https && opt->proxy_auth && !header_exists(opt->headers, "Proxy-Authorization")) {
        pauth = base64_basic(opt->proxy_auth);
        sb_printf(&b, "Proxy-Authorization: Basic %s\r\n", pauth);
    }

    int body_present = opt->body.type != BODY_NONE;
    int chunked_upload = 0;
    if (body_present && !header_exists(opt->headers, "Content-Length") && !header_exists(opt->headers, "Transfer-Encoding")) {
        if (opt->body.length_known) sb_printf(&b, "Content-Length: %lld\r\n", (long long)opt->body.length);
        else { sb_add(&b, "Transfer-Encoding: chunked\r\n"); chunked_upload = 1; }
    } else if (body_present && header_exists(opt->headers, "Transfer-Encoding")) {
        const char *te = header_get(opt->headers, "Transfer-Encoding");
        chunked_upload = te && contains_token_ci(te, "chunked");
    }
    if (body_present && !header_exists(opt->headers, "Content-Type") && opt->body.type == BODY_MEMORY)
        sb_add(&b, "Content-Type: application/x-www-form-urlencoded\r\n");

    for (Header *h = opt->headers; h; h = h->next) {
        if (opt->strip_authorization && (strieq(h->name, "Authorization") || strieq(h->name, "Cookie") || strieq(h->name, "Host"))) continue;
        if ((!proxy || u->https) && strieq(h->name, "Proxy-Authorization")) continue;
        if (opt->strip_body_headers && (strieq(h->name, "Content-Length") || strieq(h->name, "Transfer-Encoding") ||
                                       strieq(h->name, "Content-Type") || strieq(h->name, "Expect"))) continue;
        sb_printf(&b, "%s: %s\r\n", h->name, h->value);
    }
    sb_add(&b, "\r\n");

    if (opt->verbose) {
        char *tmp = xstrdup(b.p);
        char *save = NULL;
        for (char *ln = strtok_r(tmp, "\r\n", &save); ln; ln = strtok_r(NULL, "\r\n", &save)) {
            if (stristarts(ln, "Authorization:") || stristarts(ln, "Proxy-Authorization:") || stristarts(ln, "Cookie:"))
                fprintf(stderr, "> %.*s: <redacted>\n", (int)(strchr(ln, ':') - ln), ln);
            else fprintf(stderr, "> %s\n", ln);
        }
        free(tmp);
        fprintf(stderr, ">\n");
    }

    if (conn_write_all(c, b.p, b.n)) {
        *err = xstrdup("failed to send HTTP request headers");
        free(host); free(absolute); free(auth); free(pauth); free(b.p); return -1;
    }
    free(host); free(absolute); free(auth); free(pauth); free(b.p);

    if (!body_present) return 0;
    switch (opt->body.type) {
        case BODY_MEMORY:
            if (chunked_upload) {
                if (!opt->body.mem_len) {
                    if (conn_write_all(c, "0\r\n\r\n", 5)) { *err = xstrdup("failed to send empty body"); return -1; }
                    break;
                }
                char head[32];
                int hn = snprintf(head, sizeof(head), "%zx\r\n", opt->body.mem_len);
                if (conn_write_all(c, head, (size_t)hn) ||
                    conn_write_all(c, opt->body.mem, opt->body.mem_len) ||
                    conn_write_all(c, "\r\n0\r\n\r\n", 7)) {
                    *err = xstrdup("failed to send request body"); return -1;
                }
            } else if (conn_write_all(c, opt->body.mem, opt->body.mem_len)) {
                *err = xstrdup("failed to send request body"); return -1;
            }
            break;
        case BODY_FILE:
            return send_file_body(c, opt->body.file_path, chunked_upload, opt->body.length, err);
        case BODY_STDIN:
            if (!chunked_upload) { *err = xstrdup("stdin body requires chunked transfer encoding"); return -1; }
            return send_stdin_body(c, err);
        default: break;
    }
    return 0;
}

typedef struct {
    int fd;
    int own_fd;
    int decompress;
    z_stream zs;
    int zinit;
    int zend;
    int gzip;
    long long written;
} Sink;

static int sink_open(Sink *s, const char *path, int remote_name, int gzip, int deflate, int compressed, char **err) {
    memset(s, 0, sizeof(*s));
    s->fd = STDOUT_FILENO;
    if (path) {
        s->fd = output_open(path, remote_name, err);
        if (s->fd < 0) return -1;
        s->own_fd = 1;
    }
    if (compressed && (gzip || deflate)) {
        memset(&s->zs, 0, sizeof(s->zs));
        int wb = gzip ? 16 + MAX_WBITS : MAX_WBITS;
        if (inflateInit2(&s->zs, wb) != Z_OK) {
            if (s->own_fd) close(s->fd);
            *err = xstrdup("zlib initialization failed"); return -1;
        }
        s->decompress = 1;
        s->zinit = 1;
        s->gzip = gzip;
    }
    return 0;
}

static int sink_output(Sink *s, const unsigned char *buf, size_t len, char **err) {
    if (len > (unsigned long long)(LLONG_MAX - s->written)) { *err = xstrdup("output byte count overflow"); return -1; }
    if (write_all_fd(s->fd, buf, len)) { *err = fmt_err("output write failed: %s", strerror(errno)); return -1; }
    s->written += (long long)len; return 0;
}

static int sink_write(Sink *s, const unsigned char *buf, size_t len, char **err) {
    if (!s->decompress) return sink_output(s, buf, len, err);
    unsigned char out[16384];
    s->zs.next_in = (Bytef *)buf;
    s->zs.avail_in = (uInt)len;
    for (;;) {
        if (s->zend) {
            if (!s->zs.avail_in) break;
            if (!s->gzip) { *err = xstrdup("trailing data after deflate stream"); return -1; }
            Bytef *next = s->zs.next_in; uInt avail = s->zs.avail_in;
            if (inflateReset(&s->zs) != Z_OK) { *err = xstrdup("gzip reset failed"); return -1; }
            s->zs.next_in = next; s->zs.avail_in = avail; s->zend = 0;
        }
        s->zs.next_out = out; s->zs.avail_out = sizeof(out);
        uInt before = s->zs.avail_in;
        int rc = inflate(&s->zs, Z_NO_FLUSH);
        size_t produced = sizeof(out) - s->zs.avail_out;
        if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            *err = xstrdup("invalid compressed response (data or checksum)"); return -1;
        }
        if (produced && sink_output(s, out, produced, err)) return -1;
        if (rc == Z_STREAM_END) { s->zend = 1; continue; }
        if (!s->zs.avail_in && s->zs.avail_out) break;
        if (before == s->zs.avail_in && !produced) { *err = xstrdup("compressed response made no progress"); return -1; }
    }
    return 0;
}

static int sink_finish(Sink *s, char **err) {
    if (s->decompress && !s->zend) { *err = xstrdup("truncated compressed response"); return -1; }
    return 0;
}

static int sink_close(Sink *s) {
    if (s->zinit) inflateEnd(&s->zs);
    return s->own_fd ? close(s->fd) : 0;
}

static int output_headers(Sink *sink, const Response *r, char **err) {
    char *line = fmt_err("HTTP/1.1 %d %s\r\n", r->status, r->reason ? r->reason : "");
    int rc = write_all_fd(sink->fd, line, strlen(line));
    free(line);
    if (rc) { *err = fmt_err("output write failed: %s", strerror(errno)); return -1; }
    for (Header *h = r->headers; h; h = h->next) {
        size_t need = strlen(h->name) + strlen(h->value) + 5;
        char *hs = xmalloc(need);
        snprintf(hs, need, "%s: %s\r\n", h->name, h->value);
        int rc = write_all_fd(sink->fd, hs, strlen(hs));
        free(hs);
        if (rc) {
            *err = fmt_err("output write failed: %s", strerror(errno));
            return -1;
        }
    }
    if (write_all_fd(sink->fd, "\r\n", 2)) {
        *err = fmt_err("output write failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int read_exact(Connection *c, unsigned char *buf, size_t len, char **err) {
    while (len) {
        ssize_t n = conn_read(c, buf, len);
        if (n < 0) { *err = fmt_err("response read failed: %s", strerror(errno)); return -1; }
        if (n == 0) { *err = xstrdup("unexpected EOF in response body"); return -1; }
        buf += (size_t)n; len -= (size_t)n;
    }
    return 0;
}

static int read_chunked_body(Connection *c, Sink *sink, Response *r, Progress *prog, char **err) {
    unsigned char buf[16384];
    for (;;) {
        char *line = NULL;
        int rr = conn_read_line(c, &line, 65536);
        if (rr <= 0) { *err = xstrdup("truncated chunked response"); free(line); return -1; }
        char *semi = strchr(line, ';');
        if (semi) *semi = 0;
        char *end = NULL;
        errno = 0;
        unsigned long long n = strtoull(line, &end, 16);
        while (end && *end && isspace((unsigned char)*end)) ++end;
        int valid_hex = end != line;
        const char *hex_end = semi ? semi : line + strcspn(line, "\r\n");
        for (const char *p = line; p < hex_end; ++p) if (!isxdigit((unsigned char)*p)) valid_hex = 0;
        if (errno || !valid_hex || n > LLONG_MAX || (end && *end)) { free(line); *err = xstrdup("invalid HTTP chunk size"); return -1; }
        free(line);
        if (n == 0) {
            size_t trailer_bytes = 0;
            for (;;) {
                line = NULL;
                rr = conn_read_line(c, &line, 65536);
                if (rr <= 0) { free(line); *err = xstrdup("truncated chunk trailer"); return -1; }
                trailer_bytes += strlen(line);
                if (trailer_bytes > 65536) { free(line); *err = xstrdup("HTTP trailers exceed 64 KiB"); return -1; }
                if (!strcmp(line, "\r\n") || !strcmp(line, "\n")) { free(line); break; }
                char *colon = strchr(line, ':');
                if (colon) *colon = 0;
                if (!colon || !valid_token(line) || strieq(line, "Content-Length") || strieq(line, "Transfer-Encoding")) {
                    free(line); *err = xstrdup("invalid HTTP trailer"); return -1;
                }
                free(line);
            }
            break;
        }
        unsigned long long left = n;
        while (left) {
            size_t take = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
            if (read_exact(c, buf, take, err)) return -1;
            if (sink_write(sink, buf, take, err)) return -1;
            progress_add(prog, take);
            left -= take;
        }
        unsigned char crlf[2];
        if (read_exact(c, crlf, 2, err)) return -1;
        if (crlf[0] != '\r' || crlf[1] != '\n') { *err = xstrdup("malformed chunk terminator"); return -1; }
    }
    r->body_bytes = sink->written;
    return 0;
}

static int read_fixed_body(Connection *c, Sink *sink, Response *r, long long length, Progress *prog, char **err) {
    unsigned char buf[16384];
    long long left = length;
    while (left > 0) {
        size_t want = left > (long long)sizeof(buf) ? sizeof(buf) : (size_t)left;
        ssize_t n = conn_read(c, buf, want);
        if (n < 0) { *err = fmt_err("response read failed: %s", strerror(errno)); return -1; }
        if (n == 0) { *err = xstrdup("unexpected EOF in fixed-length response"); return -1; }
        if (sink_write(sink, buf, (size_t)n, err)) return -1;
        progress_add(prog, (size_t)n);
        left -= n;
    }
    r->body_bytes = sink->written;
    return 0;
}

static int read_to_eof(Connection *c, Sink *sink, Response *r, Progress *prog, char **err) {
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = conn_read(c, buf, sizeof(buf));
        if (n < 0) { *err = fmt_err("response read failed: %s", strerror(errno)); return -1; }
        if (n == 0) break;
        if (sink_write(sink, buf, (size_t)n, err)) return -1;
        progress_add(prog, (size_t)n);
    }
    r->body_bytes = sink->written;
    return 0;
}

static int is_redirect_status(int s) { return s == 301 || s == 302 || s == 303 || s == 307 || s == 308; }

static int same_origin(const Url *a, const Url *b) {
    return strieq(a->scheme, b->scheme) && strieq(a->host, b->host) && !strcmp(a->port, b->port);
}

static int body_allowed(const char *method, int status) {
    if (strieq(method, "HEAD")) return 0;
    if (status >= 100 && status < 200) return 0;
    if (status == 204 || status == 304) return 0;
    return 1;
}

static char *choose_output_path(const Url *u, const Options *opt) {
    if (opt->output_path) return xstrdup(opt->output_path);
    if (opt->remote_name) return url_remote_name(u);
    return NULL;
}

static int one_transaction(const Url *u, const Url *proxy, const Options *opt, const char *method,
                           Response *resp, int suppress_body, int suppress_redirect_body, char **err) {
    Connection c;
    if (conn_open(&c, u, proxy, opt, err) != 0) return -1;
    if (send_request(&c, u, proxy, opt, method, err) != 0) { conn_close(&c); return -1; }
    if (parse_status_and_headers(&c, resp, opt, err) != 0) { conn_close(&c); return -1; }

    int redirect_suppressed = suppress_redirect_body && is_redirect_status(resp->status) && resp->location;
    int no_body = !body_allowed(method, resp->status);
    int fail_suppressed = opt->fail_http && resp->status >= 400;
    if (suppress_body || redirect_suppressed || no_body || fail_suppressed) {
        if (!suppress_body && !redirect_suppressed && (opt->include_headers || strieq(method, "HEAD"))) {
            char *hpath = choose_output_path(u, opt);
            Sink hsink;
            if (sink_open(&hsink, hpath, opt->remote_name, 0, 0, 0, err) != 0) {
                free(hpath); conn_close(&c); return -1;
            }
            free(hpath);
            int hrc = output_headers(&hsink, resp, err);
            if (sink_close(&hsink) && !hrc) { *err = xstrdup("output close failed"); hrc = -1; }
            if (hrc) { conn_close(&c); return -1; }
        }
        conn_close(&c);
        return 0;
    }

    char *path = choose_output_path(u, opt);
    int output_is_file = path != NULL;
    Sink sink;
    if (sink_open(&sink, path, opt->remote_name, resp->gzip, resp->deflate, opt->compressed, err) != 0) {
        free(path); conn_close(&c); return -1;
    }
    free(path);

    if (opt->include_headers && output_headers(&sink, resp, err) != 0) {
        sink_close(&sink); conn_close(&c); return -1;
    }

    Progress prog;
    memset(&prog, 0, sizeof(prog));
    int metadata_mode = opt->status_only || opt->meta || opt->json_meta;
    int default_progress = output_is_file && isatty(STDERR_FILENO);
    prog.enabled = !opt->silent && !metadata_mode && !opt->no_progress_meter &&
                   (opt->progress_bar || default_progress);
    prog.total = (!resp->chunked && resp->has_content_length) ? resp->content_length : -1;
    prog.start_ms = monotonic_ms();
    if (prog.enabled) progress_render(&prog, 0);

    int rc;
    if (resp->chunked) rc = read_chunked_body(&c, &sink, resp, &prog, err);
    else if (resp->has_content_length) rc = read_fixed_body(&c, &sink, resp, resp->content_length, &prog, err);
    else rc = read_to_eof(&c, &sink, resp, &prog, err);

    if (!rc && sink_finish(&sink, err)) rc = -1;
    if (prog.enabled) { if (!rc) progress_render(&prog, 1); else fputc('\n', stderr); }
    resp->body_bytes = sink.written;
    if (sink_close(&sink) && !rc) { *err = xstrdup("output close failed"); rc = -1; }
    conn_close(&c);
    return rc;
}

int http_transaction(const Url *url, const Options *opt, Response *resp, char **effective_url, char **err) {
    if (!err) { errno = EINVAL; return -1; }
    *err = NULL;
    if (effective_url) *effective_url = NULL;
    long long start = monotonic_ms();
    char *current = url_to_string(url);
    char *method = xstrdup(opt->method ? opt->method : "GET");
    int redirects = 0;
    int send_body = opt->body.type != BODY_NONE;
    int allow_auth = 1;

    Url proxy;
    int have_proxy = 0;
    memset(&proxy, 0, sizeof(proxy));
    if (opt->proxy) {
        if (url_parse(opt->proxy, &proxy, err) != 0) { free(current); free(method); return -1; }
        if (!strieq(proxy.scheme, "http")) {
            url_free(&proxy); free(current); free(method);
            *err = xstrdup("proxy URL must use http://"); return -1;
        }
        have_proxy = 1;
    }

    for (;;) {
        Url u;
        if (url_parse(current, &u, err) != 0) {
            if (have_proxy) url_free(&proxy);
            free(current); free(method);
            return -1;
        }
        if (u.ftp) {
            url_free(&u); if (have_proxy) url_free(&proxy); free(current); free(method);
            *err = xstrdup("HTTP redirects to FTP are not allowed"); return -1;
        }
        response_free(resp);

        Options ropt = *opt;
        if (!send_body) {
            memset(&ropt.body, 0, sizeof(ropt.body));
            ropt.strip_body_headers = opt->body.type != BODY_NONE;
        }
        if (!allow_auth) {
            ropt.basic_auth = NULL;
            ropt.strip_authorization = 1;
        }

        int metadata_only = (opt->status_only || opt->meta || opt->json_meta) && !opt->output_path && !opt->remote_name;
        if (one_transaction(&u, have_proxy ? &proxy : NULL, &ropt, method, resp,
                            metadata_only, opt->follow_redirects, err) != 0) {
            url_free(&u);
            if (have_proxy) url_free(&proxy);
            free(current); free(method);
            return -1;
        }

        if (opt->follow_redirects && is_redirect_status(resp->status) && resp->location) {
            if (redirects >= opt->max_redirects) {
                *err = fmt_err("too many redirects (max %d)", opt->max_redirects);
                url_free(&u);
                if (have_proxy) url_free(&proxy);
                free(current); free(method);
                return -1;
            }

            char *next = url_resolve(&u, resp->location);
            Url nu;
            if (url_parse(next, &nu, err) != 0) {
                free(next); url_free(&u);
                if (have_proxy) url_free(&proxy);
                free(current); free(method);
                return -1;
            }

            if (!same_origin(&u, &nu)) allow_auth = 0;

            int switch_to_get = (resp->status == 303 && !strieq(method, "HEAD")) ||
                                ((resp->status == 301 || resp->status == 302) && strieq(method, "POST"));
            if (switch_to_get) {
                free(method);
                method = xstrdup("GET");
                send_body = 0;
            } else if (send_body && opt->body.type == BODY_STDIN) {
                *err = xstrdup("cannot replay stdin request body across a redirect");
                url_free(&nu); free(next); url_free(&u);
                if (have_proxy) url_free(&proxy);
                free(current); free(method);
                return -1;
            }

            if (opt->verbose) fprintf(stderr, "* Redirect %d -> %s\n", resp->status, next);
            free(current);
            current = next;
            ++redirects;
            url_free(&nu);
            url_free(&u);
            continue;
        }

        resp->elapsed_ms = monotonic_ms() - start;
        if (effective_url) *effective_url = xstrdup(current);
        url_free(&u);
        if (have_proxy) url_free(&proxy);
        free(current);
        free(method);
        return 0;
    }
}

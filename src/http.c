#include "frogurl.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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
    va_list ap;
    va_start(ap, fmt);
    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
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
    for (;;) {
        char *line = NULL;
        int rr = conn_read_line(c, &line, 65536);
        if (rr <= 0) { *err = xstrdup("server closed connection before response status"); return -1; }
        if (opt->verbose) fprintf(stderr, "< %s", line);

        int status = 0;
        char *sp1 = strchr(line, ' ');
        if (!sp1 || strncmp(line, "HTTP/", 5) || sscanf(sp1 + 1, "%d", &status) != 1) {
            free(line);
            *err = xstrdup("invalid HTTP status line");
            return -1;
        }
        char *sp2 = strchr(sp1 + 1, ' ');
        char *reason = sp2 ? trim_dup(sp2 + 1) : xstrdup("");
        size_t rn = strlen(reason);
        while (rn && (reason[rn - 1] == '\r' || reason[rn - 1] == '\n')) reason[--rn] = 0;
        free(line);

        Header *headers = NULL;
        size_t header_bytes = 0;
        for (;;) {
            line = NULL;
            rr = conn_read_line(c, &line, 65536);
            if (rr <= 0) { free(line); headers_free(headers); free(reason); *err = xstrdup("truncated HTTP headers"); return -1; }
            header_bytes += strlen(line);
            if (header_bytes > 1024 * 1024) {
                free(line); headers_free(headers); free(reason);
                *err = xstrdup("HTTP response headers exceed 1 MiB");
                return -1;
            }
            if (opt->verbose) fprintf(stderr, "< %s", line);
            if (!strcmp(line, "\r\n") || !strcmp(line, "\n")) { free(line); break; }
            char *colon = strchr(line, ':');
            if (!colon) { free(line); continue; }
            *colon = 0;
            char *name = trim_dup(line);
            char *value = trim_dup(colon + 1);
            size_t vn = strlen(value);
            while (vn && (value[vn - 1] == '\r' || value[vn - 1] == '\n')) value[--vn] = 0;
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

    const char *v;
    if ((v = header_get(r->headers, "Content-Length"))) {
        char *end = NULL;
        errno = 0;
        long long n = strtoll(v, &end, 10);
        if (!errno && end != v && n >= 0) { r->content_length = n; r->has_content_length = 1; }
    }
    if ((v = header_get(r->headers, "Transfer-Encoding"))) r->chunked = contains_token_ci(v, "chunked");
    if ((v = header_get(r->headers, "Content-Encoding"))) {
        r->gzip = contains_token_ci(v, "gzip");
        r->deflate = contains_token_ci(v, "deflate");
    }
    if ((v = header_get(r->headers, "Connection"))) r->connection_close = contains_token_ci(v, "close");
    if ((v = header_get(r->headers, "Location"))) r->location = xstrdup(v);
    if ((v = header_get(r->headers, "Content-Type"))) r->content_type = xstrdup(v);
    if ((v = header_get(r->headers, "Server"))) r->server = xstrdup(v);
    return 0;
}

static int send_file_body(Connection *c, const char *path, int chunked, char **err) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { *err = fmt_err("cannot open request body file '%s': %s", path, strerror(errno)); return -1; }
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            *err = fmt_err("read failed on '%s': %s", path, strerror(errno));
            close(fd); return -1;
        }
        if (!n) break;
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
    if (!header_exists(opt->headers, "Host")) sb_printf(&b, "Host: %s\r\n", host);
    if (!header_exists(opt->headers, "User-Agent")) sb_printf(&b, "User-Agent: %s\r\n", opt->user_agent ? opt->user_agent : "frogurl/1.0");
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
        if (opt->strip_authorization && strieq(h->name, "Authorization")) continue;
        sb_printf(&b, "%s: %s\r\n", h->name, h->value);
    }
    sb_add(&b, "\r\n");

    if (opt->verbose) {
        char *tmp = xstrdup(b.p);
        char *save = NULL;
        for (char *ln = strtok_r(tmp, "\r\n", &save); ln; ln = strtok_r(NULL, "\r\n", &save)) {
            if (stristarts(ln, "Authorization:") || stristarts(ln, "Proxy-Authorization:"))
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
            return send_file_body(c, opt->body.file_path, chunked_upload, err);
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
    long long written;
} Sink;

typedef struct {
    int enabled;
    long long total;
    long long done;
    long long start_ms;
    long long last_ms;
} Progress;

static void human_bytes(double n, char out[24]) {
    static const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int i = 0;
    while (n >= 1024.0 && i < 4) { n /= 1024.0; ++i; }
    if (i == 0) snprintf(out, 24, "%.0f %s", n, u[i]);
    else if (n >= 100.0) snprintf(out, 24, "%.0f %s", n, u[i]);
    else if (n >= 10.0) snprintf(out, 24, "%.1f %s", n, u[i]);
    else snprintf(out, 24, "%.2f %s", n, u[i]);
}

static void progress_render(Progress *p, int final) {
    if (!p || !p->enabled) return;
    long long now = monotonic_ms();
    if (!final && p->last_ms && now - p->last_ms < 100) return;
    p->last_ms = now;

    double secs = (now - p->start_ms) / 1000.0;
    if (secs < 0.001) secs = 0.001;
    char done[24], total[24], speed[24];
    human_bytes((double)p->done, done);
    human_bytes((double)p->done / secs, speed);

    if (p->total > 0) {
        int pct = (int)((p->done * 100) / p->total);
        if (pct > 100) pct = 100;
        const int width = 28;
        int fill = (pct * width) / 100;
        char bar[29];
        for (int i = 0; i < width; ++i) bar[i] = i < fill ? '=' : ' ';
        if (!final && fill < width) bar[fill] = '>';
        bar[width] = 0;
        human_bytes((double)p->total, total);
        long long eta = 0;
        if (p->done > 0 && p->done < p->total) eta = (long long)(((p->total - p->done) * secs) / p->done);
        fprintf(stderr, "\rfrogurl [%s] %3d%%  %s / %s  %s/s  ETA %02lld:%02lld",
                bar, final ? 100 : pct, done, total, speed, eta / 60, eta % 60);
    } else {
        const char spin[] = "|/-\\";
        unsigned si = (unsigned)((now / 120) & 3);
        fprintf(stderr, "\rfrogurl [%c] %s  %s/s", spin[si], done, speed);
    }
    if (final) fputc('\n', stderr);
    fflush(stderr);
}

static void progress_add(Progress *p, size_t n) {
    if (!p || !p->enabled) return;
    p->done += (long long)n;
    progress_render(p, 0);
}

static int sink_open(Sink *s, const char *path, int gzip, int deflate, int compressed, char **err) {
    memset(s, 0, sizeof(*s));
    s->fd = STDOUT_FILENO;
    if (path) {
        s->fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
        if (s->fd < 0) { *err = fmt_err("cannot open output '%s': %s", path, strerror(errno)); return -1; }
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
    }
    return 0;
}

static int sink_write(Sink *s, const unsigned char *buf, size_t len, char **err) {
    if (!s->decompress) {
        if (write_all_fd(s->fd, buf, len)) { *err = fmt_err("output write failed: %s", strerror(errno)); return -1; }
        s->written += (long long)len;
        return 0;
    }

    unsigned char out[16384];
    s->zs.next_in = (Bytef *)buf;
    s->zs.avail_in = (uInt)len;
    while (s->zs.avail_in) {
        s->zs.next_out = out;
        s->zs.avail_out = sizeof(out);
        int rc = inflate(&s->zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            *err = fmt_err("compressed response decode failed: %s", s->zs.msg ? s->zs.msg : "zlib error");
            return -1;
        }
        size_t produced = sizeof(out) - s->zs.avail_out;
        if (produced && write_all_fd(s->fd, out, produced)) { *err = fmt_err("output write failed: %s", strerror(errno)); return -1; }
        s->written += (long long)produced;
        if (rc == Z_STREAM_END) break;
    }
    return 0;
}

static int sink_finish(Sink *s, char **err) {
    if (s->decompress) {
        unsigned char out[16384];
        for (;;) {
            s->zs.next_in = NULL;
            s->zs.avail_in = 0;
            s->zs.next_out = out;
            s->zs.avail_out = sizeof(out);
            int rc = inflate(&s->zs, Z_FINISH);
            size_t produced = sizeof(out) - s->zs.avail_out;
            if (produced && write_all_fd(s->fd, out, produced)) { *err = fmt_err("output write failed: %s", strerror(errno)); return -1; }
            s->written += (long long)produced;
            if (rc == Z_STREAM_END || rc == Z_BUF_ERROR) break;
            if (rc != Z_OK) { *err = xstrdup("compressed response finalization failed"); return -1; }
        }
    }
    return 0;
}

static void sink_close(Sink *s) {
    if (s->zinit) inflateEnd(&s->zs);
    if (s->own_fd) close(s->fd);
}

static int output_headers(Sink *sink, const Response *r, char **err) {
    char line[512];
    int n = snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", r->status, r->reason ? r->reason : "");
    if (n < 0 || write_all_fd(sink->fd, line, (size_t)n)) {
        *err = fmt_err("output write failed: %s", strerror(errno));
        return -1;
    }
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
        if (errno || end == line || (end && *end)) { free(line); *err = xstrdup("invalid HTTP chunk size"); return -1; }
        free(line);
        if (n == 0) {
            for (;;) {
                line = NULL;
                rr = conn_read_line(c, &line, 65536);
                if (rr <= 0) { free(line); *err = xstrdup("truncated chunk trailer"); return -1; }
                if (!strcmp(line, "\r\n") || !strcmp(line, "\n")) { free(line); break; }
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
            if (sink_open(&hsink, hpath, 0, 0, 0, err) != 0) {
                free(hpath); conn_close(&c); return -1;
            }
            free(hpath);
            int hrc = output_headers(&hsink, resp, err);
            sink_close(&hsink);
            if (hrc) { conn_close(&c); return -1; }
        }
        conn_close(&c);
        return 0;
    }

    char *path = choose_output_path(u, opt);
    int output_is_file = path != NULL;
    Sink sink;
    if (sink_open(&sink, path, resp->gzip, resp->deflate, opt->compressed, err) != 0) {
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
    if (prog.enabled) progress_render(&prog, rc == 0);
    resp->body_bytes = sink.written;
    sink_close(&sink);
    conn_close(&c);
    return rc;
}

int http_transaction(const Url *url, const Options *opt, Response *resp, char **effective_url, char **err) {
    if (err) *err = NULL;
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
        have_proxy = 1;
    }

    for (;;) {
        Url u;
        if (url_parse(current, &u, err) != 0) {
            if (have_proxy) url_free(&proxy);
            free(current); free(method);
            return -1;
        }
        response_free(resp);

        Options ropt = *opt;
        if (!send_body) memset(&ropt.body, 0, sizeof(ropt.body));
        if (!allow_auth) {
            ropt.basic_auth = NULL;
            ropt.strip_authorization = 1;
        }

        int metadata_only = opt->status_only || opt->meta || opt->json_meta;
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
            } else if ((resp->status == 307 || resp->status == 308) && send_body &&
                       opt->body.type == BODY_STDIN) {
                *err = xstrdup("cannot replay stdin request body across a 307/308 redirect");
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

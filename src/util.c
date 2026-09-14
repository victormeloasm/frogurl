#include "frogurl.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("frogurl: out of memory");
    return p;
}

void *xcalloc(size_t n, size_t s) {
    void *p = calloc(n ? n : 1, s ? s : 1);
    if (!p) die("frogurl: out of memory");
    return p;
}

char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *xstrndup(const char *s, size_t n) {
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

char *strlower_dup(const char *s) {
    size_t n = strlen(s);
    char *p = xmalloc(n + 1);
    for (size_t i = 0; i < n; ++i) p[i] = (char)tolower((unsigned char)s[i]);
    p[n] = 0;
    return p;
}

char *trim_dup(const char *s) {
    while (*s && isspace((unsigned char)*s)) ++s;
    const char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) --e;
    return xstrndup(s, (size_t)(e - s));
}

int strieq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

int stristarts(const char *s, const char *prefix) {
    while (*prefix) {
        if (!*s || tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        ++s; ++prefix;
    }
    return 1;
}

char *base64_basic(const char *s) {
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(s);
    size_t outn = 4 * ((n + 2) / 3);
    char *out = xmalloc(outn + 1);
    size_t i = 0, j = 0;
    while (i + 3 <= n) {
        unsigned v = ((unsigned)(unsigned char)s[i] << 16) |
                     ((unsigned)(unsigned char)s[i + 1] << 8) |
                     (unsigned)(unsigned char)s[i + 2];
        out[j++] = tab[(v >> 18) & 63];
        out[j++] = tab[(v >> 12) & 63];
        out[j++] = tab[(v >> 6) & 63];
        out[j++] = tab[v & 63];
        i += 3;
    }
    if (i < n) {
        unsigned a = (unsigned char)s[i++];
        unsigned b = i < n ? (unsigned char)s[i++] : 0;
        unsigned v = (a << 16) | (b << 8);
        out[j++] = tab[(v >> 18) & 63];
        out[j++] = tab[(v >> 12) & 63];
        out[j++] = (n % 3 == 2) ? tab[(v >> 6) & 63] : '=';
        out[j++] = '=';
    }
    out[j] = 0;
    return out;
}

int write_all_fd(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

char *json_escape(const char *s) {
    if (!s) return xstrdup("");
    size_t cap = strlen(s) * 6 + 1;
    char *out = xmalloc(cap);
    char *p = out;
    static const char hex[] = "0123456789abcdef";
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '\\': *p++='\\'; *p++='\\'; break;
            case '"':  *p++='\\'; *p++='"'; break;
            case '\n': *p++='\\'; *p++='n'; break;
            case '\r': *p++='\\'; *p++='r'; break;
            case '\t': *p++='\\'; *p++='t'; break;
            default:
                if (c < 0x20) {
                    *p++='\\'; *p++='u'; *p++='0'; *p++='0';
                    *p++=hex[c >> 4]; *p++=hex[c & 15];
                } else *p++=(char)c;
        }
    }
    *p=0;
    return out;
}

long long monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

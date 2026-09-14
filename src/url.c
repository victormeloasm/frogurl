#include "frogurl.h"

#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_scheme_char(int c) {
    return isalnum((unsigned char)c) || c == '+' || c == '-' || c == '.';
}

static char *strip_fragment(const char *s) {
    const char *p = strchr(s, '#');
    return p ? xstrndup(s, (size_t)(p - s)) : xstrdup(s);
}

int url_parse(const char *s, Url *u, char **err) {
    memset(u, 0, sizeof(*u));
    if (err) *err = NULL;
    if (!s || !*s) {
        if (err) *err = xstrdup("empty URL");
        return -1;
    }

    char *clean = strip_fragment(s);
    for (const unsigned char *q = (const unsigned char *)clean; *q; ++q) {
        if (*q <= 0x20 || *q == 0x7f) {
            if (err) *err = xstrdup("URL contains whitespace or control characters; percent-encode them");
            free(clean);
            return -1;
        }
    }
    const char *p = strstr(clean, "://");
    if (!p || p == clean) {
        if (err) *err = xstrdup("URL must include http://, https:// or ftp://");
        free(clean);
        return -1;
    }
    for (const char *q = clean; q < p; ++q) {
        if (!is_scheme_char(*q)) {
            if (err) *err = xstrdup("invalid URL scheme");
            free(clean);
            return -1;
        }
    }
    char *scheme_raw = xstrndup(clean, (size_t)(p - clean));
    u->scheme = strlower_dup(scheme_raw);
    free(scheme_raw);
    if (!strieq(u->scheme, "http") && !strieq(u->scheme, "https") && !strieq(u->scheme, "ftp")) {
        if (err) *err = xstrdup("only http, https and ftp are supported");
        free(clean);
        url_free(u);
        return -1;
    }
    u->https = strieq(u->scheme, "https");
    u->ftp = strieq(u->scheme, "ftp");

    const char *auth = p + 3;
    const char *path = strpbrk(auth, "/?");
    const char *auth_end = path ? path : clean + strlen(clean);
    if (auth == auth_end) {
        if (err) *err = xstrdup("missing host");
        free(clean);
        url_free(u);
        return -1;
    }
    if (memchr(auth, '@', (size_t)(auth_end - auth))) {
        if (err) *err = xstrdup("userinfo in URL is not supported; use -u user:pass");
        free(clean);
        url_free(u);
        return -1;
    }

    if (*auth == '[') {
        const char *rb = memchr(auth, ']', (size_t)(auth_end - auth));
        if (!rb) {
            if (err) *err = xstrdup("invalid bracketed IPv6 host");
            free(clean);
            url_free(u);
            return -1;
        }
        u->host = xstrndup(auth + 1, (size_t)(rb - auth - 1));
        unsigned char addr[16];
        if (inet_pton(AF_INET6, u->host, addr) != 1) {
            if (err) *err = xstrdup("invalid IPv6 literal");
            free(clean); url_free(u); return -1;
        }
        if (rb + 1 < auth_end) {
            if (rb[1] != ':') {
                if (err) *err = xstrdup("invalid authority after IPv6 host");
                free(clean);
                url_free(u);
                return -1;
            }
            u->port = xstrndup(rb + 2, (size_t)(auth_end - (rb + 2)));
            u->explicit_port = 1;
        }
    } else {
        const char *colon = NULL;
        for (const char *q = auth; q < auth_end; ++q) if (*q == ':') colon = q;
        if (colon) {
            u->host = xstrndup(auth, (size_t)(colon - auth));
            u->port = xstrndup(colon + 1, (size_t)(auth_end - colon - 1));
            u->explicit_port = 1;
        } else {
            u->host = xstrndup(auth, (size_t)(auth_end - auth));
        }
    }

    if (!u->host || !*u->host) {
        if (err) *err = xstrdup("missing host");
        free(clean);
        url_free(u);
        return -1;
    }
    if (*auth != '[') {
        for (const unsigned char *q = (const unsigned char *)u->host; *q; ++q) {
            if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
                  (*q >= '0' && *q <= '9') || *q == '-' || *q == '.' || *q == '_')) {
                if (err) *err = xstrdup("invalid host; use bracketed IPv6 or an ASCII hostname");
                free(clean); url_free(u); return -1;
            }
        }
    }
    if (!u->port) u->port = xstrdup(u->ftp ? "21" : (u->https ? "443" : "80"));
    if (!*u->port) {
        if (err) *err = xstrdup("empty port");
        free(clean);
        url_free(u);
        return -1;
    }
    for (char *q = u->port; *q; ++q) if (!isdigit((unsigned char)*q)) {
        if (err) *err = xstrdup("non-numeric port");
        free(clean);
        url_free(u);
        return -1;
    }
    unsigned long long port;
    if (parse_decimal(u->port, 65535, &port) || !port) {
        if (err) *err = xstrdup("port must be between 1 and 65535");
        free(clean); url_free(u); return -1;
    }
    char canonical_port[6];
    snprintf(canonical_port, sizeof(canonical_port), "%u", (unsigned)port);
    free(u->port); u->port = xstrdup(canonical_port);

    if (!path) u->path = xstrdup("/");
    else if (*path == '?') {
        size_t n = strlen(path);
        u->path = xmalloc(n + 2);
        u->path[0] = '/';
        memcpy(u->path + 1, path, n + 1);
    } else u->path = xstrdup(path);

    free(clean);
    return 0;
}

void url_free(Url *u) {
    if (!u) return;
    free(u->scheme);
    free(u->host);
    free(u->port);
    free(u->path);
    memset(u, 0, sizeof(*u));
}

static int host_needs_brackets(const char *host) {
    return strchr(host, ':') != NULL;
}

char *url_host_header(const Url *u) {
    int default_port = !strcmp(u->port, u->ftp ? "21" : (u->https ? "443" : "80"));
    int brackets = host_needs_brackets(u->host);
    size_t n = strlen(u->host) + strlen(u->port) + 8;
    char *s = xmalloc(n);
    if (default_port) snprintf(s, n, brackets ? "[%s]" : "%s", u->host);
    else snprintf(s, n, brackets ? "[%s]:%s" : "%s:%s", u->host, u->port);
    return s;
}

char *url_to_string(const Url *u) {
    char *host = url_host_header(u);
    size_t n = strlen(u->scheme) + strlen(host) + strlen(u->path) + 8;
    char *s = xmalloc(n);
    snprintf(s, n, "%s://%s%s", u->scheme, host, u->path);
    free(host);
    return s;
}

static char *normalize_path(const char *path) {
    const char *qmark = strchr(path, '?');
    size_t plen = qmark ? (size_t)(qmark - path) : strlen(path);
    char *work = xstrndup(path, plen);
    char **stack = xcalloc(plen + 1, sizeof(char*));
    size_t top = 0;

    /* Keep empty segments: /a//b and /a/b can identify different resources. */
    char *part = work + (work[0] == '/');
    for (;;) {
        char *slash = strchr(part, '/');
        if (slash) *slash = 0;
        if (!strcmp(part, ".")) {
            if (!slash) stack[top++] = part + 1;
        } else if (!strcmp(part, "..")) {
            if (top) --top;
            if (!slash) stack[top++] = part + 2;
        } else stack[top++] = part;
        if (!slash) break;
        part = slash + 1;
    }

    size_t cap = plen + (qmark ? strlen(qmark) : 0) + 3;
    char *out = xmalloc(cap);
    size_t pos = 0;
    out[pos++] = '/';
    for (size_t i = 0; i < top; ++i) {
        size_t n = strlen(stack[i]);
        memcpy(out + pos, stack[i], n);
        pos += n;
        if (i + 1 < top) out[pos++] = '/';
    }
    if (qmark) {
        size_t n = strlen(qmark);
        memcpy(out + pos, qmark, n);
        pos += n;
    }
    out[pos] = 0;
    free(stack);
    free(work);
    return out;
}

char *url_resolve(const Url *base, const char *location) {
    if (!location || !*location) return url_to_string(base);
    if (*location == '#') return url_to_string(base);
    if (strstr(location, "://")) return strip_fragment(location);

    if (!strncmp(location, "//", 2)) {
        size_t n = strlen(base->scheme) + strlen(location) + 2;
        char *s = xmalloc(n);
        snprintf(s, n, "%s:%s", base->scheme, location);
        char *clean = strip_fragment(s);
        free(s);
        return clean;
    }

    char *host = url_host_header(base);
    char *loc = strip_fragment(location);
    char *path = NULL;

    if (loc[0] == '/') {
        path = normalize_path(loc);
    } else if (loc[0] == '?') {
        const char *q = strchr(base->path, '?');
        size_t plen = q ? (size_t)(q - base->path) : strlen(base->path);
        path = xmalloc(plen + strlen(loc) + 1);
        memcpy(path, base->path, plen);
        strcpy(path + plen, loc);
    } else {
        const char *q = strchr(base->path, '?');
        size_t plen = q ? (size_t)(q - base->path) : strlen(base->path);
        const char *slash = NULL;
        for (size_t i = 0; i < plen; ++i) if (base->path[i] == '/') slash = base->path + i;
        size_t dirlen = slash ? (size_t)(slash - base->path + 1) : 1;
        char *tmp = xmalloc(dirlen + strlen(loc) + 1);
        memcpy(tmp, base->path, dirlen);
        strcpy(tmp + dirlen, loc);
        path = normalize_path(tmp);
        free(tmp);
    }

    size_t n = strlen(base->scheme) + strlen(host) + strlen(path) + 8;
    char *out = xmalloc(n);
    snprintf(out, n, "%s://%s%s", base->scheme, host, path);
    free(path);
    free(loc);
    free(host);
    return out;
}

char *url_remote_name(const Url *u) {
    const char *end = strchr(u->path, '?');
    if (!end) end = u->path + strlen(u->path);
    const char *start = end;
    while (start > u->path && start[-1] != '/') --start;
    if (start == end) return xstrdup("index.html");
    return xstrndup(start, (size_t)(end - start));
}

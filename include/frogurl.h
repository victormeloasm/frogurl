#ifndef FROGURL_H
#define FROGURL_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/ssl.h>

typedef struct {
    char *scheme;
    char *host;
    char *port;
    char *path;
    int https;
    int explicit_port;
} Url;

typedef struct Header {
    char *name;
    char *value;
    struct Header *next;
} Header;

typedef enum {
    BODY_NONE = 0,
    BODY_MEMORY,
    BODY_FILE,
    BODY_STDIN
} BodyType;

typedef struct {
    BodyType type;
    const unsigned char *mem;
    size_t mem_len;
    char *file_path;
    off_t length;
    int length_known;
} RequestBody;

typedef struct {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int tls;
    int verbose;
    unsigned char rbuf[16384];
    size_t rpos;
    size_t rlen;
} Connection;

typedef struct {
    int status;
    char *reason;
    long long content_length;
    int has_content_length;
    int chunked;
    int gzip;
    int deflate;
    int connection_close;
    char *location;
    char *content_type;
    char *server;
    Header *headers;
    long long body_bytes;
    long long elapsed_ms;
} Response;

typedef struct {
    const char *method;
    Header *headers;
    RequestBody body;
    const char *output_path;
    int remote_name;
    int follow_redirects;
    int max_redirects;
    int include_headers;
    int insecure;
    const char *cacert;
    const char *user_agent;
    const char *basic_auth;
    const char *proxy;
    const char *proxy_auth;
    int connect_timeout_ms;
    int io_timeout_ms;
    int verbose;
    int silent;
    int fail_http;
    int compressed;
    int status_only;
    int meta;
    int json_meta;
    int progress_bar;
    int no_progress_meter;
    int strip_authorization; /* internal: do not forward credentials across origins */
} Options;

/* util.c */
void die(const char *fmt, ...);
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t s);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *strlower_dup(const char *s);
char *trim_dup(const char *s);
int strieq(const char *a, const char *b);
int stristarts(const char *s, const char *prefix);
char *base64_basic(const char *s);
int write_all_fd(int fd, const void *buf, size_t len);
char *json_escape(const char *s);
long long monotonic_ms(void);

/* url.c */
int url_parse(const char *s, Url *u, char **err);
void url_free(Url *u);
char *url_to_string(const Url *u);
char *url_host_header(const Url *u);
char *url_resolve(const Url *base, const char *location);
char *url_remote_name(const Url *u);

/* net.c */
int conn_open(Connection *c, const Url *target, const Url *proxy, const Options *opt, char **err);
ssize_t conn_read_raw(Connection *c, void *buf, size_t len);
int conn_write_all(Connection *c, const void *buf, size_t len);
ssize_t conn_read(Connection *c, void *buf, size_t len);
int conn_read_line(Connection *c, char **line, size_t max_len);
void conn_close(Connection *c);

/* http.c */
Header *header_add(Header **list, const char *name, const char *value);
const char *header_get(const Header *list, const char *name);
int header_exists(const Header *list, const char *name);
void headers_free(Header *h);
void response_free(Response *r);
int http_transaction(const Url *url, const Options *opt, Response *resp, char **effective_url, char **err);

#endif

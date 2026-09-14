#include "frogurl.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void usage(FILE *f) {
    fprintf(f,
"frogurl - small HTTP/HTTPS command-line client\n"
"\n"
"Usage: frogurl [options] URL\n"
"\n"
"Core options:\n"
"  -X, --request METHOD         HTTP method\n"
"  -I, --head                   HEAD request and print response headers\n"
"  -H, --header 'Name: value'  Add request header (repeatable)\n"
"  -d, --data DATA              Send DATA (defaults method to POST)\n"
"      --data-binary DATA       Send exact DATA, @FILE, or @- for stdin\n"
"  -T, --upload-file FILE       Upload FILE (defaults method to PUT)\n"
"  -o, --output FILE            Write response body to FILE\n"
"  -O, --remote-name            Save using the remote path basename\n"
"  -L, --location               Follow redirects\n"
"      --max-redirs N           Maximum redirects (default: 10)\n"
"\n"
"Connection/TLS:\n"
"  -x, --proxy URL              HTTP proxy URL\n"
"      --proxy-user USER:PASS   Basic proxy credentials\n"
"  -u, --user USER:PASS         HTTP Basic credentials\n"
"  -k, --insecure               Disable TLS certificate verification\n"
"      --cacert FILE            CA bundle/file for TLS verification\n"
"      --connect-timeout SEC    TCP connect timeout (default: 10)\n"
"      --timeout SEC            Socket I/O timeout (default: 30)\n"
"      --compressed             Request gzip/deflate and decompress it\n"
"\n"
"Output/control:\n"
"  -i, --include                Include response headers in output\n"
"  -A, --user-agent STRING      Set User-Agent\n"
"  -f, --fail                   Exit 22 on HTTP >= 400 and suppress body\n"
"  -s, --silent                 Suppress non-essential diagnostics\n"
"  -v, --verbose                Verbose connection and HTTP trace\n"
"  -#, --progress-bar           Display transfer progress as a bar\n"
"      --no-progress-meter     Disable transfer progress display\n"
"      --status                 Print only final HTTP status code\n"
"      --meta                   Print final response metadata\n"
"      --json-meta              Print metadata as JSON\n"
"      --version                Show version\n"
"  -h, --help                   Show this help\n"
"\n"
"Examples:\n"
"  frogurl https://example.com\n"
"  frogurl -LO https://example.com/archive.tar.gz\n"
"  frogurl -H 'Accept: application/json' https://example.com/api\n"
"  frogurl -d 'frog=green' https://example.com/form\n"
"  frogurl --data-binary @payload.bin -X POST https://example.com/upload\n"
"  frogurl -x http://127.0.0.1:8080 https://example.com\n");
}

static int parse_seconds_ms(const char *s, int *out) {
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || end == s || *end || v < 0 || v > 2147483.0) return -1;
    *out = (int)(v * 1000.0 + 0.5);
    return 0;
}

static void parse_header_arg(Header **headers, const char *arg) {
    const char *colon = strchr(arg, ':');
    if (!colon || colon == arg) die("frogurl: invalid header '%s' (expected Name: value)", arg);
    char *name = xstrndup(arg, (size_t)(colon - arg));
    char *value = trim_dup(colon + 1);
    header_add(headers, name, value);
    free(name); free(value);
}

static void set_memory_body(Options *o, const char *data) {
    if (o->body.type != BODY_NONE) die("frogurl: only one request body source may be used");
    o->body.type = BODY_MEMORY;
    o->body.mem = (const unsigned char *)xstrdup(data);
    o->body.mem_len = strlen(data);
    o->body.length = (off_t)o->body.mem_len;
    o->body.length_known = 1;
}

static void set_binary_body(Options *o, const char *arg) {
    if (o->body.type != BODY_NONE) die("frogurl: only one request body source may be used");
    if (arg[0] != '@') {
        o->body.type = BODY_MEMORY;
        o->body.mem = (const unsigned char *)xstrdup(arg);
        o->body.mem_len = strlen(arg);
        o->body.length = (off_t)o->body.mem_len;
        o->body.length_known = 1;
        return;
    }
    if (!strcmp(arg, "@-")) {
        o->body.type = BODY_STDIN;
        o->body.length_known = 0;
        return;
    }
    const char *path = arg + 1;
    struct stat st;
    if (stat(path, &st) != 0) die("frogurl: cannot stat '%s': %s", path, strerror(errno));
    if (!S_ISREG(st.st_mode)) die("frogurl: request body '%s' is not a regular file", path);
    o->body.type = BODY_FILE;
    o->body.file_path = xstrdup(path);
    o->body.length = st.st_size;
    o->body.length_known = 1;
}

static void set_upload_file(Options *o, const char *path) {
    if (o->body.type != BODY_NONE) die("frogurl: only one request body source may be used");
    struct stat st;
    if (stat(path, &st) != 0) die("frogurl: cannot stat '%s': %s", path, strerror(errno));
    if (!S_ISREG(st.st_mode)) die("frogurl: upload source '%s' is not a regular file", path);
    o->body.type = BODY_FILE;
    o->body.file_path = xstrdup(path);
    o->body.length = st.st_size;
    o->body.length_known = 1;
}

static void print_meta(const Response *r, const char *effective) {
    printf("status=%d\n", r->status);
    printf("effective_url=%s\n", effective ? effective : "");
    if (r->content_type) printf("content_type=%s\n", r->content_type);
    if (r->has_content_length) printf("content_length=%lld\n", r->content_length);
    printf("body_bytes=%lld\n", r->body_bytes);
    printf("elapsed_ms=%lld\n", r->elapsed_ms);
    if (r->server) printf("server=%s\n", r->server);
}

static void print_json_meta(const Response *r, const char *effective) {
    char *eu = json_escape(effective ? effective : "");
    char *ct = json_escape(r->content_type ? r->content_type : "");
    char *sv = json_escape(r->server ? r->server : "");
    printf("{\"status\":%d,\"effective_url\":\"%s\",", r->status, eu);
    if (r->has_content_length) printf("\"content_length\":%lld,", r->content_length);
    else printf("\"content_length\":null,");
    printf("\"body_bytes\":%lld,\"elapsed_ms\":%lld,", r->body_bytes, r->elapsed_ms);
    printf("\"content_type\":\"%s\",\"server\":\"%s\"}\n", ct, sv);
    free(eu); free(ct); free(sv);
}

int main(int argc, char **argv) {
    Options o;
    memset(&o, 0, sizeof(o));
    o.max_redirects = 10;
    o.connect_timeout_ms = 10000;
    o.io_timeout_ms = 30000;
    o.user_agent = "frogurl/1.1";

    int method_explicit = 0;
    int head = 0;
    int upload_defaults_put = 0;

    enum {
        OPT_DATA_BINARY = 1000,
        OPT_MAX_REDIRS,
        OPT_PROXY_USER,
        OPT_CACERT,
        OPT_CONNECT_TIMEOUT,
        OPT_TIMEOUT,
        OPT_COMPRESSED,
        OPT_STATUS,
        OPT_META,
        OPT_JSON_META,
        OPT_NO_PROGRESS_METER,
        OPT_VERSION
    };

    static const struct option longopts[] = {
        {"request", required_argument, 0, 'X'},
        {"head", no_argument, 0, 'I'},
        {"header", required_argument, 0, 'H'},
        {"data", required_argument, 0, 'd'},
        {"data-binary", required_argument, 0, OPT_DATA_BINARY},
        {"upload-file", required_argument, 0, 'T'},
        {"output", required_argument, 0, 'o'},
        {"remote-name", no_argument, 0, 'O'},
        {"location", no_argument, 0, 'L'},
        {"max-redirs", required_argument, 0, OPT_MAX_REDIRS},
        {"proxy", required_argument, 0, 'x'},
        {"proxy-user", required_argument, 0, OPT_PROXY_USER},
        {"user", required_argument, 0, 'u'},
        {"insecure", no_argument, 0, 'k'},
        {"cacert", required_argument, 0, OPT_CACERT},
        {"connect-timeout", required_argument, 0, OPT_CONNECT_TIMEOUT},
        {"timeout", required_argument, 0, OPT_TIMEOUT},
        {"compressed", no_argument, 0, OPT_COMPRESSED},
        {"include", no_argument, 0, 'i'},
        {"user-agent", required_argument, 0, 'A'},
        {"fail", no_argument, 0, 'f'},
        {"silent", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"status", no_argument, 0, OPT_STATUS},
        {"meta", no_argument, 0, OPT_META},
        {"json-meta", no_argument, 0, OPT_JSON_META},
        {"progress-bar", no_argument, 0, '#'},
        {"no-progress-meter", no_argument, 0, OPT_NO_PROGRESS_METER},
        {"version", no_argument, 0, OPT_VERSION},
        {"help", no_argument, 0, 'h'},
        {0,0,0,0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "X:IH:d:T:o:OLx:u:kiA:fsv#h", longopts, NULL)) != -1) {
        switch (ch) {
            case 'X': o.method = optarg; method_explicit = 1; break;
            case 'I': head = 1; o.include_headers = 1; break;
            case 'H': parse_header_arg(&o.headers, optarg); break;
            case 'd': set_memory_body(&o, optarg); break;
            case OPT_DATA_BINARY: set_binary_body(&o, optarg); break;
            case 'T': set_upload_file(&o, optarg); upload_defaults_put = 1; break;
            case 'o': o.output_path = optarg; break;
            case 'O': o.remote_name = 1; break;
            case 'L': o.follow_redirects = 1; break;
            case OPT_MAX_REDIRS: {
                char *e = NULL; long v = strtol(optarg, &e, 10);
                if (!e || *e || v < 0 || v > 1000) die("frogurl: invalid --max-redirs value");
                o.max_redirects = (int)v; break;
            }
            case 'x': o.proxy = optarg; break;
            case OPT_PROXY_USER: o.proxy_auth = optarg; break;
            case 'u': o.basic_auth = optarg; break;
            case 'k': o.insecure = 1; break;
            case OPT_CACERT: o.cacert = optarg; break;
            case OPT_CONNECT_TIMEOUT:
                if (parse_seconds_ms(optarg, &o.connect_timeout_ms)) die("frogurl: invalid --connect-timeout");
                break;
            case OPT_TIMEOUT:
                if (parse_seconds_ms(optarg, &o.io_timeout_ms)) die("frogurl: invalid --timeout");
                break;
            case OPT_COMPRESSED: o.compressed = 1; break;
            case 'i': o.include_headers = 1; break;
            case 'A': o.user_agent = optarg; break;
            case 'f': o.fail_http = 1; break;
            case 's': o.silent = 1; break;
            case 'v': o.verbose = 1; break;
            case '#': o.progress_bar = 1; break;
            case OPT_STATUS: o.status_only = 1; break;
            case OPT_META: o.meta = 1; break;
            case OPT_JSON_META: o.json_meta = 1; break;
            case OPT_NO_PROGRESS_METER: o.no_progress_meter = 1; break;
            case OPT_VERSION:
                puts("frogurl 1.1 (HTTP/1.1, OpenSSL, zlib)");
                return 0;
            case 'h': usage(stdout); return 0;
            default: usage(stderr); return 2;
        }
    }

    if (optind + 1 != argc) {
        usage(stderr);
        return 2;
    }
    if (o.output_path && o.remote_name) die("frogurl: -o and -O are mutually exclusive");
    if ((o.status_only ? 1 : 0) + (o.meta ? 1 : 0) + (o.json_meta ? 1 : 0) > 1)
        die("frogurl: choose only one of --status, --meta, or --json-meta");

    if (head) {
        if (o.body.type != BODY_NONE) die("frogurl: HEAD cannot be combined with a request body");
        if (!method_explicit) o.method = "HEAD";
    } else if (!method_explicit) {
        if (o.body.type == BODY_NONE) o.method = "GET";
        else o.method = upload_defaults_put ? "PUT" : "POST";
    }

    Url url;
    char *err = NULL;
    if (url_parse(argv[optind], &url, &err) != 0) {
        fprintf(stderr, "frogurl: %s\n", err ? err : "invalid URL");
        free(err);
        headers_free(o.headers);
        return 3;
    }

    Response r;
    memset(&r, 0, sizeof(r));
    char *effective = NULL;
    int rc = http_transaction(&url, &o, &r, &effective, &err);
    url_free(&url);

    if (rc != 0) {
        if (!o.silent) fprintf(stderr, "frogurl: %s\n", err ? err : "request failed");
        free(err);
        free(effective);
        response_free(&r);
        headers_free(o.headers);
        free((void *)o.body.mem);
        free(o.body.file_path);
        return 1;
    }

    if (o.status_only) printf("%d\n", r.status);
    else if (o.meta) print_meta(&r, effective);
    else if (o.json_meta) print_json_meta(&r, effective);

    int exit_code = (o.fail_http && r.status >= 400) ? 22 : 0;
    free(effective);
    response_free(&r);
    headers_free(o.headers);
    free((void *)o.body.mem);
    free(o.body.file_path);
    return exit_code;
}

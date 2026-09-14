#include "frogurl.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Deliberately small: binary, stream-mode passive RETR/STOR, no raw commands. */
typedef struct {
    Connection control;
    const Options *opt;
    char *reply;
    int code;
} Ftp;

static int ftp_error(char **err, const char *msg) {
    if (!*err) *err = xstrdup(msg);
    return -1;
}

static int reply_code(const char *s) {
    if (strlen(s) < 4 || s[0] < '1' || s[0] > '5' ||
        s[1] < '0' || s[1] > '9' || s[2] < '0' || s[2] > '9' ||
        (s[3] != ' ' && s[3] != '-')) return -1;
    return 100 * (s[0] - '0') + 10 * (s[1] - '0') + s[2] - '0';
}

static int ftp_reply(Ftp *f, int sensitive, char **err) {
    size_t total = 0;
    int first = 1, multiline = 0, code = 0;
    for (;;) {
        char *line = NULL;
        if (conn_read_line(&f->control, &line, 8192) <= 0)
            return ftp_error(err, "truncated, invalid or timed-out FTP reply");
        total += strlen(line);
        if (total > 65536) { free(line); return ftp_error(err, "FTP reply exceeds 64 KiB"); }
        int current = reply_code(line);
        if (first) {
            if (current < 0) { free(line); return ftp_error(err, "invalid FTP reply code"); }
            code = current; multiline = line[3] == '-';
        }
        if (f->opt->verbose) {
            if (sensitive) fprintf(stderr, "< FTP authentication reply (text redacted)\n");
            else fprintf(stderr, "< %s", line);
        }
        int last = !multiline || (!first && current == code && line[3] == ' ');
        first = 0;
        if (last) {
            size_t n = strlen(line);
            while (n && (line[n-1] == '\r' || line[n-1] == '\n')) line[--n] = 0;
            free(f->reply); f->reply = xstrdup(line); f->code = code;
            free(line); return 0;
        }
        free(line);
    }
}

static int ftp_safe_arg(const char *s) {
    if (strlen(s) > 8000) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (*p < 32 || *p == 127 || *p == 255) return 0;
    return 1;
}

static int ftp_command(Ftp *f, const char *cmd, const char *arg, char **err) {
    if (arg && !ftp_safe_arg(arg)) return ftp_error(err, "invalid FTP command argument");
    int sensitive = !strcmp(cmd, "USER") || !strcmp(cmd, "PASS");
    if (f->opt->verbose)
        fprintf(stderr, "> %s%s%s\n", cmd, arg ? " " : "", arg ? (sensitive ? "<redacted>" : arg) : "");
    size_t size = strlen(cmd) + (arg ? strlen(arg) + 1 : 0) + 3;
    char *line = xmalloc(size);
    int n = snprintf(line, size, "%s%s%s\r\n", cmd, arg ? " " : "", arg ? arg : "");
    int rc = conn_write_all(&f->control, line, (size_t)n);
    free(line);
    if (rc) return ftp_error(err, "FTP command write failed or timed out");
    return ftp_reply(f, sensitive, err);
}

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *decode_path(const char *s, size_t len, char **err) {
    char *out = xmalloc(len + 1);
    size_t n = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '%') {
            if (i + 2 >= len || hexval((unsigned char)s[i+1]) < 0 || hexval((unsigned char)s[i+2]) < 0) {
                free(out); ftp_error(err, "invalid percent escape in FTP path"); return NULL;
            }
            c = (unsigned char)(hexval((unsigned char)s[i+1]) * 16 + hexval((unsigned char)s[i+2])); i += 2;
        }
        if (c < 32 || c == 127 || c == 255) {
            free(out); ftp_error(err, "control character in decoded FTP path"); return NULL;
        }
        out[n++] = (char)c;
    }
    out[n] = 0;
    return out;
}

static int passive_port(Ftp *f, unsigned *port, char **err) {
    if (ftp_command(f, "EPSV", NULL, err)) return -1;
    if (f->code == 229) {
        const char *p = strchr(f->reply, '(');
        if (!p || strlen(++p) < 6 || (unsigned char)p[0] < 33 || (unsigned char)p[0] > 126 ||
            p[1] != p[0] || p[2] != p[0]) return ftp_error(err, "malformed EPSV reply");
        char delimiter = *p; p += 3;
        const char *close = strchr(p, ')');
        if (!close || close == p || close[-1] != delimiter) return ftp_error(err, "malformed EPSV port");
        const char *end = close - 1;
        char *digits = xstrndup(p, (size_t)(end - p));
        unsigned long long value;
        int rc = parse_decimal(digits, 65535, &value);
        free(digits);
        if (rc || !value) return ftp_error(err, "invalid EPSV port");
        *port = (unsigned)value; return 0;
    }
    if (f->code != 500 && f->code != 501 && f->code != 502 && f->code != 504 && f->code != 522)
        return ftp_error(err, "FTP server rejected EPSV");
    struct sockaddr_storage peer;
    socklen_t len = sizeof(peer);
    if (getpeername(f->control.fd, (struct sockaddr *)&peer, &len) || peer.ss_family != AF_INET)
        return ftp_error(err, "FTP over IPv6 requires EPSV");
    if (ftp_command(f, "PASV", NULL, err)) return -1;
    if (f->code != 227) return ftp_error(err, "FTP server rejected PASV");
    const char *p = strchr(f->reply, '(');
    if (!p) return ftp_error(err, "malformed PASV reply");
    ++p;
    unsigned fields[6];
    for (int i = 0; i < 6; ++i) {
        const char *start = p;
        unsigned n = 0;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (unsigned)(*p++ - '0');
            if (n > 255 || p - start > 3) return ftp_error(err, "invalid PASV field");
        }
        if (p == start || *p != (i == 5 ? ')' : ',')) return ftp_error(err, "malformed PASV tuple");
        fields[i] = n; ++p;
    }
    /* Only use the port. conn_open_peer always uses the connected server IP. */
    *port = fields[4] * 256 + fields[5];
    return *port ? 0 : ftp_error(err, "invalid PASV port");
}

int ftp_transaction(const Url *url, const Options *opt, Response *resp, char **effective_url, char **err) {
    if (!err) { errno = EINVAL; return -1; }
    *err = NULL;
    if (effective_url) *effective_url = NULL;
    Ftp f = { .control = { .fd = -1 }, .opt = opt };
    Connection data = { .fd = -1 };
    char *raw = NULL, *name = NULL, *output = NULL, *user = NULL;
    char **dirs = NULL;
    size_t dir_count = 0;
    int input_fd = -1, output_fd = -1, own_input = 0, own_output = 0, rc = -1;
    int upload = opt->body.type != BODY_NONE;
    int metadata = opt->status_only || opt->meta || opt->json_meta;
    long long start = monotonic_ms();
    Progress prog = { .total = -1, .start_ms = start };
    unsigned long long expected = 0;
    int have_size = 0;
    const char *password = "frogurl@";

    if (opt->basic_auth) {
        const char *colon = strchr(opt->basic_auth, ':');
        user = colon ? xstrndup(opt->basic_auth, (size_t)(colon - opt->basic_auth)) : xstrdup(opt->basic_auth);
        password = colon ? colon + 1 : "";
    } else user = xstrdup("anonymous");
    if (!*user || !ftp_safe_arg(user) || !ftp_safe_arg(password)) {
        ftp_error(err, "invalid FTP username or password"); goto done;
    }
    if (strchr(url->path, '?')) { ftp_error(err, "percent-encode '?' in FTP filenames"); goto done; }
    if (strlen(url->path) > 65536) { ftp_error(err, "FTP path too long"); goto done; }
    raw = xstrdup(url->path + 1); /* RFC 1738: path is relative to the login directory. */
    char *type = strrchr(raw, ';');
    if (type && stristarts(type, ";type=")) {
        if (!strieq(type, ";type=i")) { ftp_error(err, "only binary FTP ;type=i is supported"); goto done; }
        *type = 0;
    }
    dirs = xcalloc(strlen(raw) + 1, sizeof(*dirs));
    char *part = raw, *slash;
    while ((slash = strchr(part, '/'))) {
        if (slash == part && part != raw) {
            ftp_error(err, "empty interior FTP directory component"); goto done;
        }
        if (dir_count >= 256) { ftp_error(err, "too many FTP path components"); goto done; }
        char *dir = slash == part ? xstrdup("/") : decode_path(part, (size_t)(slash - part), err);
        if (!dir) goto done;
        dirs[dir_count++] = dir;
        if (!ftp_safe_arg(dir)) { ftp_error(err, "FTP directory component too long"); goto done; }
        part = slash + 1;
    }
    name = decode_path(part, strlen(part), err);
    if (!name) goto done;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..") || !ftp_safe_arg(name)) {
        ftp_error(err, "FTP URL must name a file (directory listing is not supported)"); goto done;
    }
    if (opt->output_path) output = xstrdup(opt->output_path);
    else if (opt->remote_name) {
        if (strchr(name, '/') || strchr(name, '\\')) { ftp_error(err, "unsafe FTP remote output name"); goto done; }
        output = xstrdup(name);
    }
    if (upload && output) { ftp_error(err, "FTP upload cannot be combined with -o or -O"); goto done; }
    if (upload) {
        if (opt->body.type == BODY_STDIN) input_fd = STDIN_FILENO;
        else if (opt->body.type == BODY_FILE) {
            input_fd = open(opt->body.file_path, O_RDONLY | O_NONBLOCK);
            if (input_fd < 0) { ftp_error(err, "cannot open FTP upload source"); goto done; }
            own_input = 1;
            struct stat st;
            if (fstat(input_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) {
                ftp_error(err, "FTP upload source must be a regular file"); goto done;
            }
            expected = (unsigned long long)st.st_size; have_size = 1;
        } else { ftp_error(err, "use -T for FTP uploads"); goto done; }
    }
    if (conn_open(&f.control, url, NULL, opt, err)) goto done;
    if (ftp_reply(&f, 0, err)) goto done;
    if (f.code == 120 && ftp_reply(&f, 0, err)) goto done;
    if (f.code != 220) { ftp_error(err, "FTP server did not send a ready greeting"); goto done; }
    if (ftp_command(&f, "USER", user, err)) goto done;
    if (f.code == 331 && ftp_command(&f, "PASS", password, err)) goto done;
    if (f.code != 230) { ftp_error(err, "FTP authentication failed"); goto done; }
    if (ftp_command(&f, "TYPE", "I", err)) goto done;
    if (f.code != 200) { ftp_error(err, "FTP server rejected binary transfer mode"); goto done; }
    for (size_t i = 0; i < dir_count; ++i) {
        if (ftp_command(&f, "CWD", dirs[i], err)) goto done;
        if (f.code != 250) { ftp_error(err, "FTP directory change failed"); goto done; }
    }
    if (!upload) {
        if (ftp_command(&f, "SIZE", name, err)) goto done;
        if (f.code == 213) {
            char *size = trim_dup(f.reply + 4);
            int invalid = parse_decimal(size, LLONG_MAX, &expected);
            free(size);
            if (invalid) { ftp_error(err, "invalid FTP SIZE reply"); goto done; }
            have_size = 1;
        } else if (f.code < 500 || f.code >= 600) { ftp_error(err, "unexpected FTP SIZE reply"); goto done; }
    }
    if (have_size) { resp->content_length = (long long)expected; resp->has_content_length = 1; }
    unsigned port;
    if (passive_port(&f, &port, err) || conn_open_peer(&data, &f.control, port, opt, err)) goto done;
    if (ftp_command(&f, upload ? "STOR" : "RETR", name, err)) goto done;
    if (f.code != 125 && f.code != 150) { ftp_error(err, "FTP transfer was rejected"); goto done; }
    if (!upload) {
        if (output) {
            output_fd = output_open(output, opt->remote_name, err);
            if (output_fd < 0) goto done;
            own_output = 1;
        } else if (!metadata) output_fd = STDOUT_FILENO;
    }
    prog.enabled = !opt->silent && !metadata && !opt->no_progress_meter &&
                   (opt->progress_bar || ((output || upload) && isatty(STDERR_FILENO)));
    prog.total = have_size ? (long long)expected : -1;
    progress_render(&prog, 0);
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = upload ? read(input_fd, buf, sizeof(buf)) : conn_read(&data, buf, sizeof(buf));
        if (n < 0) {
            if (upload && errno == EINTR) continue;
            ftp_error(err, "FTP data read failed or timed out"); goto done;
        }
        if (!n) break;
        if (resp->body_bytes > LLONG_MAX - n ||
            (have_size && (unsigned long long)resp->body_bytes + (unsigned long long)n > expected)) {
            ftp_error(err, "FTP transfer exceeds expected size"); goto done;
        }
        if ((upload && conn_write_all(&data, buf, (size_t)n)) ||
            (!upload && output_fd >= 0 && write_all_fd(output_fd, buf, (size_t)n))) {
            ftp_error(err, "FTP transfer write failed or timed out"); goto done;
        }
        resp->body_bytes += n; progress_add(&prog, (size_t)n);
    }
    if (have_size && (unsigned long long)resp->body_bytes != expected) {
        ftp_error(err, "FTP transfer size mismatch (truncated or changed file)"); goto done;
    }
    if (upload && shutdown(data.fd, SHUT_WR)) { ftp_error(err, "FTP data shutdown failed"); goto done; }
    conn_close(&data);
    if (ftp_reply(&f, 0, err)) goto done;
    if (f.code != 226 && f.code != 250) { ftp_error(err, "FTP server did not confirm successful transfer"); goto done; }
    if (own_output) {
        int close_rc = close(output_fd); own_output = 0;
        if (close_rc) { ftp_error(err, "FTP output close failed"); goto done; }
    }
    resp->status = f.code;
    resp->reason = xstrdup(f.reply + 4);
    resp->elapsed_ms = monotonic_ms() - start;
    if (effective_url) *effective_url = url_to_string(url);
    rc = 0;
    /* Transfer result is final; closing the control socket ends the session. */
done:
    if (prog.enabled) {
        if (!rc) progress_render(&prog, 1);
        else fputc('\n', stderr);
    }
    if (own_input) close(input_fd);
    if (own_output) close(output_fd);
    conn_close(&data); conn_close(&f.control);
    free(f.reply); free(raw); free(name); free(output); free(user);
    for (size_t i = 0; i < dir_count; ++i) free(dirs[i]);
    free(dirs);
    return rc;
}

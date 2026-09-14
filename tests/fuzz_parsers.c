#include "frogurl.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Reproducible mutation smoke test, not a coverage-guided fuzzing campaign. */
static uint32_t state = 0x46524f47;
static uint32_t rnd(void) {
    state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state;
}

int main(void) {
    static const char chars[] = "abcXYZ019/?.:%#@[]+-_~ \\;\r\n\t";
    static const char *prefix[] = {"http://host/", "https://[::1]/", "ftp://host:21/", "http://", ""};
    unsigned long long value;
    assert(parse_decimal("18446744073709551615", ULLONG_MAX, &value) == 0 && value == ULLONG_MAX);
    assert(parse_decimal("18446744073709551616", ULLONG_MAX, &value) == -1);
    Url base; char *err = NULL;
    assert(!url_parse("https://example.com/a/b?x=1", &base, &err));
    for (unsigned i = 0; i < 50000; ++i) {
        char s[320];
        strcpy(s, prefix[rnd() % 5]);
        size_t len = strlen(s), n = rnd() % 240;
        while (n--) s[len++] = chars[rnd() % (sizeof(chars) - 1)];
        s[len] = 0;
        Url u;
        err = NULL;
        if (!url_parse(s, &u, &err)) {
            char *serialized = url_to_string(&u);
            Url again; char *err2 = NULL;
            assert(!url_parse(serialized, &again, &err2));
            assert(!strcmp(u.host, again.host));
            assert(!strcmp(u.port, again.port));
            assert(!strcmp(u.path, again.path));
            char *name = url_remote_name(&u); free(name);
            free(serialized); free(err2); url_free(&again); url_free(&u);
        }
        free(err);
        char *resolved = url_resolve(&base, s); free(resolved);
        int status; (void)parse_http_status(s, &status);
        (void)parse_decimal(s, LLONG_MAX, &value);
        (void)valid_token(s); (void)valid_field_value(s);
        if (i < 5000) {
            int fd[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
            for (size_t j = 0; j < len; ++j) s[j] = (char)rnd();
            assert(!write_all_fd(fd[0], s, len));
            close(fd[0]);
            Connection c = { .fd = fd[1], .io_timeout_ms = 100 };
            char *line = NULL;
            int rc = conn_read_line(&c, &line, rnd() % 300);
            if (rc > 0) assert(line && strlen(line) <= 300);
            free(line); conn_close(&c);
        }
    }
    url_free(&base);
    puts("parser mutation smoke: 50000 cases + 5000 binary line inputs OK");
    return 0;
}

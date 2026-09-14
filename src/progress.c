#include "frogurl.h"

static void human_bytes(double n, char out[24]) {
    static const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int i = 0;
    while (n >= 1024.0 && i < 4) { n /= 1024.0; ++i; }
    if (i == 0) snprintf(out, 24, "%.0f %s", n, u[i]);
    else if (n >= 100.0) snprintf(out, 24, "%.0f %s", n, u[i]);
    else if (n >= 10.0) snprintf(out, 24, "%.1f %s", n, u[i]);
    else snprintf(out, 24, "%.2f %s", n, u[i]);
}

void progress_render(Progress *p, int final) {
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
        int pct = (int)(100.0 * ((double)p->done / (double)p->total));
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
                bar, pct, done, total, speed, eta / 60, eta % 60);
    } else {
        const char spin[] = "|/-\\";
        unsigned si = (unsigned)((now / 120) & 3);
        fprintf(stderr, "\rfrogurl [%c] %s  %s/s", spin[si], done, speed);
    }
    if (final) fputc('\n', stderr);
    fflush(stderr);
}

void progress_add(Progress *p, size_t n) {
    if (!p || !p->enabled) return;
    p->done += (long long)n;
    progress_render(p, 0);
}


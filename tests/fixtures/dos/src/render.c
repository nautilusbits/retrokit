#include <string.h>
#include "engine.h"

static const unsigned char g_tile_colors[3] = { 1, 6, 2 };

void render_hline(unsigned char *screen, int pitch, int x0, int x1, int y, int color)
{
    if (y < 0 || y >= 200)
        return;
    if (x0 < 0)
        x0 = 0;
    if (x1 > 319)
        x1 = 319;
    if (x1 >= x0)
        memset(screen + y * pitch + x0, color, x1 - x0 + 1);
}

int render_text(unsigned char *screen, int pitch, int x, int y, const char *text)
{
    int n = 0;
    while (*text) {
        unsigned char c = (unsigned char)*text++;
        int row;
        for (row = 0; row < 7; row++)
            if ((c >> (row & 7)) & 1)
                render_hline(screen, pitch, x + n * 6, x + n * 6 + 4, y + row, 15);
        n++;
    }
    return n * 6;
}

void render_frame(const World *w, unsigned char *screen, int pitch, int cam_x, int cam_y)
{
    int tx, ty;
    for (ty = 0; ty < 50; ty++) {
        for (tx = 0; tx < 80; tx++) {
            int mx = (tx + cam_x) & (MAP_W - 1);
            int my = (ty + cam_y) & (MAP_H - 1);
            int c = g_tile_colors[w->tiles[my][mx]] + (w->height[my][mx] >> 6);
            render_hline(screen, pitch, tx * 4, tx * 4 + 3, ty * 4, c);
        }
    }
    entity_draw_all(w, screen, pitch);
    render_text(screen, pitch, 4, 4, w->level_name);
}

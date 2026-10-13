#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "engine.h"

World *g_world;

World *world_create(unsigned int seed)
{
    World *w = (World *)malloc(sizeof(World));
    if (w == NULL)
        fatal("out of memory allocating world (%u bytes)", (unsigned)sizeof(World));
    memset(w, 0, sizeof(World));
    w->seed = seed;
    strcpy(w->level_name, "untitled");
    log_msg(2, "world created, seed %u", seed);
    return w;
}

void world_generate(World *w, int roughness, int water_level)
{
    int x, y, h;
    for (y = 0; y < MAP_H; y++) {
        for (x = 0; x < MAP_W; x++) {
            h = 128 + rng_range(&w->seed, -roughness, roughness);
            if (x > 0)
                h = (h + w->height[y][x - 1]) / 2;
            if (y > 0)
                h = (h + w->height[y - 1][x]) / 2;
            w->height[y][x] = (unsigned char)clamp(h, 0, 255);
            w->tiles[y][x] = h < water_level ? 0 : (h < water_level + 20 ? 1 : 2);
        }
    }
    world_smooth(w, 2);
}

int world_height_at(const World *w, int x, int y)
{
    int ix = (x >> 16) & (MAP_W - 1);
    int iy = (y >> 16) & (MAP_H - 1);
    return w->height[iy][ix];
}

void world_smooth(World *w, int passes)
{
    int p, x, y, s;
    for (p = 0; p < passes; p++) {
        for (y = 1; y < MAP_H - 1; y++) {
            for (x = 1; x < MAP_W - 1; x++) {
                s = w->height[y - 1][x] + w->height[y + 1][x] +
                    w->height[y][x - 1] + w->height[y][x + 1];
                w->height[y][x] = (unsigned char)((s + 2 * w->height[y][x]) / 6);
            }
        }
    }
}

int world_load(World *w, const char *path)
{
    FILE *f;
    char line[80];
    char key[32];
    int value, n = 0;

    f = fopen(path, "r");
    if (f == NULL) {
        log_msg(1, "cannot open level file %s", path);
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%31s %d", key, &value) != 2)
            continue;
        if (stricmp(key, "seed") == 0)
            w->seed = (unsigned)value;
        else if (stricmp(key, "spawn") == 0)
            entity_spawn(w, value, rng_range(&w->seed, 0, MAP_W - 1) << 16,
                         rng_range(&w->seed, 0, MAP_H - 1) << 16);
        else if (stricmp(key, "name") == 0)
            sprintf(w->level_name, "level_%03d", value);
        else
            fatal("unknown key '%s' in %s", key, path);
        n++;
    }
    fclose(f);
    return n;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "engine.h"

static unsigned char g_screen[320 * 200];

static void usage(void)
{
    printf("usage: engine [-seed N] [-level FILE] [-frames N] [-quiet]\n");
}

int main(int argc, char **argv)
{
    int i, frames = 10, f;
    unsigned int seed = 1234;
    const char *level = NULL;
    long long big;

    for (i = 1; i < argc; i++) {
        if (stricmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = (unsigned)atoi(argv[++i]);
        else if (stricmp(argv[i], "-level") == 0 && i + 1 < argc)
            level = argv[++i];
        else if (stricmp(argv[i], "-frames") == 0 && i + 1 < argc)
            frames = atoi(argv[++i]);
        else if (stricmp(argv[i], "-quiet") == 0)
            g_verbose = 0;
        else {
            usage();
            return 1;
        }
    }

    g_world = world_create(seed);
    world_generate(g_world, 40, 90);
    if (level != NULL && world_load(g_world, level) == 0)
        fatal("level %s is empty", level);
    for (i = 0; i < 8; i++)
        entity_spawn(g_world, 1 + (i % 2), i << 18, i << 17);

    for (f = 0; f < frames; f++) {
        entity_update_all(g_world, 1);
        render_frame(g_world, g_screen, 320, f, f / 2);
        g_world->tick++;
    }

    big = mul64(g_world->score, 1000003);
    log_msg(1, "frames %d score %d checksum %08x big %ld", frames, g_world->score,
            checksum(g_screen, sizeof(g_screen), 7, 1, 0xff, 5), (long)(big >> 8));
    log_msg(1, "walker class id %d", entity_class_by_name("walker"));
    free(g_world);
    return 0;
}

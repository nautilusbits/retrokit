/* Synthetic test program for retro-kit: exercises the code patterns the
 * pipeline has to handle in DOS-era Watcom binaries. Not a real game.
 *
 * Annotations read by tests/evaluate.py (comment on the line before a
 * function definition):
 *   @noreturn   function never returns
 *   @table      only reachable through a function-pointer table
 *   @varargs    variadic
 */
#ifndef ENGINE_H
#define ENGINE_H

#define MAX_ENTITIES 64
#define MAP_W 64
#define MAP_H 64

typedef struct Entity Entity;
typedef void (*UpdateFn)(Entity *e, int ticks);
typedef int (*DrawFn)(const Entity *e, unsigned char *screen, int pitch);

typedef struct EntityClass {
    const char *name;
    int id;
    UpdateFn update;
    DrawFn draw;
    int enabled;
} EntityClass;

struct Entity {
    int x, y;            /* 16.16 fixed point */
    int dx, dy;
    short health;
    short state;
    unsigned char cls;
    unsigned char flags;
    unsigned short frame;
    Entity *target;
};

typedef struct World {
    unsigned char height[MAP_H][MAP_W];
    unsigned char tiles[MAP_H][MAP_W];
    Entity entities[MAX_ENTITIES];
    int entity_count;
    unsigned int seed;
    int tick;
    int score;
    char level_name[32];
} World;

extern World *g_world;
extern const EntityClass g_classes[];
extern int g_class_count;
extern int g_verbose;

/* util.c */
void fatal(const char *fmt, ...);
void log_msg(int level, const char *fmt, ...);
unsigned int rng_next(unsigned int *seed);
int rng_range(unsigned int *seed, int lo, int hi);
int clamp(int v, int lo, int hi);
int fixed_mul(int a, int b);
long long mul64(int a, int b);
int checksum(const unsigned char *p, int len, int seed, int rounds, int mask, int shift);

/* world.c */
World *world_create(unsigned int seed);
void world_generate(World *w, int roughness, int water_level);
int world_height_at(const World *w, int x, int y);
void world_smooth(World *w, int passes);
int world_load(World *w, const char *path);

/* entity.c */
Entity *entity_spawn(World *w, int cls, int x, int y);
void entity_update_all(World *w, int ticks);
int entity_draw_all(const World *w, unsigned char *screen, int pitch);
int entity_class_by_name(const char *name);
void entity_damage(Entity *e, int amount, int source, int flags);

/* render.c */
void render_frame(const World *w, unsigned char *screen, int pitch, int cam_x, int cam_y);
void render_hline(unsigned char *screen, int pitch, int x0, int x1, int y, int color);
int render_text(unsigned char *screen, int pitch, int x, int y, const char *text);

#endif

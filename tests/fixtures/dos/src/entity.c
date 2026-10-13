#include <string.h>
#include "engine.h"

enum { ST_IDLE, ST_WALK, ST_ATTACK, ST_DEAD };

/* @table */
void upd_static(Entity *e, int ticks)
{
    e->frame = (unsigned short)(e->frame + ticks);
}

/* @table */
void upd_walker(Entity *e, int ticks)
{
    switch (e->state) {
    case ST_IDLE:
        if (rng_next(&g_world->seed) < 100)
            e->state = ST_WALK;
        break;
    case ST_WALK:
        e->x += e->dx * ticks;
        e->y += e->dy * ticks;
        if (world_height_at(g_world, e->x, e->y) < 40) {
            e->dx = -e->dx;
            e->dy = -e->dy;
        }
        break;
    case ST_ATTACK:
        if (e->target != NULL && e->target->health > 0)
            entity_damage(e->target, 5, e->cls, 1);
        else
            e->state = ST_IDLE;
        break;
    case ST_DEAD:
        e->flags &= ~1;
        break;
    default:
        fatal("bad entity state %d", e->state);
    }
    e->frame++;
}

/* @table */
void upd_flyer(Entity *e, int ticks)
{
    int h = world_height_at(g_world, e->x, e->y);
    e->x += fixed_mul(e->dx, ticks << 16);
    e->y += fixed_mul(e->dy, ticks << 16);
    if (h > 200)
        e->dy = -e->dy;
    e->frame = (unsigned short)((e->frame + 1) & 7);
}

/* @table */
int draw_sprite(const Entity *e, unsigned char *screen, int pitch)
{
    int sx = (e->x >> 16) * 4, sy = (e->y >> 16) * 3;
    int i;
    if (sx < 0 || sy < 0 || sx > 316 || sy > 196)
        return 0;
    for (i = 0; i < 4; i++)
        render_hline(screen, pitch, sx, sx + 3, sy + i, 32 + e->cls * 8 + (e->frame & 3));
    return 1;
}

/* @table */
int draw_none(const Entity *e, unsigned char *screen, int pitch)
{
    (void)e; (void)screen; (void)pitch;
    return 0;
}

const EntityClass g_classes[] = {
    { "marker", 0, upd_static, draw_none,   1 },
    { "walker", 1, upd_walker, draw_sprite, 1 },
    { "flyer",  2, upd_flyer,  draw_sprite, 1 },
    { "ghost",  3, upd_flyer,  draw_none,   0 },
};
int g_class_count = sizeof(g_classes) / sizeof(g_classes[0]);

Entity *entity_spawn(World *w, int cls, int x, int y)
{
    Entity *e;
    if (cls < 0 || cls >= g_class_count)
        fatal("bad entity class %d", cls);
    if (w->entity_count >= MAX_ENTITIES)
        return NULL;
    e = &w->entities[w->entity_count++];
    memset(e, 0, sizeof(*e));
    e->x = x;
    e->y = y;
    e->dx = rng_range(&w->seed, -2, 2) << 12;
    e->dy = rng_range(&w->seed, -2, 2) << 12;
    e->health = 100;
    e->cls = (unsigned char)cls;
    e->flags = 1;
    return e;
}

void entity_update_all(World *w, int ticks)
{
    int i;
    for (i = 0; i < w->entity_count; i++) {
        Entity *e = &w->entities[i];
        const EntityClass *c = &g_classes[e->cls];
        if ((e->flags & 1) && c->enabled)
            c->update(e, ticks);
    }
}

int entity_draw_all(const World *w, unsigned char *screen, int pitch)
{
    int i, n = 0;
    for (i = 0; i < w->entity_count; i++) {
        const Entity *e = &w->entities[i];
        n += g_classes[e->cls].draw(e, screen, pitch);
    }
    return n;
}

int entity_class_by_name(const char *name)
{
    int i;
    for (i = 0; i < g_class_count; i++)
        if (strcmp(g_classes[i].name, name) == 0)
            return i;
    return -1;
}

void entity_damage(Entity *e, int amount, int source, int flags)
{
    if (flags & 2)
        amount *= 2;
    e->health = (short)(e->health - amount);
    if (e->health <= 0) {
        e->state = ST_DEAD;
        log_msg(2, "entity killed by class %d", source);
        if (g_world != NULL)
            g_world->score += 10;
    }
}

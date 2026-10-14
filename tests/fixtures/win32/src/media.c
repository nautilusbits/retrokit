/* Win32-only part of the test program (variant nt_s): DirectDraw used through its vtables,
 * the way C programs of the period called COM, plus imports from the Miles and Smacker DLLs.
 * Only built and linked, never run; the import libraries are made by build_fixtures.py.
 * The decompiled C must show the method names (tests/run_tests.py, "expect" in variant.json).
 */

typedef long (__stdcall *COMFN)();
typedef struct COMOBJ { COMFN *lpVtbl; } COMOBJ;

extern long __stdcall DirectDrawCreate(void *guid, COMOBJ **dd, void *outer);
extern long __stdcall AIL_startup(void);
extern long __stdcall AIL_set_preference(unsigned long number, long value);
extern void *__stdcall SmackOpen(const char *name, unsigned long flags, unsigned long extrabuf);
extern void __stdcall SmackClose(void *smk);

COMOBJ *g_dd;
COMOBJ *g_primary;
static unsigned char surface_desc[124];

int video_init(void *hwnd)
{
    COMOBJ *back = 0;
    long caps[4] = {4, 0, 0, 0};

    if (DirectDrawCreate(0, &g_dd, 0) != 0)
        return -1;
    g_dd->lpVtbl[20](g_dd, hwnd, 0x13);                       /* SetCooperativeLevel */
    g_dd->lpVtbl[21](g_dd, 640, 480, 8);                      /* SetDisplayMode */
    surface_desc[0] = 124;
    g_dd->lpVtbl[6](g_dd, surface_desc, &g_primary, 0);       /* CreateSurface */
    g_primary->lpVtbl[12](g_primary, caps, &back);            /* GetAttachedSurface */
    back->lpVtbl[25](back, 0, surface_desc, 1, 0);            /* Lock */
    back->lpVtbl[32](back, 0);                                /* Unlock */
    g_primary->lpVtbl[11](g_primary, 0, 1);                   /* Flip */
    return 0;
}

int media_init(void)
{
    void *smk;

    AIL_startup();
    AIL_set_preference(1, 22050);
    smk = SmackOpen("intro.smk", 0, 0);
    if (smk != 0)
        SmackClose(smk);
    return 0;
}

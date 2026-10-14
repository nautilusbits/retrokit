/* RAD Game Tools Smacker (SMACKW32.DLL) and Bink (BINKW32.DLL) - the commonly called part of
 * the Win32 API as documented in the SDKs (smack.h / bink.h). All functions are __stdcall
 * (imported as _Name@N; N = bytes of arguments, checked when the prototype is applied).
 * The handle structures are opaque here except for the leading fields games read directly.
 */

typedef void *HSMACK_FILE;

typedef struct SmackTag {
    U32 Version;            /* 'SMK2' / 'SMK4' */
    U32 Width;
    U32 Height;
    U32 Frames;
    U32 MSPerFrame;
    U32 SmackerType;
    U32 LargestInTrack[7];
    U32 tablesize;
    U32 codesize;
    U32 absize;
    U32 detailsize;
    U32 typesize;
    U32 TrackType[7];
    U32 extra;
    U32 NewPalette;
    unsigned char Palette[772];
    U32 PalType;
    U32 FrameNum;
    U32 FrameSize;
    U32 SndSize;
    S32 LastRectx;
    S32 LastRecty;
    S32 LastRectw;
    S32 LastRecth;
    U32 OpenFlags;
    U32 LeftOfs;
    U32 TopOfs;
} Smack;

typedef struct BINK {
    U32 Width;
    U32 Height;
    U32 Frames;
    U32 FrameNum;
    U32 LastFrameNum;
    U32 FrameRate;
    U32 FrameRateDiv;
    U32 ReadError;
    U32 OpenFlags;
    U32 BinkType;
    U32 Size;
    U32 FrameSize;
    U32 SndSize;
} BINK;
typedef BINK *HBINK;

Smack *__stdcall SmackOpen(const char *name, U32 flags, U32 extrabuf);
void __stdcall SmackClose(Smack *smk);
U32 __stdcall SmackDoFrame(Smack *smk);
void __stdcall SmackNextFrame(Smack *smk);
U32 __stdcall SmackWait(Smack *smk);
void __stdcall SmackToBuffer(Smack *smk, U32 left, U32 top, U32 Pitch, U32 destheight, void *buf, U32 Flags);
U32 __stdcall SmackToBufferRect(Smack *smk, U32 SmackSurface);
void __stdcall SmackGoto(Smack *smk, U32 frame);
void __stdcall SmackColorRemap(Smack *smk, const void *remappal, U32 numcolors, U32 paltype);
void __stdcall SmackSoundOnOff(Smack *smk, U32 on);
U32 __stdcall SmackSoundUseDirectSound(void *dd);
U32 __stdcall SmackSoundUseMSS(void *dd);
U32 __stdcall SmackSoundUseWin(void);
void __stdcall SmackVolumePan(Smack *smk, U32 trackflag, U32 volume, U32 pan);
U32 __stdcall SmackGetTrackData(Smack *smk, void *dest, U32 trackflag);
void __stdcall SmackSimulate(U32 sim);
void __stdcall SmackBufferNewPalette(void *sbuf, const void *pal, U32 paltype);

HBINK __stdcall BinkOpen(const char *name, U32 flags);
void __stdcall BinkClose(HBINK bink);
S32 __stdcall BinkDoFrame(HBINK bink);
void __stdcall BinkNextFrame(HBINK bink);
S32 __stdcall BinkWait(HBINK bink);
S32 __stdcall BinkPause(HBINK bink, S32 pause);
S32 __stdcall BinkCopyToBuffer(HBINK bink, void *dest, S32 destpitch, U32 destheight, U32 destx, U32 desty, U32 flags);
S32 __stdcall BinkCopyToBufferRect(HBINK bink, void *dest, S32 destpitch, U32 destheight, U32 destx, U32 desty, U32 srcx, U32 srcy, U32 srcw, U32 srch, U32 flags);
void __stdcall BinkGoto(HBINK bink, U32 frame, S32 flags);
S32 __stdcall BinkDDSurfaceType(void *lpDDS);
S32 __stdcall BinkSetSoundSystem(void *open, U32 param);
void *__stdcall BinkOpenDirectSound(U32 param);
void *__stdcall BinkOpenMiles(U32 param);
void __stdcall BinkSetVolume(HBINK bink, U32 trackid, S32 volume);
void __stdcall BinkSetPan(HBINK bink, U32 trackid, S32 pan);
void __stdcall BinkSetSoundOnOff(HBINK bink, S32 onoff);
void __stdcall BinkSetVideoOnOff(HBINK bink, S32 onoff);
char *__stdcall BinkGetError(void);

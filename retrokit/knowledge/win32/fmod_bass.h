/* FMOD 3 (FMOD.DLL, imported as _FSOUND_name@N / _FMUSIC_name@N) and BASS 2.2-2.4 (BASS.DLL,
 * undecorated names) - the commonly called functions as documented in fmod.h / bass.h, all
 * __stdcall. For FMOD the argument bytes in the decorated import name are checked; BASS
 * functions whose arguments changed between 2.x versions are left out.
 */

typedef struct FSOUND_SAMPLE FSOUND_SAMPLE;
typedef struct FSOUND_STREAM FSOUND_STREAM;
typedef struct FMUSIC_MODULE FMUSIC_MODULE;

signed char __stdcall FSOUND_Init(int mixrate, int maxsoftwarechannels, unsigned int flags);
void __stdcall FSOUND_Close(void);
signed char __stdcall FSOUND_SetOutput(int outputtype);
signed char __stdcall FSOUND_SetDriver(int driver);
signed char __stdcall FSOUND_SetHWND(void *hwnd);
int __stdcall FSOUND_GetError(void);
void __stdcall FSOUND_Update(void);
void __stdcall FSOUND_SetSFXMasterVolume(int volume);
FSOUND_SAMPLE *__stdcall FSOUND_Sample_Load(int index, const char *name_or_data, unsigned int inputmode, int offset, int length);
void __stdcall FSOUND_Sample_Free(FSOUND_SAMPLE *sptr);
int __stdcall FSOUND_PlaySound(int channel, FSOUND_SAMPLE *sptr);
signed char __stdcall FSOUND_StopSound(int channel);
signed char __stdcall FSOUND_SetVolume(int channel, int vol);
signed char __stdcall FSOUND_SetPan(int channel, int pan);
signed char __stdcall FSOUND_SetFrequency(int channel, int freq);
signed char __stdcall FSOUND_SetPaused(int channel, signed char paused);
signed char __stdcall FSOUND_SetLoopMode(int channel, unsigned int loopmode);
signed char __stdcall FSOUND_IsPlaying(int channel);
FSOUND_STREAM *__stdcall FSOUND_Stream_Open(const char *name_or_data, unsigned int mode, int offset, int length);
int __stdcall FSOUND_Stream_Play(int channel, FSOUND_STREAM *stream);
signed char __stdcall FSOUND_Stream_Stop(FSOUND_STREAM *stream);
signed char __stdcall FSOUND_Stream_Close(FSOUND_STREAM *stream);
FMUSIC_MODULE *__stdcall FMUSIC_LoadSong(const char *name);
signed char __stdcall FMUSIC_PlaySong(FMUSIC_MODULE *mod);
signed char __stdcall FMUSIC_StopSong(FMUSIC_MODULE *mod);
signed char __stdcall FMUSIC_FreeSong(FMUSIC_MODULE *mod);
signed char __stdcall FMUSIC_SetMasterVolume(FMUSIC_MODULE *mod, int volume);
signed char __stdcall FMUSIC_IsPlaying(FMUSIC_MODULE *mod);

BOOL __stdcall BASS_Init(int device, DWORD freq, DWORD flags, HWND win, const void *dsguid);
BOOL __stdcall BASS_Free(void);
BOOL __stdcall BASS_Start(void);
BOOL __stdcall BASS_Stop(void);
BOOL __stdcall BASS_Pause(void);
int __stdcall BASS_ErrorGetCode(void);
DWORD __stdcall BASS_GetVersion(void);
DWORD __stdcall BASS_StreamCreateFile(BOOL mem, const void *file, QWORD offset, QWORD length, DWORD flags);
BOOL __stdcall BASS_StreamFree(DWORD handle);
BOOL __stdcall BASS_SampleFree(DWORD handle);
BOOL __stdcall BASS_MusicFree(DWORD handle);
BOOL __stdcall BASS_ChannelPlay(DWORD handle, BOOL restart);
BOOL __stdcall BASS_ChannelStop(DWORD handle);
BOOL __stdcall BASS_ChannelPause(DWORD handle);
DWORD __stdcall BASS_ChannelIsActive(DWORD handle);

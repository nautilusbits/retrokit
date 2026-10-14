/* Miles Sound System for Win32 (MSS32.DLL, MSS 3.x-6.x) - the commonly called part of the API
 * as documented in the SDK (mss.h). __stdcall, imported as _AIL_name@N (N = argument bytes,
 * checked when the prototype is applied, so a version with other arguments is left alone).
 * Handles are opaque.
 */

typedef struct _DIG_DRIVER *HDIGDRIVER;
typedef struct _MDI_DRIVER *HMDIDRIVER;
typedef struct _SAMPLE *HSAMPLE;
typedef struct _SEQUENCE *HSEQUENCE;
typedef struct _STREAM *HSTREAM;
typedef struct _AUDIO *HAUDIO;
typedef struct _REDBOOK *HREDBOOK;
typedef S32 HTIMER;

S32 __stdcall AIL_startup(void);
void __stdcall AIL_shutdown(void);
S32 __stdcall AIL_set_preference(U32 number, S32 value);
char *__stdcall AIL_last_error(void);
S32 __stdcall AIL_set_redist_directory(const char *dir);
void *__stdcall AIL_mem_alloc_lock(U32 size);
void __stdcall AIL_mem_free_lock(void *ptr);
void *__stdcall AIL_file_read(const char *filename, void *dest);
S32 __stdcall AIL_file_size(const char *filename);

S32 __stdcall AIL_waveOutOpen(HDIGDRIVER *drvr, void **lphWaveOut, S32 dwDeviceID, void *lpFormat);
void __stdcall AIL_waveOutClose(HDIGDRIVER drvr);
HDIGDRIVER __stdcall AIL_open_digital_driver(U32 frequency, S32 bits, S32 channel, U32 flags);
void __stdcall AIL_close_digital_driver(HDIGDRIVER dig);
void __stdcall AIL_set_digital_master_volume(HDIGDRIVER dig, S32 master_volume);
S32 __stdcall AIL_digital_master_volume(HDIGDRIVER dig);

HSAMPLE __stdcall AIL_allocate_sample_handle(HDIGDRIVER dig);
void __stdcall AIL_release_sample_handle(HSAMPLE S);
void __stdcall AIL_init_sample(HSAMPLE S);
S32 __stdcall AIL_set_sample_file(HSAMPLE S, const void *file_image, S32 block);
void __stdcall AIL_set_sample_address(HSAMPLE S, const void *start, U32 len);
void __stdcall AIL_set_sample_type(HSAMPLE S, S32 format, U32 flags);
void __stdcall AIL_set_sample_playback_rate(HSAMPLE S, S32 playback_rate);
void __stdcall AIL_set_sample_volume(HSAMPLE S, S32 volume);
void __stdcall AIL_set_sample_pan(HSAMPLE S, S32 pan);
void __stdcall AIL_set_sample_loop_count(HSAMPLE S, S32 loop_count);
void __stdcall AIL_start_sample(HSAMPLE S);
void __stdcall AIL_stop_sample(HSAMPLE S);
void __stdcall AIL_resume_sample(HSAMPLE S);
void __stdcall AIL_end_sample(HSAMPLE S);
U32 __stdcall AIL_sample_status(HSAMPLE S);
S32 __stdcall AIL_sample_volume(HSAMPLE S);
void *__stdcall AIL_register_EOS_callback(HSAMPLE S, void *EOS);

HSTREAM __stdcall AIL_open_stream(HDIGDRIVER dig, const char *filename, S32 stream_mem);
void __stdcall AIL_close_stream(HSTREAM stream);
void __stdcall AIL_start_stream(HSTREAM stream);
void __stdcall AIL_pause_stream(HSTREAM stream, S32 onoff);
void __stdcall AIL_set_stream_volume(HSTREAM stream, S32 volume);
void __stdcall AIL_set_stream_pan(HSTREAM stream, S32 pan);
void __stdcall AIL_set_stream_loop_count(HSTREAM stream, S32 count);
S32 __stdcall AIL_stream_status(HSTREAM stream);

S32 __stdcall AIL_midiOutOpen(HMDIDRIVER *drvr, void **lphMidiOut, S32 dwDeviceID);
void __stdcall AIL_midiOutClose(HMDIDRIVER mdi);
HSEQUENCE __stdcall AIL_allocate_sequence_handle(HMDIDRIVER mdi);
void __stdcall AIL_release_sequence_handle(HSEQUENCE S);
S32 __stdcall AIL_init_sequence(HSEQUENCE S, const void *start, S32 sequence_num);
void __stdcall AIL_start_sequence(HSEQUENCE S);
void __stdcall AIL_stop_sequence(HSEQUENCE S);
void __stdcall AIL_resume_sequence(HSEQUENCE S);
void __stdcall AIL_end_sequence(HSEQUENCE S);
void __stdcall AIL_set_sequence_volume(HSEQUENCE S, S32 volume, S32 milliseconds);
void __stdcall AIL_set_sequence_loop_count(HSEQUENCE S, S32 loop_count);
U32 __stdcall AIL_sequence_status(HSEQUENCE S);
void __stdcall AIL_set_XMIDI_master_volume(HMDIDRIVER mdi, S32 master_volume);

HTIMER __stdcall AIL_register_timer(void *callback_fn);
void __stdcall AIL_set_timer_frequency(HTIMER timer, U32 hertz);
void __stdcall AIL_start_timer(HTIMER timer);
void __stdcall AIL_stop_timer(HTIMER timer);
void __stdcall AIL_release_timer_handle(HTIMER timer);

S32 __stdcall AIL_quick_startup(S32 use_digital, S32 use_MIDI, U32 output_rate, S32 output_bits, S32 output_channels);
void __stdcall AIL_quick_shutdown(void);
HAUDIO __stdcall AIL_quick_load(const char *filename);
S32 __stdcall AIL_quick_play(HAUDIO audio, U32 loop_count);
void __stdcall AIL_quick_halt(HAUDIO audio);
void __stdcall AIL_quick_unload(HAUDIO audio);
void __stdcall AIL_quick_set_volume(HAUDIO audio, S32 volume, S32 extravol);
S32 __stdcall AIL_quick_status(HAUDIO audio);

HREDBOOK __stdcall AIL_redbook_open(U32 which);
U32 __stdcall AIL_redbook_play(HREDBOOK hand, U32 startms, U32 endms);
U32 __stdcall AIL_redbook_stop(HREDBOOK hand);
void __stdcall AIL_redbook_close(HREDBOOK hand);

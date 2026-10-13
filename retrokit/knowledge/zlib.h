/* zlib 1.0 - 1.2 interface (zlib license), as in the library's zlib.h. Applied to the functions
 * the zlib signatures name. Ghidra's C parser reads all knowledge headers together, so the
 * types of watcom_clib.h are available here.
 */

typedef unsigned char Byte;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef Byte Bytef;
typedef char charf;
typedef int intf;
typedef uInt uIntf;
typedef uLong uLongf;
typedef void *voidpf;
typedef void *voidp;
typedef voidp gzFile;
typedef voidpf (*alloc_func)(voidpf opaque, uInt items, uInt size);
typedef void (*free_func)(voidpf opaque, voidpf address);

struct internal_state;

typedef struct z_stream_s {
    Bytef *next_in;
    uInt avail_in;
    uLong total_in;
    Bytef *next_out;
    uInt avail_out;
    uLong total_out;
    char *msg;
    struct internal_state *state;
    alloc_func zalloc;
    free_func zfree;
    voidpf opaque;
    int data_type;
    uLong adler;
    uLong reserved;
} z_stream;

typedef z_stream *z_streamp;

const char *zlibVersion(void);
int deflate(z_streamp strm, int flush);
int deflateEnd(z_streamp strm);
int inflate(z_streamp strm, int flush);
int inflateEnd(z_streamp strm);
int deflateSetDictionary(z_streamp strm, const Bytef *dictionary, uInt dictLength);
int deflateCopy(z_streamp dest, z_streamp source);
int deflateReset(z_streamp strm);
int deflateParams(z_streamp strm, int level, int strategy);
int inflateSetDictionary(z_streamp strm, const Bytef *dictionary, uInt dictLength);
int inflateSync(z_streamp strm);
int inflateReset(z_streamp strm);
int inflateSyncPoint(z_streamp z);
int deflateInit_(z_streamp strm, int level, const char *version, int stream_size);
int inflateInit_(z_streamp strm, const char *version, int stream_size);
int deflateInit2_(z_streamp strm, int level, int method, int windowBits, int memLevel, int strategy,
                  const char *version, int stream_size);
int inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int compress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level);
uLong compressBound(uLong sourceLen);
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
gzFile gzopen(const char *path, const char *mode);
gzFile gzdopen(int fd, const char *mode);
int gzsetparams(gzFile file, int level, int strategy);
int gzread(gzFile file, voidp buf, unsigned len);
int gzwrite(gzFile file, const voidp buf, unsigned len);
int gzprintf(gzFile file, const char *format, ...);
int gzputs(gzFile file, const char *s);
char *gzgets(gzFile file, char *buf, int len);
int gzputc(gzFile file, int c);
int gzgetc(gzFile file);
int gzflush(gzFile file, int flush);
long gzseek(gzFile file, long offset, int whence);
int gzrewind(gzFile file);
long gztell(gzFile file);
int gzeof(gzFile file);
int gzclose(gzFile file);
const char *gzerror(gzFile file, int *errnum);
uLong adler32(uLong adler, const Bytef *buf, uInt len);
uLong crc32(uLong crc, const Bytef *buf, uInt len);
const char *zError(int err);
const uLongf *get_crc_table(void);

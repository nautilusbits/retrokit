/* Prototypes of the Watcom C/C++ 32-bit run-time library (C standard library, POSIX-style
 * I/O, DOS and BIOS interfaces) for functions that retrokit's signatures name.
 * Written from the C standard and the documented Watcom library interface; plain C that
 * Ghidra's C parser accepts. Applied by ghidra_scripts/ApplyLibraryPrototypes.java to every
 * function with one of these names; the calling convention comes from the program (Watcom
 * register or stack convention), variadic functions always take their arguments on the stack.
 */

typedef unsigned int size_t;
typedef int ssize_t;
typedef long off_t;
typedef long time_t;
typedef long clock_t;
typedef unsigned short wchar_t;
typedef char *va_list;
typedef long fpos_t;
typedef void (*__sighandler_t)(int);

typedef struct __iobuf {
    unsigned char *_ptr;
    int _cnt;
    unsigned char *_base;
    unsigned _flag;
    int _handle;
    unsigned _bufsize;
    unsigned char _ungotten;
    unsigned char _tmpfchar;
} FILE;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef struct {
    int quot;
    int rem;
} div_t;

typedef struct {
    long quot;
    long rem;
} ldiv_t;

typedef unsigned int jmp_buf[13];

struct DWORDREGS {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    unsigned int esi;
    unsigned int edi;
    unsigned int cflag;
};

union REGS {
    struct DWORDREGS x;
};

struct SREGS {
    unsigned short es;
    unsigned short cs;
    unsigned short ss;
    unsigned short ds;
    unsigned short fs;
    unsigned short gs;
};

struct find_t {
    char reserved[21];
    char attrib;
    unsigned short wr_time;
    unsigned short wr_date;
    unsigned long size;
    char name[13];
};

struct dosdate_t {
    unsigned char day;
    unsigned char month;
    unsigned short year;
    unsigned char dayofweek;
};

struct dostime_t {
    unsigned char hour;
    unsigned char minute;
    unsigned char second;
    unsigned char hsecond;
};

struct diskfree_t {
    unsigned short total_clusters;
    unsigned short avail_clusters;
    unsigned short sectors_per_cluster;
    unsigned short bytes_per_sector;
};

struct stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned short st_mode;
    short st_nlink;
    unsigned long st_uid;
    short st_gid;
    unsigned long st_rdev;
    long st_size;
    long st_atime;
    long st_mtime;
    long st_ctime;
};

/* string.h */
void *memchr(const void *s, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memicmp(const void *a, const void *b, size_t n);
char *strcat(char *dst, const char *src);
char *strchr(const char *s, int c);
int strcmp(const char *a, const char *b);
int strcoll(const char *a, const char *b);
char *strcpy(char *dst, const char *src);
size_t strcspn(const char *s, const char *reject);
char *strdup(const char *s);
char *strerror(int errnum);
int stricmp(const char *a, const char *b);
int _stricmp(const char *a, const char *b);
int strcmpi(const char *a, const char *b);
int strcasecmp(const char *a, const char *b);
size_t strlen(const char *s);
char *strlwr(char *s);
char *_strlwr(char *s);
char *strncat(char *dst, const char *src, size_t n);
int strncmp(const char *a, const char *b, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
int strnicmp(const char *a, const char *b, size_t n);
int _strnicmp(const char *a, const char *b, size_t n);
int strncasecmp(const char *a, const char *b, size_t n);
char *strnset(char *s, int c, size_t n);
char *strpbrk(const char *s, const char *accept);
char *strrchr(const char *s, int c);
char *strrev(char *s);
char *strset(char *s, int c);
size_t strspn(const char *s, const char *accept);
char *strstr(const char *haystack, const char *needle);
char *strtok(char *s, const char *delim);
char *strupr(char *s);
char *_strupr(char *s);
size_t strxfrm(char *dst, const char *src, size_t n);

/* ctype.h */
int isalnum(int c);
int isalpha(int c);
int iscntrl(int c);
int isdigit(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);
int isascii(int c);
int tolower(int c);
int toupper(int c);
int _tolower(int c);
int _toupper(int c);

/* stdlib.h */
void abort(void);
int abs(int n);
int atexit(void (*fn)(void));
double atof(const char *s);
int atoi(const char *s);
long atol(const char *s);
void *bsearch(const void *key, const void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
void *calloc(size_t n, size_t size);
div_t div(int num, int den);
void exit(int status);
void _exit(int status);
void free(void *p);
char *getenv(const char *name);
char *itoa(int value, char *buf, int radix);
long labs(long n);
ldiv_t ldiv(long num, long den);
char *ltoa(long value, char *buf, int radix);
void *malloc(size_t size);
int putenv(const char *s);
void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
int rand(void);
void *realloc(void *p, size_t size);
void srand(unsigned int seed);
double strtod(const char *s, char **end);
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
int system(const char *cmd);
char *ultoa(unsigned long value, char *buf, int radix);
char *utoa(unsigned int value, char *buf, int radix);
char *_fullpath(char *buf, const char *path, size_t size);
void _makepath(char *path, const char *drive, const char *dir, const char *fname, const char *ext);
void _splitpath(const char *path, char *drive, char *dir, char *fname, char *ext);
void *_nmalloc(size_t size);
void _nfree(void *p);
void *_nrealloc(void *p, size_t size);
void *_ncalloc(size_t n, size_t size);
void *_expand(void *p, size_t size);
size_t _msize(void *p);
int _heapchk(void);
int _heapmin(void);
int _heapshrink(void);

/* stdio.h */
void clearerr(FILE *fp);
int fclose(FILE *fp);
int fcloseall(void);
FILE *fdopen(int handle, const char *mode);
int feof(FILE *fp);
int ferror(FILE *fp);
int fflush(FILE *fp);
int fgetc(FILE *fp);
int fgetpos(FILE *fp, fpos_t *pos);
char *fgets(char *buf, int n, FILE *fp);
int fileno(FILE *fp);
int flushall(void);
FILE *fopen(const char *name, const char *mode);
int fprintf(FILE *fp, const char *fmt, ...);
int fputc(int c, FILE *fp);
int fputs(const char *s, FILE *fp);
size_t fread(void *buf, size_t size, size_t n, FILE *fp);
FILE *freopen(const char *name, const char *mode, FILE *fp);
int fscanf(FILE *fp, const char *fmt, ...);
int fseek(FILE *fp, long offset, int whence);
int fsetpos(FILE *fp, const fpos_t *pos);
long ftell(FILE *fp);
size_t fwrite(const void *buf, size_t size, size_t n, FILE *fp);
int getc(FILE *fp);
int getchar(void);
char *gets(char *buf);
void perror(const char *s);
int printf(const char *fmt, ...);
int putc(int c, FILE *fp);
int putchar(int c);
int puts(const char *s);
int remove(const char *name);
int rename(const char *from, const char *to);
void rewind(FILE *fp);
int scanf(const char *fmt, ...);
void setbuf(FILE *fp, char *buf);
int setvbuf(FILE *fp, char *buf, int mode, size_t size);
int snprintf(char *buf, size_t n, const char *fmt, ...);
int _snprintf(char *buf, size_t n, const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
int sscanf(const char *s, const char *fmt, ...);
FILE *tmpfile(void);
char *tmpnam(char *buf);
int ungetc(int c, FILE *fp);
int vfprintf(FILE *fp, const char *fmt, va_list ap);
int vprintf(const char *fmt, va_list ap);
int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int _vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int vsprintf(char *buf, const char *fmt, va_list ap);
int vfscanf(FILE *fp, const char *fmt, va_list ap);
int vsscanf(const char *s, const char *fmt, va_list ap);

/* io.h, fcntl.h: handle-based I/O */
int access(const char *path, int mode);
int chmod(const char *path, int mode);
int chsize(int handle, long size);
int close(int handle);
int creat(const char *path, int mode);
int dup(int handle);
int dup2(int handle, int handle2);
int eof(int handle);
long filelength(int handle);
int fstat(int handle, struct stat *buf);
int fsync(int handle);
int isatty(int handle);
long lseek(int handle, long offset, int whence);
int open(const char *path, int access, ...);
int read(int handle, void *buf, unsigned int len);
int setmode(int handle, int mode);
int sopen(const char *path, int access, int share, ...);
int _sopen(const char *path, int access, int share, ...);
int stat(const char *path, struct stat *buf);
long tell(int handle);
int umask(int mode);
int unlink(const char *path);
int write(int handle, const void *buf, unsigned int len);

/* direct.h */
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int mkdir(const char *path);
int rmdir(const char *path);

/* time.h */
char *asctime(const struct tm *t);
clock_t clock(void);
char *ctime(const time_t *t);
double difftime(time_t a, time_t b);
struct tm *gmtime(const time_t *t);
struct tm *localtime(const time_t *t);
time_t mktime(struct tm *t);
size_t strftime(char *buf, size_t n, const char *fmt, const struct tm *t);
time_t time(time_t *t);
void tzset(void);

/* setjmp.h, signal.h */
int setjmp(jmp_buf env);
int _setjmp(jmp_buf env);
void longjmp(jmp_buf env, int value);
__sighandler_t signal(int sig, __sighandler_t handler);
int raise(int sig);

/* math.h */
double acos(double x);
double asin(double x);
double atan(double x);
double atan2(double y, double x);
double ceil(double x);
double cos(double x);
double cosh(double x);
double exp(double x);
double fabs(double x);
double floor(double x);
double fmod(double x, double y);
double frexp(double x, int *e);
double hypot(double x, double y);
double ldexp(double x, int e);
double log(double x);
double log10(double x);
double modf(double x, double *ip);
double pow(double x, double y);
double sin(double x);
double sinh(double x);
double sqrt(double x);
double tan(double x);
double tanh(double x);

/* conio.h */
int getch(void);
int getche(void);
int kbhit(void);
int putch(int c);
int ungetch(int c);
int cprintf(const char *fmt, ...);
int cputs(const char *s);
char *cgets(char *buf);
unsigned int inp(unsigned int port);
unsigned int inpw(unsigned int port);
unsigned int outp(unsigned int port, unsigned int value);
unsigned int outpw(unsigned int port, unsigned int value);

/* dos.h, i86.h, bios.h */
int int386(int intno, union REGS *in, union REGS *out);
int int386x(int intno, union REGS *in, union REGS *out, struct SREGS *seg);
void segread(struct SREGS *seg);
void delay(unsigned int ms);
void sound(unsigned int hz);
void nosound(void);
unsigned int _dos_close(int handle);
unsigned int _dos_creat(const char *path, unsigned int attr, int *handle);
unsigned int _dos_findfirst(const char *path, unsigned int attr, struct find_t *buf);
unsigned int _dos_findnext(struct find_t *buf);
unsigned int _dos_findclose(struct find_t *buf);
void _dos_getdate(struct dosdate_t *date);
unsigned int _dos_getdiskfree(unsigned int drive, struct diskfree_t *buf);
void _dos_getdrive(unsigned int *drive);
unsigned int _dos_getfileattr(const char *path, unsigned int *attr);
void _dos_gettime(struct dostime_t *time);
unsigned int _dos_open(const char *path, unsigned int mode, int *handle);
unsigned int _dos_read(int handle, void *buf, unsigned int count, unsigned int *bytes);
unsigned int _dos_setdate(struct dosdate_t *date);
void _dos_setdrive(unsigned int drive, unsigned int *total);
unsigned int _dos_setfileattr(const char *path, unsigned int attr);
unsigned int _dos_settime(struct dostime_t *time);
unsigned int _dos_write(int handle, const void *buf, unsigned int count, unsigned int *bytes);
unsigned short _bios_keybrd(unsigned int cmd);
int _harderr(void *handler);
void _hardresume(int result);
void _hardretn(int error);

/* process.h */
int spawnl(int mode, const char *path, const char *arg0, ...);
int spawnv(int mode, const char *path, const char *const *argv);
int spawnvp(int mode, const char *path, const char *const *argv);
int execv(const char *path, const char *const *argv);

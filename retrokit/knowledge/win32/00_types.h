/* Basic Win32 types used by the other knowledge/win32 headers (parsed first, together). */

typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long LONG;
typedef unsigned int UINT;
typedef int BOOL;
typedef long HRESULT;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HDC;
typedef void *HINSTANCE;
/* wchar_t, size_t, ...: watcom_clib.h, parsed before */
typedef unsigned __int64 QWORD;
typedef unsigned long U32;
typedef long S32;
typedef struct _GUID { DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8]; } GUID;

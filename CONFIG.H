#include "YASM-VERSION.h"
#define yasm__splitpath(path, tail)     yasm__splitpath_win(path, tail)
#define yasm__abspath(path)             yasm__abspath_win(path)
#define yasm__combpath(from, to)        yasm__combpath_win(from, to)

/* Command name to run C preprocessor */
#define CPP_PROG "cpp"

/* Define if you have the `abort' function. */
#define HAVE_ABORT 1

/* Define to 1 if you have the <direct.h> header file. */
#define HAVE_DIRECT_H 1

/* Define to 1 if you have the `getcwd' function. */
#define HAVE_GETCWD 1

/* Define if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the `toascii' function. */
#define HAVE_TOASCII 1
#define toascii __toascii

/* Define to 1 if you have the `_stricmp' function. */
#define HAVE__STRICMP 1

/* Define to 1 if you have the `_strnicmp' function. */
#define HAVE__STRNICMP 1

/* Name of package */
#define PACKAGE "yasm"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "bug-yasm@tortall.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "yasm"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "yasm"

/* Define if the C compiler supports function prototypes. */
#define PROTOTYPES 1

/* Define if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "HEAD"

/* Define like PROTOTYPES; this can be used by system headers. */
#define __PROTOTYPES 1

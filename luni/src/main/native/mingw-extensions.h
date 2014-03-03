#ifndef MINGW_EXTENSIONS
#define MINGW_EXTENSIONS

// mingw-w64 now lacks support of these functions and structures
// If some of them are included into the new version of MinGW, they could be removed from this file

#ifdef __PROVIDE_FIXMES
#define FIXME_STUB(newErrno, returnCode) \
    { \
        printf("!FIXME! %s:%d (%s) - errno = %d, rc = %d\n", __FILE__, __LINE__, __FUNCTION__, newErrno, returnCode); \
        errno = newErrno; \
        return returnCode; \
    }
#else
#define FIXME_STUB(newErrno, returnCode) \
    { \
        errno = newErrno; \
        return returnCode; \
    }
#endif

// including Winsock2.h unconditionally as it has to be included before windows.h
#include <Winsock2.h>

#include <windows.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include <iphlpapi.h>

#include "Portability.h"

#define EAI_ADDRFAMILY    1
//#define EAI_AGAIN         2
//#define EAI_BADFLAGS      3
//#define EAI_FAIL          4
//#define EAI_FAMILY        5
//#define EAI_MEMORY        6
//#define EAI_NONAME        7
#define EAI_OVERFLOW      8
//#define EAI_SERVICE       9
//#define EAI_SOCKTYPE      10
#define EAI_SYSTEM        11

#define AI_ADDRCONFIG    0x0001
#define AI_ALL           0x0002
//#define AI_CANONNAME     0x0004
//#define AI_NUMERICHOST   0x0008
#define AI_NUMERICSERV   0x0010
//#define AI_PASSIVE       0x0020
#define AI_V4MAPPED      0x0040
#define AI_DEFAULT       (AI_V4MAPPED | AI_ADDRCONFIG)

//#define NI_DGRAM         0x0001
//#define NI_NAMEREQD      0x0002
//#define NI_NOFQDN        0x0004
//#define NI_NUMERICHOST   0x0008
#define NI_NUMERICSCOPE  0x0010
//#define NI_NUMERICSERV   0x0020

#define EPERM        1
#define ENOENT       2
#define ESRCH        3
#define EINTR        4
#define EIO      5
#define ENXIO        6
#define E2BIG        7
#define ENOEXEC      8
#define EBADF        9
#define ECHILD      10

#ifdef EAGAIN	// Actually we are sure here
#undef EAGAIN
#endif
#define EAGAIN      EWOULDBLOCK

#define ENOMEM      12
#define EACCES      13
#define EFAULT      14
#define ENOTBLK     15
#define EBUSY       16
#define EEXIST      17
#define EXDEV       18
#define ENODEV      19
#define ENOTDIR     20
#define EISDIR      21
#define EINVAL      22
#define ENFILE      23
#define EMFILE      24
#define ENOTTY      25
#define ETXTBSY     26
#define EFBIG       27
#define ENOSPC      28
#define ESPIPE      29
#define EROFS       30
#define EMLINK      31
#define EPIPE       32
#define EDOM        33
#define ERANGE      34

//#define EDEADLK     35
//#define ENAMETOOLONG    36
//#define ENOLCK      37
//#define ENOSYS      38
//#define ENOTEMPTY   39
//#define ELOOP       40
//#define EWOULDBLOCK EAGAIN
#define ENOMSG      42
#define EIDRM       43
#define ECHRNG      44
#define EL2NSYNC    45
#define EL3HLT      46
#define EL3RST      47
#define ELNRNG      48
#define EUNATCH     49
#define ENOCSI      50
#define EL2HLT      51
#define EBADE       52
#define EBADR       53
#define EXFULL      54
#define ENOANO      55
#define EBADRQC     56
#define EBADSLT     57

#define EDEADLOCK   EDEADLK

#define EBFONT      59
#define ENOSTR      60
#define ENODATA     61
#define ETIME       62
#define ENOSR       63
#define ENONET      64
#define ENOPKG      65
#define EREMOTE     66
#define ENOLINK     67
#define EADV        68
#define ESRMNT      69
#define ECOMM       70
//#define EPROTO      71
#define EMULTIHOP   72
#define EDOTDOT     73
#define EBADMSG     74
//#define EOVERFLOW   75
#define ENOTUNIQ    76
#define EBADFD      77
#define EREMCHG     78
#define ELIBACC     79
#define ELIBBAD     80
#define ELIBSCN     81
#define ELIBMAX     82
#define ELIBEXEC    83
//#define EILSEQ      84
#define ERESTART    85
#define ESTRPIPE    86
#define EUSERS      87
//#define ENOTSOCK    88
//#define EDESTADDRREQ    89
//#define EMSGSIZE    90
//#define EPROTOTYPE  91
//#define ENOPROTOOPT 92
//#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
//#define EOPNOTSUPP  95
#define EPFNOSUPPORT    96
//#define EAFNOSUPPORT    97
//#define EADDRINUSE  98
//#define EADDRNOTAVAIL   99
//#define ENETDOWN    100
//#define ENETUNREACH 101
//#define ENETRESET   102
//#define ECONNABORTED    103
//#define ECONNRESET  104
//#define ENOBUFS     105
//#define EISCONN     106
//#define ENOTCONN    107
#define ESHUTDOWN   108
#define ETOOMANYREFS    109
//#define ETIMEDOUT   110
//#define ECONNREFUSED    111
#define EHOSTDOWN   112
//#define EHOSTUNREACH    113
//#define EALREADY    114
//#define EINPROGRESS 115
#define ESTALE      116
#define EUCLEAN     117
#define ENOTNAM     118
#define ENAVAIL     119
#define EISNAM      120
#define EREMOTEIO   121
#define EDQUOT      122

#define ENOMEDIUM   123
#define EMEDIUMTYPE 124
//#define ECANCELED   125
#define ENOKEY      126
#define EKEYEXPIRED 127
#define EKEYREVOKED 128
#define EKEYREJECTED    129
//#define EOWNERDEAD  130
#define ENOTRECOVERABLE 131

#define	FD_CLOEXEC	1

#define	F_DUPFD		0
#define	F_GETFD		1
#define	F_SETFD		2
#define	F_GETFL		3
#define	F_SETFL		4
#define	F_GETOWN	5
#define F_SETOWN	6
#define	F_GETLK		7
#define	F_SETLK		8
#define	F_SETLKW	9

#define	F_RDLCK		1
#define	F_UNLCK		2
#define	F_WRLCK		3

#define IFF_DEBUG       0x4 
#define IFF_ALLMULTI    0x200 
#define IFF_NOARP       0x80
#define IFF_NOTRAILERS  0x20
#define IFF_POINTOPOINT 0x10
#define IFF_PROMISC     0x100
#define IFF_RUNNING     0x40

#define MCL_CURRENT     1
#define MCL_FUTURE      2

#define MSG_CTRUNC      8
#define MSG_EOR         0x80
#define MSG_TRUNC       0x20

#define O_NOCTTY        0x00000400
#define O_NOFOLLOW      0x00400000
#define O_NONBLOCK      0x00004000
#define O_SYNC          0x04100000

#define POLLIN          0x0001
#define POLLPRI         0x0002
#define POLLOUT         0x0004
#define POLLERR         0x0008
#define POLLHUP         0x0010
#define POLLNVAL        0x0020

#define POLLRDNORM      0x0040
#define POLLRDBAND      0x0080
#define POLLWRNORM      0x0100
#define POLLWRBAND      0x0200
//#define POLLMSG         0x0400
//#define POLLREMOVE      0x1000
//#define POLLRDHUP       0x2000
//#define POLLFREE        0x4000
//#define POLL_BUSY_LOOP  0x8000

enum sock_shutdown_cmd {
    SHUT_RD,
    SHUT_WR,
    SHUT_RDWR,
};

#define SIGHUP           1
//#define SIGINT           2
#define SIGQUIT          3
//#define SIGILL           4
#define SIGTRAP          5
//#define SIGABRT          6
//#define SIGIOT           6
#define SIGBUS           7
//#define SIGFPE           8
#define SIGKILL          9
#define SIGUSR1         10
//#define SIGSEGV         11
#define SIGUSR2         12
#define SIGPIPE         13
#define SIGALRM         14
//#define SIGTERM         15
//#define SIGSTKFLT       16
#define SIGCHLD         17
#define SIGCONT         18
#define SIGSTOP         19
#define SIGTSTP         20
#define SIGTTIN         21
#define SIGTTOU         22
#define SIGURG          23
#define SIGXCPU         24
#define SIGXFSZ         25
#define SIGVTALRM       26
#define SIGPROF         27
#define SIGWINCH        28
#define SIGIO           29
//#define SIGPOLL         SIGIO
#define SIGSYS          31

#define SIOCGIFADDR     0x8915
//#define SIOCSIFADDR     0x8916
#define SIOCGIFDSTADDR  0x8917
//#define SIOCSIFDSTADDR  0x8918
#define SIOCGIFBRDADDR  0x8919
//#define SIOCSIFBRDADDR  0x891a
#define SIOCGIFNETMASK  0x891b
//#define SIOCSIFNETMASK  0x891c

//#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
//#define S_IFREG  0100000
//#define S_IFBLK  0060000
//#define S_IFDIR  0040000
//#define S_IFCHR  0020000
//#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

//#define S_IRWXU 00700
//#define S_IRUSR 00400
//#define S_IWUSR 00200
//#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define WNOHANG         0x00000001
#define WUNTRACED       0x00000002
#define WSTOPPED        WUNTRACED
#define WEXITED         0x00000004
#define WCONTINUED      0x00000008
#define WNOWAIT         0x01000000

#define NI_MAXHOST       1025
#define NI_MAXSERV       32


#define IF_NAMESIZE	32

typedef unsigned int uid_t;
typedef unsigned int gid_t;

typedef long loff_t;

// Sockets
typedef int socklen_t;

#define UNIX_PATH_LEN   108
typedef struct _sockaddr_un {
    uint16_t   sun_family;
    char       sun_path[UNIX_PATH_LEN];
} sockaddr_un;

#ifndef TEMP_FAILURE_RETRY
/* Stub. On Windows EINTR makes no sense AFAIK.
 * TODO: verify that. */
#define TEMP_FAILURE_RETRY(exp) (exp)
#endif


struct ucred {
	unsigned int 	pid;
	uid_t 	uid;
	gid_t 	gid;
};


// Password
struct passwd
{
  char *pw_name;		// Username.
  char *pw_passwd;		// Password.
  uid_t pw_uid;			// User ID.
  gid_t pw_gid;			// Group ID.
  char *pw_comment;		// Comment
  char *pw_gecos;		// Real name.
  char *pw_dir;			// Home directory.
  char *pw_shell;		// Shell program.
};

int getpwnam_r(const char *name, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result);

int getpwuid_r(uid_t uid, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result);

// chown
int chown(const char *path, uid_t owner, gid_t group);
int lchown(const char *path, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);

// mincore
int mincore(void *addr, size_t length, unsigned char *vec);

// mkdir
int mkdir(const char *pathname, mode_t mode);

// mlock/munlock/mmap

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_FILE        0
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_TYPE        0xf
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

#define MAP_FAILED      ((void *)-1)

/* Flags for msync. */
#define MS_ASYNC        1
#define MS_SYNC         2
#define MS_INVALIDATE   4

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE    0x0020
#endif /* FILE_MAP_EXECUTE */

// TODO: isn't it the same function as windowsErrorToErrno() in mingw-extensions.cpp ?
int mmap_winapi_error_to_posix(const DWORD winError);
DWORD mmap_page(const int prot);
DWORD mmap_file(const int prot);
void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t len, int flags);
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);

// pipe
int pipe(int* pipefd);

// fcntl

struct flock64 {
        short  l_type;
        short  l_whence;
        loff_t l_start;
        loff_t l_len;
        pid_t  l_pid;
        /*__ARCH_FLOCK64_PAD*/
};

int fcntl(int fd, int cmd, ... /* arg */ );

// fdatasync

int fdatasync(int fd);

int fsync(int fd);

// getgid, uid, ppid

gid_t getgid(void);
gid_t getegid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
int seteuid(uid_t euid);
int setegid(gid_t egid);
int setgid(gid_t gid);
pid_t setsid(void);
int setuid(uid_t euid);

// chmod

int fchmod(int fd, mode_t mode);

// uname

struct utsname
{
	char 	machine [20];
	char 	nodename [20];
	char 	release [20];
	char 	sysname [20];
	char 	version [20];
};

int uname(struct utsname *buf);

/** Assuming Windows ioctlsocket() function signature for now.
 * I see that ioctl() is used only twice in luni, this should be enough.
 */
int ioctl(int fd, int request, void *argp);

// kill

int kill(pid_t pid, int sig);

// ifreq

#define IFNAMSIZ        16

struct ifmap {
    unsigned long   mem_start;
    unsigned long   mem_end;
    unsigned short  base_addr;
    unsigned char   irq;
    unsigned char   dma;
    unsigned char   port;
};

struct ifreq {
    char    ifr_name[IFNAMSIZ];/* Interface name */
    union {
            sockaddr ifr_addr;
            sockaddr ifr_dstaddr;
            sockaddr ifr_broadaddr;
            sockaddr ifr_netmask;
            sockaddr ifr_hwaddr;
            short   ifr_flags;
            int     ifr_ifindex;
            int     ifr_metric;
            int     ifr_mtu;
            ifmap   ifr_map;
            char    ifr_slave[IFNAMSIZ];
            char    ifr_newname[IFNAMSIZ];
            char *  ifr_data;
    };
};

char *if_indextoname(unsigned int ifindex, char *ifname);

int inet_pton(int af, const char *src, void *dst);

// StatFS
#define _fullpath(res,path,size) \
  (GetFullPathName ((path), (size), (res), NULL) ? (res) : NULL)

#define realpath(path,resolved_path) _fullpath(resolved_path, path, MAX_PATH)

/* fake block size */
#define FAKED_BLOCK_SIZE 512

/* linux-compatible values for fs type */
#define MSDOS_SUPER_MAGIC     0x4d44
#define NTFS_SUPER_MAGIC      0x5346544E

#ifdef HAVE_SYS_VFS_H
  #undef HAVE_SYS_VFS_H
  #define HAVE_SYS_VFS_H 1
#else  /* HAVE_SYS_VFS_H */

struct statfs {
   long    f_type;     /* type of filesystem (see below) */
   long    f_bsize;    /* optimal transfer block size */
   long long    f_blocks;   /* total data blocks in file system */
   long long    f_bfree;    /* free blocks in fs */
   long long    f_bavail;   /* free blocks avail to non-superuser */
   long    f_files;    /* total file nodes in file system */
   long    f_ffree;    /* free file nodes in fs */
   long    f_fsid;     /* file system id */
   long    f_namelen;  /* maximum length of filenames */
   long    f_spare[6]; /* spare for later */
   
   long long f_frsize;
};
#endif /* HAVE_SYS_VFS_H */

int fstatfs (int fd, struct statfs *buf);

int __statfs (const char *path, struct statfs *buf);

#define statfs(_path,_buf) __statfs(_path,_buf)

int vasprintf(char **strp, const char *fmt, va_list args);
int asprintf(char **strp, const char *fmt, ...);

// lstat

int lstat(const char *path, struct stat *buf);

// sysconf
#define _SC_ARG_MAX             0x0000
#define _SC_BC_BASE_MAX         0x0001
#define _SC_BC_DIM_MAX          0x0002
#define _SC_BC_SCALE_MAX        0x0003
#define _SC_BC_STRING_MAX       0x0004
#define _SC_CHILD_MAX           0x0005
#define _SC_CLK_TCK             0x0006
#define _SC_COLL_WEIGHTS_MAX    0x0007
#define _SC_EXPR_NEST_MAX       0x0008
#define _SC_LINE_MAX            0x0009
#define _SC_NGROUPS_MAX         0x000a
#define _SC_OPEN_MAX            0x000b
#define _SC_PASS_MAX            0x000c
#define _SC_2_C_BIND            0x000d
#define _SC_2_C_DEV             0x000e
#define _SC_2_C_VERSION         0x000f
#define _SC_2_CHAR_TERM         0x0010
#define _SC_2_FORT_DEV          0x0011
#define _SC_2_FORT_RUN          0x0012
#define _SC_2_LOCALEDEF         0x0013
#define _SC_2_SW_DEV            0x0014
#define _SC_2_UPE               0x0015
#define _SC_2_VERSION           0x0016
#define _SC_JOB_CONTROL         0x0017
#define _SC_SAVED_IDS           0x0018
#define _SC_VERSION             0x0019
#define _SC_RE_DUP_MAX          0x001a
#define _SC_STREAM_MAX          0x001b
#define _SC_TZNAME_MAX          0x001c
#define _SC_XOPEN_CRYPT         0x001d
#define _SC_XOPEN_ENH_I18N      0x001e
#define _SC_XOPEN_SHM           0x001f
#define _SC_XOPEN_VERSION       0x0020
#define _SC_XOPEN_XCU_VERSION   0x0021
#define _SC_XOPEN_REALTIME      0x0022
#define _SC_XOPEN_REALTIME_THREADS  0x0023
#define _SC_XOPEN_LEGACY        0x0024
#define _SC_ATEXIT_MAX          0x0025
#define _SC_IOV_MAX             0x0026
#define _SC_PAGESIZE            0x0027
#define _SC_PAGE_SIZE           0x0028
#define _SC_XOPEN_UNIX          0x0029
#define _SC_XBS5_ILP32_OFF32    0x002a
#define _SC_XBS5_ILP32_OFFBIG   0x002b
#define _SC_XBS5_LP64_OFF64     0x002c
#define _SC_XBS5_LPBIG_OFFBIG   0x002d
#define _SC_AIO_LISTIO_MAX      0x002e
#define _SC_AIO_MAX             0x002f
#define _SC_AIO_PRIO_DELTA_MAX  0x0030
#define _SC_DELAYTIMER_MAX      0x0031
#define _SC_MQ_OPEN_MAX         0x0032
#define _SC_MQ_PRIO_MAX         0x0033
#define _SC_RTSIG_MAX           0x0034
#define _SC_SEM_NSEMS_MAX       0x0035
#define _SC_SEM_VALUE_MAX       0x0036
#define _SC_SIGQUEUE_MAX        0x0037
#define _SC_TIMER_MAX           0x0038
#define _SC_ASYNCHRONOUS_IO     0x0039
#define _SC_FSYNC               0x003a
#define _SC_MAPPED_FILES        0x003b
#define _SC_MEMLOCK             0x003c
#define _SC_MEMLOCK_RANGE       0x003d
#define _SC_MEMORY_PROTECTION   0x003e
#define _SC_MESSAGE_PASSING     0x003f
#define _SC_PRIORITIZED_IO      0x0040
#define _SC_PRIORITY_SCHEDULING 0x0041
#define _SC_REALTIME_SIGNALS    0x0042
#define _SC_SEMAPHORES          0x0043
#define _SC_SHARED_MEMORY_OBJECTS  0x0044
#define _SC_SYNCHRONIZED_IO     0x0045
#define _SC_TIMERS              0x0046
#define _SC_GETGR_R_SIZE_MAX    0x0047
#define _SC_GETPW_R_SIZE_MAX    0x0048
#define _SC_LOGIN_NAME_MAX      0x0049
#define _SC_THREAD_DESTRUCTOR_ITERATIONS  0x004a
#define _SC_THREAD_KEYS_MAX     0x004b
#define _SC_THREAD_STACK_MIN    0x004c
#define _SC_THREAD_THREADS_MAX  0x004d
#define _SC_TTY_NAME_MAX        0x004e

#define _SC_THREADS                     0x004f
#define _SC_THREAD_ATTR_STACKADDR       0x0050
#define _SC_THREAD_ATTR_STACKSIZE       0x0051
#define _SC_THREAD_PRIORITY_SCHEDULING  0x0052
#define _SC_THREAD_PRIO_INHERIT         0x0053
#define _SC_THREAD_PRIO_PROTECT         0x0054
#define _SC_THREAD_SAFE_FUNCTIONS       0x0055

#define _SC_NPROCESSORS_CONF            0x0060
#define _SC_NPROCESSORS_ONLN            0x0061
#define _SC_PHYS_PAGES                  0x0062
#define _SC_AVPHYS_PAGES                0x0063
#define _SC_MONOTONIC_CLOCK             0x0064

int sysconf(int name);

// sockets

typedef unsigned int nfds_t;

struct pollfd {
    SOCKET fd;
    short  events;
    short  revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

int socketpair(int domain, int type, int protocol, int sv[2]);

// pread/pwrite/sendfile

ssize_t pread64(int fd, void *buf, size_t count, off_t offset);

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset);

ssize_t sendfile(int out_fd, int in_fd, off_t * offset, size_t count);

pid_t waitpid(pid_t pid, int *status, int options);

#define unsetenv(pname) SetEnvironmentVariable(pname, NULL)

#define setenv(__pname,__pvalue,___overwrite) \
({ \
  int result; \
 if (___overwrite == 0 && getenv (__pname)) result = 0; \
   else \
     result = SetEnvironmentVariable (__pname,__pvalue); \
 result; \
})

// termios

int tcsendbreak(int fd, int duration);

int tcdrain(int fd);

// signals

char *strsignal(int sig);

// symlink

int symlink(const char *path1, const char *path2);

// Dealing with error codes

int windowsErrorToErrno(DWORD winErr);
const char* getErrnoDescription(int err);

bool is_socket(int fd);

#endif

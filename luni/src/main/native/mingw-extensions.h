#ifndef MINGW_EXTENSIONS
#define MINGW_EXTENSIONS

// mingw-w64 now lacks support of these functions and structures
// If some of them are included into the new version of MinGW, they could be removed from this file

// including Winsock2.h unconditionally as it has to be included before windows.h
#include <Winsock2.h>

#include <windows.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iphlpapi.h>

#include "Portability.h"

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

// ioctl

int ioctl(int d, int request, ...);

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
#define _SC_GETPW_R_SIZE_MAX    0x0048

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

int winsock2errno(int winsock_error);

#endif

#ifndef MINGW_EXTENSIONS
#define MINGW_EXTENSIONS

// mingw-w64 now lacks support of these functions and structures
// If some of them are included into the new version of MinGW, they could be removed from this file

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
  uid_t pw_uid;	// User ID.
  gid_t pw_gid;	// Group ID.
  char	*pw_comment;	// Comment
  char *pw_gecos;		// Real name.
  char *pw_dir;			// Home directory.
  char *pw_shell;		// Shell program.
};

int getpwnam_r(const char *name, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result)
{
	// TODO Implement record from WinAPI
	result = NULL;
	return 0;
}

int getpwuid_r(uid_t uid, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result)
{
	// TODO Implement record from WinAPI
	result = NULL;
	return 0;	
}

// chown
int chown(const char *path, uid_t owner, gid_t group)
{
	errno = EBADF;
	return -1;
}
int lchown(const char *path, uid_t owner, gid_t group)
{
	errno = EBADF;
	return -1;
}

int fchown(int fd, uid_t owner, gid_t group)
{
	errno = EBADF;
	return -1;
}

// mincore
int mincore(void *addr, size_t length, unsigned char *vec)
{
	errno = EFAULT;
	return -1;
}

// mkdir
int mkdir(const char *pathname, mode_t mode)
{
	// Just ignoring the mode
	return mkdir(pathname);
}

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

static int mmap_winapi_error_to_posix(const DWORD winError)
{
    if (winError == 0)
        return 0;

    // TODO implement conversion. Now it doesn't convert anything yet
	return winError;
}

static DWORD mmap_page(const int prot)
{
    DWORD protect = 0;
   
    if (prot == PROT_NONE)
        return protect;
       
    if ((prot & PROT_EXEC) != 0)
    {
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    }
    else
    {
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_READWRITE : PAGE_READONLY;
    }
   
    return protect;
}

static DWORD mmap_file(const int prot)
{
    DWORD desiredAccess = 0;
   
    if (prot == PROT_NONE)
        return desiredAccess;
       
    if ((prot & PROT_READ) != 0)
        desiredAccess |= FILE_MAP_READ;
    if ((prot & PROT_WRITE) != 0)
        desiredAccess |= FILE_MAP_WRITE;
    if ((prot & PROT_EXEC) != 0)
        desiredAccess |= FILE_MAP_EXECUTE;
   
    return desiredAccess;
}

void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    HANDLE fm, h;
   
    void* map = MAP_FAILED;

    const DWORD dwFileOffsetLow = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)off : (DWORD)(off & 0xFFFFFFFFL);
    const DWORD dwFileOffsetHigh = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)0 : (DWORD)((off >> 32) & 0xFFFFFFFFL);
    
	const DWORD protect = mmap_page(prot);
    const DWORD desiredAccess = mmap_file(prot);

    const off_t maxSize = off + (off_t)len;

    const DWORD dwMaxSizeLow = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)maxSize : (DWORD)(maxSize & 0xFFFFFFFFL);
    const DWORD dwMaxSizeHigh = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)0 : (DWORD)((maxSize >> 32) & 0xFFFFFFFFL);

    errno = 0;
   
    if (len == 0 || (flags & MAP_FIXED) != 0 || prot == PROT_EXEC)	// Here we check for unsupported flags
    {
        errno = EINVAL;
        return MAP_FAILED;
    }
   
    h = ((flags & MAP_ANONYMOUS) == 0) ? (HANDLE)_get_osfhandle(fildes) : INVALID_HANDLE_VALUE;

    if ((flags & MAP_ANONYMOUS) == 0 && h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return MAP_FAILED;
    }

    fm = CreateFileMapping(h, NULL, protect, dwMaxSizeHigh, dwMaxSizeLow, NULL);

    if (fm == NULL)
    {
        errno = mmap_winapi_error_to_posix(GetLastError());
        return MAP_FAILED;
    }
 
    map = MapViewOfFile(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len);

    CloseHandle(fm);
 
    if (map == NULL)
    {
        errno = mmap_winapi_error_to_posix(GetLastError());
        return MAP_FAILED;
    }

    return map;
}

int munmap(void *addr, size_t len)
{
    if (UnmapViewOfFile(addr))
        return 0;
	else
	{
		errno =  mmap_winapi_error_to_posix(GetLastError());
		return -1;
	}
}

int mprotect(void *addr, size_t len, int prot)
{
    DWORD newProtect = mmap_page(prot);
    DWORD oldProtect = 0;
   
    if (VirtualProtect(addr, len, newProtect, &oldProtect))
        return 0;
	else
	{
		errno =  mmap_winapi_error_to_posix(GetLastError());
		return -1;
	}
}

int msync(void *addr, size_t len, int flags)
{
    if (FlushViewOfFile(addr, len))
        return 0;
	else
	{
		errno =  mmap_winapi_error_to_posix(GetLastError());
		return -1;
	}
}

int mlock(const void *addr, size_t len)
{
    if (VirtualLock((LPVOID)addr, len))
        return 0;
	else
	{
		errno =  mmap_winapi_error_to_posix(GetLastError());
		return -1;
	}
}

int munlock(const void *addr, size_t len)
{
    if (VirtualUnlock((LPVOID)addr, len)) 
		return 0;
	else
	{
		errno =  mmap_winapi_error_to_posix(GetLastError());
		return -1;
	}
}

// pipe
int pipe(int* pipefd)
{
	// TODO Implement this using winapi _pipe function 
	return -1;
}

// fcntl

struct flock64 {
        short  l_type;
        short  l_whence;
        loff_t l_start;
        loff_t l_len;
        pid_t  l_pid;
        /*__ARCH_FLOCK64_PAD*/
};

int fcntl(int fd, int cmd, ... /* arg */ )
{
	errno = EBADF;
	return -1;
}

// fdatasync

int fdatasync(int fd)
{
	errno = EBADF;
	return -1;
}

int fsync(int fd)
{
	errno = EBADF;
	return -1;
}

// getgid, uid, ppid

gid_t getgid(void)
{
	return -1;
}
gid_t getegid(void)
{
	return -1;
}
pid_t getppid(void)
{
	return -1;
}
uid_t getuid(void)
{
	return -1;
}
uid_t geteuid(void)
{
	return -1;
}


// chmod

int fchmod(int fd, mode_t mode)
{
	errno = EBADF;
	return -1;
}

// utsname
struct utsname
{
	char 	machine [20];
	char 	nodename [20];
	char 	release [20];
	char 	sysname [20];
	char 	version [20];
};

// ioctl

int ioctl(int d, int request, ...)
{
	errno = EBADF;
	return -1;
}

// kill

int kill(pid_t pid, int sig)
{
	errno = EPERM;
	return -1;
}

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

char *if_indextoname(unsigned int ifindex, char *ifname)
{
	// TODO The if_indextoname function can be replaced by 
	//      a call to the ConvertInterfaceIndexToLuid function 
	//      to convert an interface index to a NET_LUID followed 
	//      by a call to the ConvertInterfaceLuidToNameA to convert 
	//      the NET_LUID to the ANSI interface name.
	return NULL;
}

int inet_pton(int af, const char *src, void *dst)
{
	// TODO The InetPton function converts an IPv4 or 
	//      IPv6 Internet network address in its standard 
	//      text presentation form into its numeric binary form.
	return 0;
}

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

static int fstatfs (int fd, struct statfs *buf)
{
	errno = EINVAL;
	return -1;
}

static int __statfs (const char *path, struct statfs *buf)
  {
    HINSTANCE h;
    FARPROC f;
    int retval = 0;
    char tmp [MAX_PATH], resolved_path [MAX_PATH];
    realpath(path, resolved_path);
    if (!resolved_path)
      retval = - 1;
    else
      {
        /* check whether GetDiskFreeSpaceExA is supported */
        h = LoadLibraryA ("kernel32.dll");
        if (h)
          f = GetProcAddress (h, "GetDiskFreeSpaceExA");
        else
          f = NULL;
        if (f)
          {
            ULARGE_INTEGER bytes_free, bytes_total, bytes_free2;
            if (!GetDiskFreeSpaceExA (resolved_path, &bytes_free2, &bytes_total, &bytes_free))
              {
                errno = ENOENT;
                retval = - 1;
              }
            else
              {
                buf -> f_bsize = FAKED_BLOCK_SIZE;
                buf -> f_bfree = (bytes_free.QuadPart) / FAKED_BLOCK_SIZE;
                buf -> f_files = buf -> f_blocks = (bytes_total.QuadPart) / FAKED_BLOCK_SIZE;
                buf -> f_ffree = buf -> f_bavail = (bytes_free2.QuadPart) / FAKED_BLOCK_SIZE;
              }
          }
        else
          {
            DWORD sectors_per_cluster, bytes_per_sector;
            if (h) FreeLibrary (h);
            if (!GetDiskFreeSpaceA (resolved_path, (LPDWORD)&sectors_per_cluster,
                   (LPDWORD)&bytes_per_sector, (LPDWORD)&buf -> f_bavail, (LPDWORD)&buf -> f_blocks))
              {
                errno = ENOENT;
                retval = - 1;
              }
            else
              {
                buf -> f_bsize = sectors_per_cluster * bytes_per_sector;
                buf -> f_files = buf -> f_blocks;
                buf -> f_ffree = buf -> f_bavail;
                buf -> f_bfree = buf -> f_bavail;
              }
          }
        if (h) FreeLibrary (h);
      }

    /* get the FS volume information */
    if (strspn (":", resolved_path) > 0) resolved_path [3] = '\0'; /* we want only the root */    
    if (GetVolumeInformation (resolved_path, NULL, 0, (LPDWORD)&buf -> f_fsid, (LPDWORD)&buf -> f_namelen, NULL, tmp, MAX_PATH))
     {
     	if (strcasecmp ("NTFS", tmp) == 0)
     	 {
     	   buf -> f_type = NTFS_SUPER_MAGIC;
     	 }
     	else
     	 {
     	   buf -> f_type = MSDOS_SUPER_MAGIC;
     	 }
     }
    else
     {
       errno = ENOENT;
       retval = - 1;
     }
    return retval;
}

#define statfs(_path,_buf) __statfs(_path,_buf)

int vasprintf(char **strp, const char *fmt, va_list args)
{
    va_list args_copy;
    int status, needed, oerrno;

    va_copy(args_copy, args);
    needed = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    if (needed < 0) {
        *strp = NULL;
        return needed;
    }
    *strp = (char*)malloc(needed + 1);
    if (*strp == NULL)
        return -1;
    status = vsnprintf(*strp, needed + 1, fmt, args);
    if (status >= 0)
        return status;
    else {
        oerrno = errno;
        free(*strp);
        *strp = NULL;
        errno = oerrno;
        return status;
    }
}

int asprintf(char **strp, const char *fmt, ...)
{
    va_list args;
    int status;

    va_start(args, fmt);
    status = vasprintf(strp, fmt, args);
    va_end(args);
    return status;
}

// lstat

int lstat(const char *path, struct stat *buf)
{
	// We don't support symbolic links in Windows
	errno = EBADF;
	return -1;
}

// sysconf
#define _SC_GETPW_R_SIZE_MAX    0x0048

int sysconf(int name)
{
	switch (name)
	{
	case _SC_GETPW_R_SIZE_MAX: return 1024;		// TODO I have no idea what we should return here
	default:
		errno = EINVAL;
		return -1;
	}
}

// sockets

typedef unsigned int nfds_t;

struct pollfd {
    SOCKET fd;
    short  events;
    short  revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	errno = EFAULT;
	return -1;
}

#endif
#ifndef MINGW_EXTENSIONS
#define MINGW_EXTENSIONS

// mingw-w64 now lacks support of these functions and structures
// If some of them are included into the new version of MinGW, they could be removed from this file

#include <stdio.h>
#include "Portability.h"

// Sockets
typedef int socklen_t;

struct ucred {
	unsigned int 	pid;
	unsigned int 	uid;
	unsigned int 	gid;
};


// Password
struct passwd
{
  char *pw_name;		// Username.
  char *pw_passwd;		// Password.
  unsigned int pw_uid;	// User ID.
  unsigned int pw_gid;	// Group ID.
  char	*pw_comment;	// Comment
  char *pw_gecos;		// Real name.
  char *pw_dir;			// Home directory.
  char *pw_shell;		// Shell program.
};

// utsname
struct utsname
{
	char 	machine [20];
	char 	nodename [20];
	char 	release [20];
	char 	sysname [20];
	char 	version [20];
};

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

#endif
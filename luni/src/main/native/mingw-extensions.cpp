#include "mingw-extensions.h"

#define USERNAME_LENGTH		255

int windowsErrorToErrno(DWORD winErr)
{
	int error;
	switch (winErr) {
	
	// EACCES
	case ERROR_ACCESS_DENIED: 
	case ERROR_ACCOUNT_DISABLED: 
	case ERROR_ACCOUNT_RESTRICTION:
	case ERROR_CANNOT_MAKE:
	case ERROR_CURRENT_DIRECTORY:
	case ERROR_INVALID_ACCESS:
	case ERROR_INVALID_LOGON_HOURS: 
	case ERROR_INVALID_WORKSTATION:
	case ERROR_LOCK_VIOLATION:
	case ERROR_LOGON_FAILURE:
	case ERROR_NO_SUCH_PRIVILEGE:
	case ERROR_PASSWORD_EXPIRED:
	case ERROR_PRIVILEGE_NOT_HELD:
	case ERROR_SHARING_VIOLATION:
		error = EACCES;
		break;

	// EBUSY
	case ERROR_ALREADY_ASSIGNED:
	case ERROR_BUSY:
	case ERROR_BUSY_DRIVE:
	case ERROR_DEVICE_IN_USE:
	case ERROR_DRIVE_LOCKED:
	case ERROR_LOCKED:
	case ERROR_OPEN_FILES:
	case ERROR_PATH_BUSY:
	case ERROR_PIPE_BUSY:
		error = EBUSY;
		break;

	// EEXIST
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		error = EEXIST;
		break;

	// EFAULT
	case ERROR_INVALID_ADDRESS:
	case ERROR_INVALID_BLOCK:
	case ERROR_NOACCESS:
		error = EFAULT;
		break;
		
	// EINVAL
	case ERROR_BAD_LENGTH:
	case ERROR_BAD_USERNAME:
	case ERROR_DIRECTORY:
	case ERROR_ENVVAR_NOT_FOUND:
	case ERROR_INVALID_DATA:
	case ERROR_INVALID_FLAGS:
	case ERROR_INVALID_NAME:
	case ERROR_INVALID_OWNER:
	case ERROR_INVALID_PARAMETER:
	case ERROR_INVALID_PRIMARY_GROUP:
	case ERROR_INVALID_SIGNAL_NUMBER:
	case ERROR_MAPPED_ALIGNMENT:
	case ERROR_NONE_MAPPED:
		error = EINVAL;
		break;
	
	// ENOENT
	case ERROR_BAD_PATHNAME:
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_SWAPERROR:
		error = ENOENT;
		break;
	
	// ENODEV
	case ERROR_BAD_DEVICE:
	case ERROR_BAD_UNIT:
	case ERROR_DEV_NOT_EXIST:
	case ERROR_FILE_INVALID:
	case ERROR_INVALID_DRIVE:
	case ERROR_UNRECOGNIZED_VOLUME:
		error = ENODEV;
		break;
	
	// ENOEXEC
	case ERROR_BAD_EXE_FORMAT:
	case ERROR_BAD_FORMAT:
	case ERROR_EXE_MARKED_INVALID:
	case ERROR_INVALID_EXE_SIGNATURE:
		error = ENOEXEC;
		break;
	
	// ENXIO
	case ERROR_BAD_DRIVER_LEVEL:
	case ERROR_UNRECOGNIZED_MEDIA:
		error = ENXIO;
		break;
	
	// EIO
	case ERROR_BAD_COMMAND:
	case ERROR_CANTOPEN:
	case ERROR_CANTREAD:
	case ERROR_CANTWRITE:
	case ERROR_CRC:
	case ERROR_DISK_CHANGE:
	case ERROR_GEN_FAILURE:
	case ERROR_INVALID_TARGET_HANDLE:
	case ERROR_IO_DEVICE:
	case ERROR_NO_MORE_SEARCH_HANDLES:
	case ERROR_READ_FAULT:
	case ERROR_SEEK:
	case ERROR_WRITE_FAULT:
		error = EIO;
		break;
	
	// EPIPE
	case ERROR_BAD_PIPE:
	case ERROR_BROKEN_PIPE:
	case ERROR_MORE_DATA:
	case ERROR_NO_DATA:
	case ERROR_PIPE_CONNECTED:
	case ERROR_PIPE_LISTENING:
	case ERROR_PIPE_NOT_CONNECTED:
		error = EPIPE;
		break;

	// ERANGE
	case ERROR_ARITHMETIC_OVERFLOW:
		error = ERANGE;
		break;

	// ENAMETOOLONG
	case ERROR_BUFFER_OVERFLOW:
	case ERROR_FILENAME_EXCED_RANGE:
		error = ENAMETOOLONG; break;

	// ENOSYS
	case ERROR_CALL_NOT_IMPLEMENTED:
	case ERROR_INVALID_FUNCTION:
		error = ENOSYS;
		break;

	// ENOTEMPTY
	case ERROR_DIR_NOT_EMPTY:
		error = ENOTEMPTY;
		break;

	// ENOSPC
	case ERROR_DISK_FULL:
	case ERROR_HANDLE_DISK_FULL:
		error = ENOSPC;
		break;

	// ENOMEM
	case ERROR_INSUFFICIENT_BUFFER:
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
	case ERROR_STACK_OVERFLOW:
		error = ENOMEM;
		break;

	// EBADF
	case ERROR_INVALID_HANDLE:
		error = EBADF;
		break;
	
	// EPERM
	case ERROR_INVALID_PASSWORD:
		error = EPERM;
		break;

	// EINTR
	case ERROR_IO_INCOMPLETE:
	case ERROR_OPERATION_ABORTED:
		error = EINTR;
		break;

	// E2BIG
	case ERROR_META_EXPANSION_TOO_LONG:
		error = E2BIG;
		break;
	
	// ESPIPE
	case ERROR_NEGATIVE_SEEK:
	case ERROR_SEEK_ON_DEVICE:
		error = ESPIPE;
		break;

	// EAGAIN
	case ERROR_NOT_READY:
	case ERROR_NO_PROC_SLOTS:
		error = EAGAIN;
		break;

	// EXDEV
	case ERROR_NOT_SAME_DEVICE:
		error = EXDEV;
		break;

	// ENFILE
	case ERROR_SHARING_BUFFER_EXCEEDED:
		error = ENFILE;
		break;
	
	// EMFILE
	case ERROR_TOO_MANY_MODULES:
	case ERROR_TOO_MANY_OPEN_FILES:
		error = EMFILE;
		break;
	
	// ECHILD
	case ERROR_WAIT_NO_CHILDREN:
		error = ECHILD;
		break;
	
	// EROFS
	case ERROR_WRITE_PROTECT:
		error = EROFS;
		break;

	default:
		error = ENOSYS;
	}
	return error;
}

int getpwnam_r(const char *name, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result)
{
	// TODO Implement record from WinAPI
	result = NULL;
	return 0;
}

int getpwuid_r(uid_t /*uid*/, struct passwd *pwd,
            char *buf, size_t buflen, struct passwd **result)
{
	// The current implementation of this function gets the name of the CURRENT user.
	// We just ignore the first argument
	
	// If you want to find a name of OTHER user, you should use LookupAccountSid 
	// (and send SID as the first argument as soon as it's the closest replacement for Win32's "uid")
	
	DWORD len = buflen;
	if (GetUserName(buf, &len) == 0)
	{
		errno = windowsErrorToErrno(GetLastError());
		return -1;
	}
	else
	{
		pwd->pw_name = buf;
		pwd->pw_gecos = "";
		pwd->pw_dir = "";
		
		// On success, getpwnam_r() and getpwuid_r() return zero, and set *result to pwd
		*result = pwd;
		return 0;
	}
	
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

int mmap_winapi_error_to_posix(const DWORD winError)
{
    if (winError == 0)
        return 0;

    // TODO implement conversion. Now it doesn't convert anything yet
	return winError;
}

DWORD mmap_page(const int prot)
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

DWORD mmap_file(const int prot)
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
int seteuid(uid_t euid)
{
	errno = EPERM;
	return -1;
}
int setegid(gid_t egid)
{
	errno = EPERM;
	return -1;
}
int setgid(gid_t gid)
{
	errno = EPERM;
	return -1;
}
pid_t setsid(void)
{
	errno = EPERM;
	return -1;
}
int setuid(uid_t euid)
{
	errno = EPERM;
	return -1;
}

// chmod

int fchmod(int fd, mode_t mode)
{
	errno = EBADF;
	return -1;
}

// uname

int uname(struct utsname *buf)
{
	errno = EFAULT;
	return -1;
}

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

int fstatfs (int fd, struct statfs *buf)
{
	errno = EINVAL;
	return -1;
}

int __statfs (const char *path, struct statfs *buf)
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

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	errno = EFAULT;
	return -1;
}

int socketpair(int domain, int type, int protocol, int sv[2])
{
	errno = EFAULT;
	return -1;
}

// pread/pwrite/sendfile

ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t retval;
    off_t saved_pos = lseek (fd, 0, SEEK_CUR);

    lseek (fd, offset, SEEK_SET);
    retval = read(fd, buf, count);
    lseek (fd, saved_pos, SEEK_SET);

    return retval;    
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
{
    ssize_t retval;
    off_t saved_pos = lseek (fd, 0, SEEK_CUR);

    lseek (fd, offset, SEEK_SET);
    retval = write(fd, buf, count);
    lseek (fd, saved_pos, SEEK_SET);

    return retval;
}

ssize_t sendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
	errno = EINVAL;
	return -1;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	// TODO Use GetExitCodeProcess here
	errno = EINVAL;
	return -1;
}

// termios

int tcsendbreak(int fd, int duration)
{
	// NB If the terminal is not using asynchronous serial data transmission, 
	//    tcsendbreak() returns without taking any action.
	return 0;
}

int tcdrain(int fd)
{
	return 0;
}

// signals

char *strsignal(int sig)
{
	return "No signals in Windows!";
}

// symlink

int symlink(const char *path1, const char *path2)
{
	errno = EACCES;
	return -1;
}

int winsock2errno(int winsock_error) {
    /* TODO: implement this */
    return winsock_error;
}
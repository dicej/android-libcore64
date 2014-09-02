/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UNICODE_DEFINES_H
#define UNICODE_DEFINES_H

// This is about necessity to use wide-char functions on Windows to correctly support Unicode
#if defined(__MINGW32__) || defined(__MINGW64__)
    #define ScopedPathChars ScopedWideChars
    #define ExecPathStrings ExecWideStrings
    #define u_open _wopen
    #define u_lstat _wlstat
    #define u_stat _wstat
    #define u_access _waccess
    #define u_chmod _wchmod
    #define u_chown _wchown
    #define u_execve _wexecve
    #define u_execv _wexecv
    #define u_getenv _wgetenv
    #define u_lchown _wlchown
    #define u_mkdir _wmkdir
    #define u_remove _wremove
    #define u_rename _wrename
    #define u_setenv _wsetenv
    #define u_statfs _wstatfs
    #define u_symlink _wsymlink
    #define u_unsetenv _wunsetenv
    #define u_link _wlink
    #define u_mkfifo _wmkfifo
    #define u_statvfs _wstatvfs
    #define u_utime _wutime
    #define u_opendir _wopendir
    #define u_closedir _wclosedir
    #define u_readdir _wreaddir

    #define u_char_t wchar_t
    #define u_string_t std::wstring
    #define u_DIR _WDIR
    #define u_dirent _wdirent
#else
    #define ScopedPathChars ScopedUtfChars
    #define ExecPathStrings ExecStrings
    #define u_open open
    #define u_lstat lstat
    #define u_stat stat
    #define _fstat fstat
    #define u_access access
    #define u_chmod chmod
    #define u_chown chown
    #define u_execv execv
    #define u_execve execve
    #define u_getenv getenv
    #define u_lchown lchown
    #define u_mkdir mkdir
    #define u_remove remove
    #define u_rename rename
    #define u_setenv setenv
    #define u_statfs statfs
    #define u_symlink symlink
    #define u_unsetenv unsetenv
    #define u_link link
    #define u_mkfifo mkfifo
    #define u_statvfs statvfs
    #define u_utime utime
    #define u_opendir opendir
    #define u_closedir closedir
    #define u_readdir readdir

    #define u_char_t char
    #define u_string_t std::string
    #define u_DIR DIR
    #define u_dirent dirent
    #define _stat stat
    #define _utimbuf utimbuf
#endif

#endif // UNICODE_DEFINES_H

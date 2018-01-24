/* bwpy-environ: Mount namespace wrapper
 * Copyright (C) 2017 Colin MacLean, University of Illinois <cmaclean@illinois.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/version.h>

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

int maint = 0;

#ifndef strlcpy
// Unlike strncpy, strlcpy always null terminates
// A non-standard function, strlcpy is available
// on BSD, but not Linux
size_t strlcpy(char *dst, const char *src, size_t dstsize) {
    size_t len = strnlen(src,dstsize);
    if (len > dstsize-1)
        len = dstsize-1;
    memcpy(dst,src,len);
    dst[len] = 0;
    return len;
}
#endif

int mkdir_p(const char* path, mode_t mode) {
    const size_t len = strnlen(path,PATH_MAX);
    char pathbuf[PATH_MAX];
    char *p;

    errno = 0;

    if (len == PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (len == 0) {
        errno = EINVAL;
        return -1;
    }

    strlcpy(pathbuf,path,PATH_MAX);

    if(pathbuf[len-1] == '/')
        pathbuf[len-1] = 0;

    for (p = pathbuf+1; *p; ++p) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(pathbuf,mode) < 0) {
                if (errno != EEXIST)
                    return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(pathbuf,mode) < 0) {
        if (errno != EEXIST)
            return -1;
    }

    return 0;
}

const char* filename_to_version(char *filename) {
    size_t len = strnlen(filename,PATH_MAX);
    if (len < strlen(IMAGE_PREFIX "-" IMAGE_SUFFIX))
        return "default";
    filename[len-strlen(IMAGE_SUFFIX)] = 0;
    filename += strlen(IMAGE_PREFIX) + 1;
    return filename;
}

int filter_versions(const struct dirent *ent) {
    int ret = fnmatch(IMAGE_PREFIX "*" IMAGE_SUFFIX,ent->d_name,0);
    return !ret;
}

int list_versions(void) {
    struct dirent **namelist;
    char path[PATH_MAX];
    char rl[PATH_MAX];
    char finalpath[PATH_MAX];
    int n, found = 0;

    n = scandir(IMAGE_DIR, &namelist, filter_versions, versionsort);
    if (n < 0) {
        fprintf(stderr,"Error: No images found.\n");
        return -1;
    }
    else {
        printf("Versions:\n");
        while (n--) {
            snprintf(path,PATH_MAX,"%s/%s",IMAGE_DIR,namelist[n]->d_name);
            struct stat st;
            if (lstat(path,&st) < 0)
                continue;
            if (S_ISLNK(st.st_mode)) {
                if (stat(path,&st) < 0)
                    continue;
                memset(rl,0,PATH_MAX);
                if (readlink(path, rl, PATH_MAX) < 0)
                    continue;
                if (realpath(path,finalpath) == NULL)
                    continue;
                if (stat(finalpath,&st) < 0)
                    continue;
                if (!(st.st_mode & 04))
                    continue;
                ++found;
                printf(COLOR_CYAN "%s" COLOR_NC " -> %s\n",filename_to_version(namelist[n]->d_name),filename_to_version(basename(rl)));
            } else {
                if (!(st.st_mode & 04))
                    continue;
                ++found;
                printf("%s\n", filename_to_version(namelist[n]->d_name));
            }
            free(namelist[n]);
        }
        free(namelist);
    }
    if (found == 0)
    printf("NONE!\n");
    return 0;
}

//Get the versioned image name
//Ensure that the image name is actually in the good directory
//This is to prevent %s.img being ../../exploit
char *versioned_image(const char* version_string, int maint) {
    char good_realdir[PATH_MAX];
    char suspect_path[PATH_MAX];
    static char suspect_realpath[PATH_MAX];
    char suspect_realdir[PATH_MAX];
    char* clean_path = NULL;

    if (realpath(IMAGE_DIR, good_realdir) == NULL) {
        fprintf(stderr,"Error: failed to get real path of image directory: %s %s\n",IMAGE_DIR,strerror(errno));
        return NULL;
    }

    snprintf(suspect_path,PATH_MAX,IMAGE_VERSIONED,version_string);

    if (strstr(version_string,"..")) {
        fprintf(stderr,"Error: \"..\" not permitted in version string!\n");
        return NULL;
    }

    if (strchr(version_string,'/')) {
        fprintf(stderr,"Error: \"/\" not permitted in version string!\n");
        return NULL;
    }

    if (realpath(suspect_path, suspect_realpath) == NULL) {
        fprintf(stderr,"Error: failed to get real path of requested image %s: %s\n",suspect_path,strerror(errno));
        return NULL;
    }

    strlcpy(suspect_realdir,suspect_realpath,PATH_MAX);

    if (strncmp(good_realdir,dirname(suspect_realdir),PATH_MAX) == 0)
        clean_path = suspect_realpath;
    else
        fprintf(stderr,"Error: Something fishy is going on here. %s != %s\n",dirname(suspect_realpath),good_realdir);

    if (!maint && strstr(clean_path,"maint")) {
        fprintf(stderr,"Error: Maintenance image versions must be mounted in maintenance mode!\n");
        return NULL;
    }

    return clean_path;
}

int setup_module(const char* name, const char* ko_file, const char* check_symbol) {
    FILE *f;
    char line[4096];
    int found = 0;
    ssize_t read_size;
    void *ko_image;
    char path[PATH_MAX];
    struct stat st;

#ifndef ALWAYS_LOAD
    snprintf(path,PATH_MAX,"/sys/module/%s",name);

    if (stat(path,&st) == 0 && S_ISDIR(st.st_mode)) {
        return 0;
    }

    if ((f = fopen("/proc/modules","r")) == NULL) {
        fprintf(stderr,"Error: Cannot open /proc/modules: %s!\n",strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *tok;
        tok = strtok(line, " \t");

        if (strcmp(name, tok) == 0) {
            found = 1;
            break;
        }
    }

    if (fclose(f) < 0) {
        fprintf(stderr,"Error: Error while closing /proc/modules: %s!\n",strerror(errno));
        return -1;
    }

#ifdef SYMBOL_CHECKS
    if (check_symbol != NULL) {
        if ((f = fopen("/proc/kallsyms","r")) == NULL) {
            fprintf(stderr,"Error: Cannot open /proc/kallsyms: %s!\n",strerror(errno));
            return -1;
        }

        while (fgets(line, sizeof(line), f)) {
            char *tok;
            tok = strtok(line, " \t");
            tok = strtok(NULL, " \t");
            tok = strtok(NULL, " \t\n");

            if (strcmp(check_symbol, tok) == 0) {
                found = 1;
                break;
            }
        }

        if (fclose(f) < 0) {
            fprintf(stderr,"Error: Error while closing /proc/kallsyms: %s!\n",strerror(errno));
            return -1;
        }
    }
#endif

    if (!found && sizeof(MODULE_BASE_DIR) > sizeof("")) {
#endif
        int fd;

        struct utsname utsname;

        uname(&utsname);

        snprintf(path, PATH_MAX, MODULE_BASE_DIR "/%s/%s", utsname.release, ko_file);

        if ((fd = open(path, O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                // Assume non-existing module files are loaded
                return 0;
            }
            fprintf(stderr,"Error: Cannot open %s: %s!\n",path,strerror(errno));
            return -1;
        }

        if (fstat(fd, &st) < 0) {
            fprintf(stderr,"Error: Cannot stat %s: %s!\n",path,strerror(errno));
            if (close(fd) < 0)
                fprintf(stderr,"Error: Error closing %s: %s!\n",path,strerror(errno));
            return -1;
        }

        if (!S_ISREG (st.st_mode)) {
            fprintf(stderr,"Error: %s is not a regular file!\n",path);
            return -1;
        }

        if ((ko_image = mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
            fprintf(stderr,"Error: Failed to mmap kenel module %s: %s!\n",path,strerror(errno));
            if (close(fd) < 0)
                fprintf(stderr,"Error: Error closing %s: %s!\n",path,strerror(errno));
            return -1;
        }

        if (close(fd) < 0) {
            fprintf(stderr,"Error: Error closing %s: %s!\n",path,strerror(errno));
            if (munmap(ko_image,st.st_size) == -1) {
                fprintf(stderr,"Error: munmap failed!\n");
            }
            return -1;
        }

        if (init_module(ko_image, st.st_size, "") != 0) {
            //errno is EEXIST if module is already loaded
            //errno is ENOEXEC if module is built-in
            if (errno == EEXIST || errno == ENOEXEC) {
                if (munmap(ko_image,st.st_size) == -1) {
                    fprintf(stderr,"Error: munmap failed!\n");
                    return -1;
                }
                return 0;
            }
            fprintf(stderr,"Error: Error inserting %s: %s!\n",path,strerror(errno));
            if (munmap(ko_image,st.st_size) == -1) {
                fprintf(stderr,"Error: munmap failed!\n");
            }
            return -1;
        }
        if (munmap(ko_image,st.st_size) == -1) {
            fprintf(stderr,"Error: munmap failed!\n");
            return -1;
        }
        return 1;
#ifndef ALWAYS_LOAD
    } else if (!found && sizeof(MODULE_BASE_DIR) == sizeof("")) {
        return 2;
    } else {
        return 0;
    }
#endif
}

const char *loop_dev_num(const unsigned char device_num) {
    static char buffer[32];
    snprintf(buffer,32,"/dev/loop%hhu",device_num);
    return buffer;
}

//loop_info and loop_info64 only have a 64 character backing file path
//Use value in sysfs to get around this limitation
const char *backing_file(const unsigned char device_num) {
    int fd;
    ssize_t len;
    char sys_backing_file[64];
    static char res[PATH_MAX];
    memset(res,0,PATH_MAX);

    snprintf(sys_backing_file,64,"/sys/block/loop%hhu/loop/backing_file",device_num);

    if ((fd = open(sys_backing_file, O_RDONLY)) < 0)
        return NULL;

    if ((len = read(fd,res,PATH_MAX)) <= 0) {
        if (len < 0) {
            fprintf(stderr,"Error: Error reading %s: %s!\n",sys_backing_file,strerror(errno));
            if (close(fd) < 0)
                fprintf(stderr,"Error: Error closing %s: %s!\n",sys_backing_file,strerror(errno));
            return NULL;
        }
        if (close(fd) < 0)
            fprintf(stderr,"Error: Error closing %s: %s!\n",sys_backing_file,strerror(errno));
        return NULL;
    }

    if (close(fd) < 0)
        fprintf(stderr,"Error: Error closing %s: %s!\n",sys_backing_file,strerror(errno));

    if (res[len-1] == '\n')
        res[len-1] = 0;

    return res;
}

//Check if there is already a loop device set
//up and running
int find_existing_loop(const char *image_path)
{
    int loop_dev;
    const char *bf;

    for (loop_dev = 0; loop_dev < MAX_LOOP_DEVS; ++loop_dev) {
        bf = backing_file(loop_dev);
        if (bf != NULL && strncmp(bf,image_path,PATH_MAX) == 0)
            return loop_dev;
    }

    return -1;
}

int setup_loop_dev(const char *image_path) {
    const char *bf;
    char real_image_path[PATH_MAX];
    int fd = -1;
    int loopfd = -1;
    int loop_dev;
    int err = 0;
    const char *errmsg = "";
    const char *dev_loop_path;

    if (realpath(image_path,real_image_path) == NULL) {
        if (errno == ENAMETOOLONG)
            fprintf(stderr,"Error: failed to get real path of image: %s\n",strerror(errno));
        else
            fprintf(stderr,"Error: failed to get real path of %s: %s\n",image_path,strerror(errno));
        return -1;
    }

retry:

    if ((loop_dev = find_existing_loop(real_image_path)) >= 0) {
        if (fd != -1 && close(fd) < 0)
            fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
        return loop_dev;
    }

    if (fd == -1) {
        if (maint) {
            if ((fd = open(real_image_path, O_RDWR)) < 0)
                return -1;
        } else {
            if ((fd = open(real_image_path, O_RDONLY)) < 0)
                return -1;
        }
        if (flock(fd,LOCK_EX) < 0) {
            fprintf(stderr,"Error: Error locking %s: %s!\n",real_image_path,strerror(errno));
            goto error_skipprint;
        }
        if ((loop_dev = find_existing_loop(real_image_path)) >= 0) {
            // Handle race condition locking fd
            if (flock(fd, LOCK_UN) < 0)
                fprintf(stderr,"Error unlocking %s: %s!\n",real_image_path,strerror(errno));

            if (close(fd) < 0) {
                fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
                goto error_noclose;
            }
            return loop_dev;
        }
    }

    //Find and open an unused loop device
    for (loop_dev = 0; loop_dev < MAX_LOOP_DEVS; ++loop_dev) {
        bf = backing_file(loop_dev);
        if (bf == NULL) {
            dev_loop_path = loop_dev_num(loop_dev);
            if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
                if (errno == ENOENT) {
                    int mode = 0660 | S_IFBLK;

                    if (mknod(dev_loop_path,mode,makedev(7,loop_dev)) < 0) {
                        // Let the flock code handle a race condition
                        // with another process attempting to create
                        // the same loop device by simply continuing
                        // here on an EEXIST.
                        if (errno != EEXIST) {
                            errmsg = "Error creating loop device: ";
                            err = errno;
                            goto error;
                        }
                    }

                    if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
                        errmsg = "Error opening loop device (2nd attempt): ";
                        err = errno;
                        goto error;
                    }

                    if (flock(loopfd,LOCK_EX | LOCK_NB) < 0) {
                        if (errno == EWOULDBLOCK) {
                            //Another wrapper is in the process of setting up
                            //this loop device. Do a blocking flock until it
                            //is done, then retry to see if this loop device
                            //has been set up with the same image we want.
                            if (flock(loopfd,LOCK_EX) < 0) {
                                errmsg = "Error locking loop device (at #1): ";
                                err = errno;
                                goto error;
                            }
                            if (flock(loopfd, LOCK_UN) < 0) {
                                errmsg = "Error unlocking loop device (at #1): ";
                                err = errno;
                                goto error;
                            }
                            if (close(loopfd) < 0) {
                                 fprintf(stderr,"Error: Error closing %s: %s!\n",dev_loop_path,strerror(errno));
                                 if (close(fd) < 0)
                                    fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
                                 goto error_noclose;
                            }
                            loopfd = -1;
                            goto retry;
                        } else {
                            errmsg = "Error locking loop device (at #2): ";
                            err = errno;
                            goto error;
                        }
                    }
                } else {
                    errmsg = "Error opening loop device: ";
                    err = errno;
                    goto error;
                }
            }
            if (flock(loopfd,LOCK_EX | LOCK_NB) < 0) {
                if (errno == EWOULDBLOCK) {
                    //Another wrapper is in the process of setting up
                    //this loop device. Do a blocking flock until it
                    //is done, then retry to see if this loop device
                    //has been set up with the same image we want.
                    if (flock(loopfd,LOCK_EX) < 0) {
                        errmsg = "Error locking loop device (at #3): ";
                        err = errno;
                        goto error;
                    }
                    flock(loopfd, LOCK_UN);
                    if (flock(loopfd, LOCK_UN) < 0) {
                        errmsg = "Error unlocking loop device (at #3): ";
                        err = errno;
                        goto error;
                    }
                    if (close(loopfd) < 0) {
                        fprintf(stderr,"Error: Error closing %s: %s!\n",dev_loop_path,strerror(errno));
                        if (close(fd) < 0)
                            fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
                        goto error_noclose;
                    }
                    loopfd = -1;
                    goto retry;
                } else {
                    errmsg = "Error locking loop device (at #4): ";
                    err = errno;
                    goto error;
                }
            }
            break;
        }
    }

    if (loop_dev == MAX_LOOP_DEVS) {
        fprintf(stderr,"Error: Out of loop devices!\n");
        goto error_skipprint;
    }

    if (loopfd < 0) {
        fprintf(stderr,"Error: Failed to find a loop device!\n");
        goto error_skipprint;
    }

    if (ioctl(loopfd, LOOP_SET_FD, fd) < 0) {
        errmsg = "Error setting loop fd: ";
        err = errno;
        goto error;
    }

    if (flock(loopfd, LOCK_UN) < 0) {
        errmsg = "Error unlocking loop device: ";
        err = errno;
        goto error;
    }

    if (flock(fd, LOCK_UN) < 0) {
        fprintf(stderr,"Error unlocking %s: %s!\n",real_image_path,strerror(errno));
        goto error_skipprint;
    }

    if (close(fd) < 0) {
        fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
        goto error_nofd;
    }

    if (close(loopfd) < 0) {
        fprintf(stderr,"Error: Error closing %s: %s!\n",dev_loop_path,strerror(errno));
        goto error_noclose;
    }
    return loop_dev;

error:
    fprintf(stderr,"Error: %s%s\n",errmsg,strerror(err));
error_skipprint:
    if (close(fd) < 0)
        fprintf(stderr,"Error: Error closing %s: %s!\n",real_image_path,strerror(errno));
error_nofd:
    if (loopfd != -1 && close(loopfd) < 0)
        fprintf(stderr,"Error: Error closing %s: %s!\n",dev_loop_path,strerror(errno));
error_noclose:
    return -1;
}

void drop_priv_perm(uid_t uid, gid_t gid) {
    //Permanently drop privileges
    //
    //setresgid/setresuid makes it more obvious that we are
    //dropping real, effective, and saved uid/gid privileges
    //vs setuid(getuid()) and setgid(getuid())
    if (setresgid(gid,gid,gid) != 0) {
        fprintf(stderr,"Error: Error dropping group privileges: %s!\n",strerror(errno));
        abort();
    }
    if (setresuid(uid,uid,uid) != 0) {
        fprintf(stderr,"Error: Error dropping privileges: %s!\n",strerror(errno));
        abort();
    }

    //Check that privileges were dropped
    uid_t check_ru, check_eu, check_su;
    gid_t check_rg, check_eg, check_sg;
    if (getresuid (&check_ru, &check_eu, &check_su) != 0
            || check_ru != uid || check_eu != uid || check_su != uid) {
        fprintf(stderr,"Error: Privileges were not dropped!\n");
        abort();
    }

    if (getresgid (&check_rg, &check_eg, &check_sg) != 0
            || check_rg != gid || check_eg != gid || check_sg != gid) {
        fprintf(stderr,"Error: Group privileges were not dropped!\n");
        abort();
    }
}

int do_mount(int maint, const int loopfd, const char* loop_dev_file, const char* image_name)
{
    unsigned long mountflags = MS_NOSUID | MS_NODEV | MS_NOATIME;

    // squashfs is always read-only, so only attempt to mount in normal mode
    if (!maint) {
        mountflags |= MS_RDONLY;

#ifdef MODULE_LOADING
        if (setup_module(SQUASHFS_NAME,SQUASHFS_KO,SQUASHFS_CHECK_SYMBOL) < 0) {
            fprintf(stderr,"Error: No squashfs support!\n");
            return -1;
        }
#endif

        // Ignore errors when attempting to mount squashfs. We fall back
        // to trying ext3, and fatal errors will be handled there.
        if (mount(loop_dev_file, MOUNTPOINT, "squashfs", mountflags, "") == 0) {
            return 0;
        }
    }

#ifdef MODULE_LOADING
    if (setup_module(MBCACHE_NAME,MBCACHE_KO,MBCACHE_CHECK_SYMBOL) < 0) {
        fprintf(stderr,"Error: No mbcache support!\n");
        return -1;
    }

    if (setup_module(JBD_NAME,JBD_KO,JBD_CHECK_SYMBOL) < 0) {
        fprintf(stderr,"Error: No jbd support!\n");
        return -1;
    }

    if (setup_module(EXT3_NAME,EXT3_KO,EXT3_CHECK_SYMBOL) < 0) {
        fprintf(stderr,"Error: No ext3 support!\n");
        return -1;
    }
#endif

    if (mount(loop_dev_file, MOUNTPOINT, "ext3", mountflags, "") < 0){
        // If we attempt to mount the same device at the same mount point,
        // there will be an EBUSY. The mount(2) man page lists that EBUSY
        // may also be produced by threads having the mount point as their
        // active working directory, open files, etc. However, these other
        // causes don't seem to be relavent to modern Linux. By ignoring
        // EBUSY, the wrapper can be called multiple times without producing
        // an error, which might happen if, for instance, this wrapper is
        // used in a shebang and things get nested or called recursively.
        // We will assume that EBUSY only means that the mount has already
        // been done and is not a fatal error.
        if (errno != EBUSY) {
            fprintf(stderr,"Error: Cannot mount ext3 image on %s (%s): %s!\n",loop_dev_file,image_name,strerror(errno));
            return -1;
        }
    }

    return 0;
}

int setup_loop_and_mount(const char* image_name) {
    int loopdev;
    int loopfd;
    int ret=0;
    const char* loop_dev_file;
    int lockfd;

    // Trying to mount at the same time from multiple
    // processes causes an EINVALID. Make a lock file to prevent
    // this problem.
    if ((lockfd = open(LOCKFILE, O_RDONLY | O_CREAT, 0644)) < 0) {
        fprintf(stderr,"Error: Cannot create lock file (" LOCKFILE ")!\n");
        return -1;
    }

    if (flock(lockfd,LOCK_EX) < 0) {
        fprintf(stderr,"Error: Error locking " LOCKFILE "!\n");
        ret=-1;
        goto error_lock;
    }

#ifdef CREATE_MOUNTPOINT
    if (mkdir_p(MOUNTPOINT,S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        fprintf(stderr,"Error: Cannot create mount point %s: %s!",MOUNTPOINT,strerror(errno));
        ret=-1;
        goto error_lock;
    }
#endif

    //Unshare the mount namespace
    if (unshare(CLONE_NEWNS) != 0) {
        fprintf(stderr,"Error: Cannot create mount namespace: %s!\n",strerror(errno));
        ret=-1;
        goto error_lock;
    }

    //Don't share the mounting with other processes
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        fprintf(stderr,"Error: Cannot give / subtree private mount propagation: %s!\n",strerror(errno));
        ret=-1;
        goto error_lock;
    }

    if ((loopdev = setup_loop_dev(image_name)) < 0) {
        fprintf(stderr,"Error: Error setting up loop device!\n");
        ret=-1;
        goto error_lock;
    }

    loop_dev_file = loop_dev_num(loopdev);
    if ((loopfd = open(loop_dev_file, O_RDWR)) < 0) {
        fprintf(stderr,"Error: Error opening loop device: %s!\n",strerror(errno));
        ret=-1;
        goto error_lock;
    }

    //Set loop device to detach automatically once last mount is unmounted
    struct loop_info64 loopinfo64;
    memset(&loopinfo64, 0, sizeof(loopinfo64));
    loopinfo64.lo_flags = LO_FLAGS_AUTOCLEAR;

    if (ioctl(loopfd, LOOP_SET_STATUS64, &loopinfo64) < 0) {
        fprintf(stderr,"Error: Error setting LO_FLAGS_AUTOCLEAR: %s!\n",strerror(errno));
        ret=-1;
        goto error_disloop;
    }


    if (do_mount(maint, loopfd, loop_dev_file, image_name) < 0) {
        ret=-1;
        goto error_disloop;
    }



error_disloop:
    if (ret != 0) {
        // If an error has been encountered, LO_FLAGS_AUTOCLEAR will not work.
        // Dissassociate the image manually.
        if (ioctl(loopfd,LOOP_CLR_FD) < 0) {
            // If the automatic disassociation did something already,
            // the loop device will be unbound and return ENXIO
            if (errno != ENXIO) {
                fprintf(stderr,"Error: Error disassociating image from loop device: %s!\n",strerror(errno));
            }
        }
    }


    if (close(loopfd) < 0) {
        fprintf(stderr,"Error: Error closing %s: %s!\n",loop_dev_file,strerror(errno));
        ret=-1;
    }

error_lock:
    if (flock(lockfd,LOCK_UN) < 0) {
        fprintf(stderr,"Error: Error unlocking " LOCKFILE "!\n");
        return -1;
    }

    if (close(lockfd) < 0) {
        fprintf(stderr,"Error closing " LOCKFILE "!\n");
        return -1;
    }
    return ret;
}

int get_exe_for_pid(pid_t pid, char *buf, size_t bufsize) {
    char path[32];
    snprintf(path,32,"/proc/%d/exe",pid);
    return readlink(path, buf, bufsize);
}

int main(int argc, char *argv[])
{
    char wrappername[NAME_MAX];
    char *program;
    char **program_args;
    char *default_program_args[3];
    char version[MAX_VERSION_LENGTH];
    int has_version = 0;
    int sym = 0;
    char user_shell[PATH_MAX];
    char *image_name = IMAGE_DEFAULT;
    const char *version_env;
    int recursing = 0;

    //Get current real and effective privileges
    gid_t gid = getgid();
    uid_t uid = getuid();
    gid_t egid = getegid();
    uid_t euid = geteuid();
    gid_t sgid = egid;
    uid_t suid = euid;

    if (egid != 0) {
        fprintf(stderr,"Error: Not a root suid binary! (When launched via aprun, `aprun -b` must be used)\n");
        return -1;
    }

#ifdef MODULE_LOADING
    if (setup_module(LOOP_NAME,LOOP_KO,LOOP_CHECK_SYMBOL) < 0) {
        fprintf(stderr,"Error: No loop device support!\n");
        return -1;
    }
#endif

    // When bwpy-environ is a shebang without a second argument,
    // test.sh will be called as bwpy-environ test.sh. This will
    // be recursive unless we break this loop.
    {
        char pprocess[PATH_MAX];
        pid_t ppid = getppid();
        if (get_exe_for_pid(ppid, pprocess, PATH_MAX) == -1) {
            fprintf(stderr,"Error: Cannot determine executable for parent process (%d): %s!\n",ppid,strerror(errno));
            return -1;
        }
        if (strncmp(pprocess,argv[0],PATH_MAX) == 0) {
            recursing = 1;
        }
    }

    //Temporarily drop permissions
    if (setegid(gid)) {
        fprintf(stderr,"Error: Cannot drop group privileges: %s!\n",strerror(errno));
        return -1;
    }
    if (seteuid(uid)) {
        fprintf(stderr,"Error: Cannot drop user privileges: %s!\n",strerror(errno));
        return -1;
    }

    strlcpy(wrappername,basename(argv[0]),NAME_MAX);

    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "maintenance",   no_argument,       0,  'm' },
            { "image-version", required_argument, 0,  'v' },
            { "list",          no_argument,       0,  'l' },
            { "symlink",       no_argument,       0,  's' },
            { "version",       no_argument,       0,  'V' },
            { "help",          no_argument,       0,  'h' },
            { 0,               0,                 0,  0   }
        };

        c = getopt_long(argc, argv, "mlv:hVs", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'm':
                maint = 1;
                break;

            case 'v':
                has_version = 1;
                strlcpy(version,optarg,MAX_VERSION_LENGTH);
                break;

            case 'l':
                drop_priv_perm(uid,gid);
                list_versions();
                return 0;

            case 's':
                sym = 1;
                break;

            case 'h':
                printf("Usage: %s [-mhv] [--image-version version] [--maintenance] [--] [program [args...]]\n",wrappername);
                printf("\nThis wrapper mounts a disk image at " MOUNTPOINT " in a private mount namespace.\n"
                       "\nThe optional program [args...] specifies a program to run within the mounted environment.\n"
                       "Use '--' prior to program to allow passing arguments to the program.\n"
                       "If no program is specified, $SHELL will be executed. If $SHELL is undefined, the wrapper\n"
                       "will run /bin/bash.\n\n"
                       "The -s, --symlink option is useful for accessing image files via ssh or across different versions.\n\n"
                    "Options:\n"
                       "     -v, --image-version VERSION    Override the image version to mount.\n"
                       "     -m, --maintenance              (Internal Use Only!) Mount the image read-write.  Must be a member of the " MAINT_GROUP " group.\n"
                       "     -s, --symlink                  Creates a symlink at " SYMLINK_BASE "/USER/image-name to /proc/PID/root/" MOUNTPOINT ".\n"
                       "     -V, --version                  Print the version of this wrapper.\n"
                       "     -h, --help                     Show this help\n"
                    "\nEnvironment Variables:\n"
                       "     SHELL:           The default program if none is specifed.\n"
                       "     " VERSION_ENV ":    The image version to mount.\n"
                       "     " MAINT_ENV ":      Mount in read-write mode.\n");
                return 0;

            case 'V':
                printf("%s version 1.1.0\n", wrappername);
                return 0;

            default:
                break;
        }
    }

    if (getenv(MAINT_ENV) != NULL)
        maint = 1;

    if (!has_version && ((version_env = getenv(VERSION_ENV)) != NULL)) {
        has_version = 1;
        strlcpy(version,version_env,MAX_VERSION_LENGTH);
    }

    if (recursing || optind >=argc) {
        char* shellenv = getenv("SHELL");
        struct passwd *pwinfo;
        if (shellenv == NULL) {
            errno = 0;
            if ((pwinfo = getpwuid(uid)) == NULL) {
                fprintf(stderr,"Error: Error getting user's shell: %s!\n",strerror(errno));
                return -1;
            }
            shellenv = pwinfo->pw_shell;
        }
        strlcpy(user_shell,shellenv,PATH_MAX);
    }

    if (optind < argc) {
        program = argv[optind];
        program_args = &argv[optind];
    } else {
        program = user_shell;
        default_program_args[0] = user_shell;
        default_program_args[1] = NULL;
        default_program_args[2] = NULL;
        program_args = default_program_args;
    }

    if (recursing) {
        default_program_args[0] = user_shell;
        default_program_args[1] = program;
        default_program_args[2] = NULL;
        program=user_shell;
        printf("%s %s %s\n", default_program_args[0], default_program_args[1], default_program_args[2]);
        program_args = default_program_args;
    }

    if (maint && uid != 0) {
        struct passwd *pwinfo;
        struct group *maintgrpinfo;
        int i, ngroups = 1;
        gid_t *groups = malloc(ngroups*sizeof(gid_t));
        gid_t *retry;

        if ((pwinfo = getpwuid(uid)) == NULL) {
            fprintf(stderr,"Error: Cannot get info for user!\n");
            return -1;
        }

        if ((maintgrpinfo = getgrnam(MAINT_GROUP)) == NULL) {
            fprintf(stderr,"Error: Cannot get group info for maintenance group!\n");
            return -1;
        }

        if (groups == NULL) {
            fprintf(stderr,"Error: Cannot allocate memory!\n");
            return -1;
        }

        if (getgrouplist(pwinfo->pw_name, pwinfo->pw_gid, groups, &ngroups) == -1) {
            retry = realloc(groups,ngroups*sizeof(gid_t));
            if (retry == NULL) {
                fprintf(stderr,"Error: Cannot allocate memory!\n");
                free(groups);
                return -1;
            } else {
                groups = retry;
            }
            if (getgrouplist(pwinfo->pw_name, pwinfo->pw_gid, groups, &ngroups) == -1) {
                free(groups);
                fprintf(stderr,"Error: Error getting user's groups!\n");
                return -1;
            }
        }

        for(i = 0; i < ngroups; ++i) {
            if (groups[i] == maintgrpinfo->gr_gid)
                break;
        }
        if (i == ngroups) {
            fprintf(stderr, "Warning: You must be a member of the " MAINT_GROUP " group to mount read-write! Mounting read-only.\n");
            maint = 0;
        }
        free(groups);
    }

    //Do this after parsing args, in case --help or --version are specified,
    //which take priority
    if (has_version) {
        if ((image_name = versioned_image(version, maint)) == NULL)
            return -1;
    }

    //Regain permissions
    if (seteuid(suid)) {
        fprintf(stderr,"Error: Cannot regain user privileges: %s!\n",strerror(errno));
        return -1;
    }
    if (setegid(sgid)) {
        fprintf(stderr,"Error: Cannot regain group privileges: %s!\n",strerror(errno));
        return -1;
    }

    if (setup_loop_and_mount(image_name) < 0) {
        return -1;
    }

    char linkbuf[PATH_MAX];
    char targetbuf[PATH_MAX];
    if (sym) {
        struct passwd *pwinfo;
        struct stat sb;
        if ((pwinfo = getpwuid(uid)) == NULL) {
            fprintf(stderr,"Error: Cannot get info for user!\n");
            return -1;
        }
        snprintf(linkbuf,PATH_MAX,SYMLINK_BASE "/%s",pwinfo->pw_name);
        if (mkdir_p(linkbuf,S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
            fprintf(stderr,"Error: Error creating directory %s: %s!\n",linkbuf,strerror(errno));
            return -1;
        }
        if (chown(linkbuf,uid,gid) < 0) {
            fprintf(stderr,"Error: Cannot chown %s: %s!\n",linkbuf,strerror(errno));
            return -1;
        }
        char *image = basename(image_name);
        snprintf(linkbuf,PATH_MAX, SYMLINK_BASE "/%s/%s",pwinfo->pw_name,image);
        if (unlink(linkbuf) == -1) {
            if (errno != ENOENT) {
                fprintf(stderr,"Error: Cannot remove %s!\n",linkbuf);
                return -1;
            }
        }
    }

    drop_priv_perm(uid,gid);

    char *ld_library_path = getenv("LD_LIBRARY_PATH_WRAP");
    if (ld_library_path != NULL && setenv("LD_LIBRARY_PATH",ld_library_path,1) != 0) {
        fprintf(stderr, "Error: Cannot set LD_LIBRARY_PATH: %s\n",strerror(errno));
        return -1;
    }

    pid_t child_pid = fork();

    if (child_pid == 0) {
        // Child
        execvp(program,program_args);
        fprintf(stderr,"Error: Error executing %s: %s!\n",program,strerror(errno));
        _exit(-1);
    } else if (child_pid < 0) {
        fprintf(stderr,"Error: Error forking!\n");
        return -1;
    } else {
        // Parent
        if (sym) {
            snprintf(targetbuf,PATH_MAX,"/proc/%d/root" MOUNTPOINT,child_pid);
            if (symlink(targetbuf,linkbuf) == -1) {
                if (errno != EEXIST) {
                    fprintf(stderr,"Error: Cannot create symlink %s -> %s: %s\n",linkbuf,targetbuf,strerror(errno));
                    return -1;
                }
            }
        }
        int status;
        wait(&status);
    }
    return -2;
}
// vim: tabstop=4:shiftwidth=4:expandtab

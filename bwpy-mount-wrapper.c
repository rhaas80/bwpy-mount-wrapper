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
#include <fcntl.h>
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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/version.h>

#define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)

#define COLOR_NC   "\e[0m"
#define COLOR_CYAN "\e[36m"
#define COLOR_RED  "\e[31m"

//Kernel headers don't always match actual kernel version
#define THIS_KERNEL_VERSION KERNEL_VERSION(3,0,101)

//Test system?
//#define TEST_SETTINGS

//Paths and image type settings
#ifdef TEST_SETTINGS
#define IMAGE_DIR "/home/colin"
//#define MAINT_GROUP "colin" //primary group
#define MAINT_GROUP "plugdev" //secondary group
//#define MAINT_GROUP "games" //non-member
#define MOUNTPOINT "/sw/bw/bwpy"
#define IMAGE_TYPE "ext3"
#else
#define IMAGE_DIR "/sw/bw/images/bwpy"
#define MAINT_GROUP "bw_seas"
#define MOUNTPOINT "/sw/bw/bwpy"
#define IMAGE_TYPE "ext3"
#define MODULE_LOADING
//#define ALWAYS_LOAD
//#define SYMBOL_CHECKS
#endif

//Image name settings
#define IMAGE_DEFAULT_FILENAME "bwpy.img"
#define IMAGE_DEFAULT IMAGE_DIR "/" IMAGE_DEFAULT_FILENAME
#define IMAGE_PREFIX "bwpy"
#define IMAGE_SUFFIX ".img"
#define IMAGE_VERSIONED IMAGE_DIR "/" IMAGE_PREFIX "-%s" IMAGE_SUFFIX

//Kernel Module settings
#define LOOP_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/drivers/block/loop.ko"
#define MBCACHE_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/fs/mbcache.ko"
#define JBD_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/fs/jbd/jbd.ko"
#define JBD2_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/fs/jbd2/jbd2.ko"
#define EXT3_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/fs/ext3/ext3.ko"
#define EXT4_KO "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/3.0.101-0.46.1_1.0502.8871-cray_gem_c/kernel/fs/ext4/ext4.ko"

//Other definitions
#define LOOP_CHECK_SYMBOL "loop_get_status"
#define LOOP_NAME "loop"
#define MAX_LOOP_DEVS 256 //The kernel limit is 256 (still?)
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

int maint = 0;

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
const char *versioned_image(const char* version_string) {
    char good_realdir[PATH_MAX]; 
    char suspect_path[PATH_MAX];
    static char suspect_realpath[PATH_MAX];
    char suspect_realdir[PATH_MAX];
    const char* clean_path = NULL;

    if (realpath(IMAGE_DIR, good_realdir) == NULL) {
        fprintf(stderr,"Error: failed to get real path of image directory: %s %s\n",IMAGE_DIR,strerror(errno));
        return NULL;
    }
    
    snprintf(suspect_path,PATH_MAX,IMAGE_VERSIONED,version_string);

    
    if (realpath(suspect_path, suspect_realpath) == NULL) {
        fprintf(stderr,"Error: failed to get real path of requested image %s: %s\n",suspect_path,strerror(errno));
        return NULL;
    }

    strncpy(suspect_realdir,suspect_realpath,PATH_MAX);

    if (strncmp(good_realdir,dirname(suspect_realdir),PATH_MAX) == 0)
        clean_path = suspect_realpath;
    else 
        fprintf(stderr,"Error: Something fishy is going on here. %s != %s\n",dirname(suspect_realpath),good_realdir);
    
    return clean_path;
}

int setup_module(const char* name, const char* ko_file, const char* check_symbol) {
    FILE *f;
    char line[4096];
    int found = 0;
    size_t ko_size;
    ssize_t read_size;
    void *ko_image;
    char sysmodulepath[PATH_MAX];
    struct stat st;

#ifndef ALWAYS_LOAD
    snprintf(sysmodulepath,PATH_MAX,"/sys/module/%s",name);

    if (stat(sysmodulepath,&st) == 0 && S_ISDIR(st.st_mode)) {
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
    fclose(f);

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

        fclose(f);
    }
#endif

    if (!found && strlen(ko_file) > 0) {
#endif
        int fd;
        
        if ((fd = open(ko_file, O_RDONLY)) < 0) {
            fprintf(stderr,"Error: Cannot open %s: %s!\n",ko_file,strerror(errno));
            return -1;
        }

        if (fstat(fd, &st) < 0) {
            fprintf(stderr,"Error: Cannot stat %s: %s!\n",ko_file,strerror(errno));
            close(fd);
            return -1;
        }

        ko_size  = st.st_size;
        if ((ko_image = malloc(ko_size)) == NULL) {
            fprintf(stderr,"Error: Failed to allocate memory for kenel module %s: %s!",ko_file,strerror(errno));
            close(fd);
            return -1;
        }   

        if ((read_size = read(fd, ko_image, ko_size)) < ko_size) {
            if (read_size < 0)
                fprintf(stderr,"Error: Error reading %s: %s!\n",ko_file,strerror(errno));
            else 
                fprintf(stderr,"Error: %s smaller than expected. %zu < %zu.\n", ko_file, (size_t) read_size, ko_size);

            free(ko_image);
            close(fd);
            return -1;
        }

        close(fd);

        if (init_module(ko_image, ko_size, "") != 0) {
            //errno is EEXIST if module is already loaded
            //errno is ENOEXEC if module is built-in
            if (errno == EEXIST || errno == ENOEXEC) {
                free(ko_image);
                return 0;
            }
            fprintf(stderr,"Error: Error inserting %s: %s!\n",ko_file,strerror(errno));
            free(ko_image);
            return -1;
        }
        free(ko_image);
        return 1;
#ifndef ALWAYS_LOAD
    } else if (!found && strlen(ko_file) == 0) {
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
            return NULL;
        }
        close(fd);
        return NULL;
    }

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
    int fd;
    int loopfd = -1;
    int loop_dev;
    int err = 0;
    const char *errmsg = "";

    if (realpath(image_path,real_image_path) == NULL) {
        fprintf(stderr,"Error: failed to get real path of %s: %s\n",image_path,strerror(errno));
        return -1;
    }

    if ((loop_dev = find_existing_loop(real_image_path)) >= 0)
        return loop_dev;

    if (maint) {
        if ((fd = open(real_image_path, O_RDWR)) < 0)
            return -1;
    } else {
        if ((fd = open(real_image_path, O_RDONLY)) < 0)
            return -1;
    }

    //Find and open an unused loop device
    for (loop_dev = 0; loop_dev < MAX_LOOP_DEVS; ++loop_dev) {
        bf = backing_file(loop_dev);
        if (bf == NULL) {
            const char *dev_loop_path = loop_dev_num(loop_dev);
            if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
                if (errno == ENOENT) {
                    int mode = 0660 | S_IFBLK;
                    
                    if (mknod(dev_loop_path,mode,makedev(7,loop_dev)) < 0) {
                        errmsg = "Error creating loop device: ";
                        err = errno;
                        goto error;
                    }

                    if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
                        errmsg = "Error opening loop device (2nd attempt): ";
                        err = errno;
                        goto error;
                    }

                    if (flock(loopfd,LOCK_EX | LOCK_NB) < 0) {
                        if (errno == EWOULDBLOCK) {
                            //Another wrapper is in the process of setting up
                            //this loop device. Close loopfd and find another.
                            close(loopfd);
                            ++loop_dev;
                            continue;
                        } else {
                            errmsg = "Error locking loop device (2nd attempt): ";
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
                    //this loop device. Close loopfd and find another.
                    close(loopfd);
                    ++loop_dev;
                    continue;
                } else {
                    errmsg = "Error locking loop device: ";
                    err = errno;
                    goto error;
                }
            }
            break;
        }
    }

    if (loop_dev == MAX_LOOP_DEVS) {
        fprintf(stderr,"Error: Out of loop devices!\n");
        goto error_noprint;
    }

    if (loopfd < 0) {
        fprintf(stderr,"Error: Failed to find a loop device!\n");
        goto error_noprint;
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

    close(fd);
    close(loopfd);
    return loop_dev;

error:
    fprintf(stderr,"Error: %s%s\n",errmsg,strerror(err));
error_noprint:
    close(fd);
    if (loopfd < 0)
        close(loopfd);
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
        abort ();
    }
  
    if (getresgid (&check_rg, &check_eg, &check_sg) != 0
            || check_rg != gid || check_eg != gid || check_sg != gid) {
        fprintf(stderr,"Error: Group privileges were not dropped!\n");
        abort ();
    }
}

int main(int argc, char *argv[])
{
    char wrappername[NAME_MAX];
    const char *program;
    char **program_args;
    int loopdev;
    char version[64];
    int has_version = 0;
    char user_shell[PATH_MAX];
    const char *image_name = IMAGE_DEFAULT; 

    //Get current real and effective privileges
    gid_t gid = getgid();
    uid_t uid = getuid();
    gid_t egid = getegid();
    uid_t euid = geteuid();
    gid_t sgid = egid;
    uid_t suid = euid;

    if (egid != 0) {
        fprintf(stderr,"Error: Not a root suid binary!\n");
        return -1;
    }

#ifdef MODULE_LOADING
    int loaded_loop, loaded_mbcache, loaded_jbd2, loaded_ext4;
    if ((loaded_loop = setup_module(LOOP_NAME,LOOP_KO,LOOP_CHECK_SYMBOL)) < 0) {
        fprintf(stderr,"Error: No loop device support!\n");
        return -1;
    }
    if ((loaded_mbcache = setup_module(MBCACHE_NAME,MBCACHE_KO,MBCACHE_CHECK_SYMBOL)) < 0) {
        fprintf(stderr,"Error: No mbcache support!\n");
        return -1;
    }
    if ((loaded_jbd2 = setup_module(JBD_NAME,JBD_KO,JBD_CHECK_SYMBOL)) < 0) {
        fprintf(stderr,"Error: No jbd2 support!\n");
        return -1;
    }
    if ((loaded_ext4 = setup_module(EXT3_NAME,EXT3_KO,EXT3_CHECK_SYMBOL)) < 0) {
        fprintf(stderr,"Error: No ext4 support!\n");
        return -1;
    }
#endif

    //Temporarily drop permissions
    if (setegid(gid)) {
        fprintf(stderr,"Error: Cannot drop group privileges: %s!\n",strerror(errno));
        return -1;
    }
    if (seteuid(uid)) {
        fprintf(stderr,"Error: Cannot drop user privileges: %s!\n",strerror(errno));
        return -1;
    }
    
    strncpy(wrappername,basename(argv[0]),NAME_MAX);    

    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "maintenance",   no_argument,       0,  'm' },
            { "image-version", required_argument, 0,  'v' },
            { "list",          no_argument,       0,  'l' },
            { "version",       no_argument,       0,  'V' },
            { "help",          no_argument,       0,  'h' },
            { 0,               0,                 0,  0   }
        };

        c = getopt_long(argc, argv, "mlv:hV", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'm':
                maint = 1;
                break;

            case 'v':
                has_version = 1;
                strncpy(version,optarg,64);
                break;

            case 'l':
                drop_priv_perm(uid,gid);
                list_versions();
                return 0;

            case 'h':
                printf("Usage: %s [-mhv] [--image-version version] [--maintenance] [--] [program [args...]]\n",wrappername);
                return 0;

            case 'V':
                printf("Version: 1.0.0\n");
                return 0;
                
            default:
                break;
        }
    }

    if (optind < argc) {
        program = argv[optind];
        program_args = &argv[optind];
    } else {
        memset(user_shell,0,PATH_MAX);
        const char* tmp = getenv("SHELL");
        struct passwd *pwinfo;
        if (tmp == NULL) {
            errno = 0;
            if ((pwinfo = getpwuid(uid)) == NULL) {
                fprintf(stderr,"Error: Error getting user's shell: %s!\n",strerror(errno));
                return -1;
            }
            tmp = pwinfo->pw_shell;
        }
        strncpy(user_shell,tmp,PATH_MAX);
        program = user_shell;
        program_args = NULL;
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
            fprintf(stderr, "Error: You must be a member of the %s group to mount read-write!\n",MAINT_GROUP);
            return -1;
        }
        free(groups);
    }

    //Do this after parsing args, in case --help or --version are specified,
    //which take priority
    if (has_version) {
        if ((image_name = versioned_image(version)) == NULL)
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

    if ((loopdev = setup_loop_dev(image_name)) < 0) {
        fprintf(stderr,"Error setting up loop device!\n");
        return -1;
    }

    //Unshare the mount namespace
    if (unshare(CLONE_NEWNS) != 0) {
        fprintf(stderr,"Error: Cannot create mount namespace: %s!\n",strerror(errno));
        return -1;
    }

    //Don't share the mounting with other processes
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        fprintf(stderr,"Error: Cannot give / subtree private mount propagation: %s!\n",strerror(errno));
        return -1;
    }

    const char* loop_dev_file = loop_dev_num(loopdev);
    unsigned long mountflags = MS_NOSUID | MS_NODEV | MS_NOATIME;
    if (!maint)
        mountflags |= MS_RDONLY;
            
    if (mount(loop_dev_file, MOUNTPOINT, IMAGE_TYPE, mountflags, "") < 0){
        fprintf(stderr,"Error: Cannot mount image on %s: %s!\n",loop_dev_file,strerror(errno));
        return -1;
    }

    //Set loop device to detach automatically once last mount is unmounted
    int loopfd;
    if ((loopfd = open(loop_dev_file, O_RDWR)) < 0) {
        fprintf(stderr,"Error: Error opening loop device: %s!\n",strerror(errno));
        return -1;
    }

    struct loop_info64 loopinfo64;
    memset(&loopinfo64, 0, sizeof(loopinfo64));
    loopinfo64.lo_flags = LO_FLAGS_AUTOCLEAR;
    
    if (ioctl(loopfd, LOOP_SET_STATUS64, &loopinfo64) < 0) {
        fprintf(stderr,"Error: Error setting LO_FLAGS_AUTOCLEAR: %s!\n",strerror(errno));
        close(loopfd);
        return -1;
    }

    close(loopfd);
   
    drop_priv_perm(uid,gid);

    if (execvp(program,program_args) < 0) {
        fprintf(stderr,"Error: Error executing %s: %s!\n",program,strerror(errno));
        return -1;
    }
    return -2;
}

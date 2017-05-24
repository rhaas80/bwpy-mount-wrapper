#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/loop.h>

#define IMAGE "/home/colin/test-symlink2.ext4"
#define IMAGE_DIR "/home/colin"
#define MOUNTPOINT "/sw/bw/bwpy"
#define IMAGE_TYPE "ext4"
#define MAINT_GROUP "bw_seas"

int maint = 0;

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

    if ((len = read(fd,res,PATH_MAX)) == 0) {
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

    for (loop_dev = 0; loop_dev < 256; ++loop_dev) {
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

    if (realpath(image_path,real_image_path) == NULL) {
        fprintf(stderr,"Error: failed to get real path of %s\n",image_path);
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
    for (loop_dev = 0; loop_dev < 255; ++loop_dev) {
        bf = backing_file(loop_dev);
        if (bf == NULL) {
            const char *dev_loop_path = loop_dev_num(loop_dev);
            if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
                if (errno == ENOENT) {
                    int mode = 0666 | S_IFBLK;
                    
                    if (mknod(dev_loop_path,mode,makedev(7,loop_dev)) < 0) {
                        err = errno;
                        goto error;
                    }

                    if ((loopfd = open(dev_loop_path, O_RDWR)) < 0) {
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
                            err = errno;
                            goto error;
                        }
                    }
                } else {
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
                    err = errno;
                    goto error;
                }
            }
            break;
        }
    }

    if (loop_dev == 255) {
        fprintf(stderr,"Error: out of loop devices!\n");
        goto error_noprint;
    }

    if (loopfd < 0) {
        fprintf(stderr,"Error: failed to find a loop device!\n");
        goto error_noprint;
    }

    if (ioctl(loopfd, LOOP_SET_FD, fd) < 0) {
        err = errno;
        goto error;
    }

    if (flock(loopfd, LOCK_UN) < 0) {
        err = errno;
        goto error;
    }

    close(fd);
    close(loopfd);
    return loop_dev;

error:
    fprintf(stderr,"Error: %s\n",strerror(err));
error_noprint:
    close(fd);
    if (loopfd < 0)
        close(loopfd);
    return -1;
}

int main(int argc, char *argv[])
{
    char wrappername[NAME_MAX];
    const char *program;
    char **program_args;
    int loopdev;
    int use_shell = 0; 
    int shift = 1;
    char version[64];
    int has_version = 0;
    char user_shell[PATH_MAX];

    //Get current real and effective privileges
    gid_t gid = getgid();
    uid_t uid = getuid();
    gid_t egid = getegid();
    uid_t euid = geteuid();
    gid_t sgid = egid;
    uid_t suid = euid;

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
            { "version",       no_argument,       0,  'V' },
            { "help",          no_argument,       0,  'h' },
            { 0,               0,                 0,  0   }
        };

        c = getopt_long(argc, argv, "mv:h", long_options, &option_index);

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
    }

    if (maint) {
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

        if (getgrouplist(argv[1], pwinfo->pw_gid, groups, &ngroups) == -1) {
            retry = realloc(groups,ngroups*sizeof(gid_t));
            if (retry == NULL) {
                fprintf(stderr,"Error: Cannot allocate memory!\n");
                return -1;
            } else {
                groups = retry;
            }
            if (getgrouplist(argv[1], pwinfo->pw_gid, groups, &ngroups) == -1) {
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
    }

    if ((loopdev = setup_loop_dev(IMAGE)) < 0) {
        fprintf(stderr,"Error setting up loop device /dev/loop%hhu!\n",loopdev);
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
    
    if (euid == 0) {
        if (unshare(CLONE_NEWNS) != 0) {
            fprintf(stderr,"Error: Cannot create mount namespace: %s!\n",strerror(errno));
            return -1;
        }

        if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
            fprintf(stderr,"Error: Cannot give / subtree private mount propagation: %s!\n",strerror(errno));
            return -1;
        }

        const char* loop_dev_file = loop_dev_num(loopdev);
        unsigned long mountflags = MS_NOSUID | MS_NODEV | MS_NOATIME;
        if (!maint)
            mountflags |= MS_RDONLY;
            
        if (mount(loop_dev_file, MOUNTPOINT, IMAGE_TYPE, mountflags, "") < 0){
            fprintf(stderr,"Error: Cannot mount image: %s!\n",strerror(errno));
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

    } else {
        fprintf(stderr,"Error: Not a root suid binary!\n");
        return -1;
    }
   
    //Permanently drop privileges
    //
    //setresgid/setresuid makes it more obvious that we are 
    //dropping real, effective, and saved uid/gid privileges
    //vs setuid(getuid()) and setgid(getuid())
    if (setresgid(gid,gid,gid) != 0) {
        fprintf(stderr,"Error: Error dropping group privileges: %s!\n",strerror(errno));
        return -1;
    }
    if (setresuid(uid,uid,uid) != 0) {
        fprintf(stderr,"Error: Error dropping privileges: %s!\n",strerror(errno));
        return -1;
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

    if (execvp(program,program_args) < 0) {
        fprintf(stderr,"Error: Error executing %s: %s!\n",program,strerror(errno));
        return -1;
    }
    return -2;
}

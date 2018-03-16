#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "bwpy-mount-wrapper.h"

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
    char clean_image_path[PATH_MAX];
    const char *version_env;
    int recursing = 0;
    char *argv0 = NULL;

    //Get current real and effective privileges
    gid_t gid = getgid();
    uid_t uid = getuid();
    gid_t egid = getegid();
    uid_t euid = geteuid();
    gid_t sgid = egid;
    uid_t suid = euid;

    if (egid != 0) {
        fprintf(stderr,"Error: Not a root suid binary! (When launched via aprun, `aprun -b` must be used)\n");
        return EXIT_FAILURE;
    }

#ifdef MODULE_LOADING
    if (setup_module(LOOP_NAME,LOOP_KO,LOOP_CHECK_SYMBOL) < 0) {
        fprintf(stderr,"Error: No loop device support!\n");
        return EXIT_FAILURE;
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
            return EXIT_FAILURE;
        }
        if (strncmp(pprocess,argv[0],PATH_MAX) == 0) {
            recursing = 1;
        }
    }

    //Temporarily drop permissions
    if (setegid(gid)) {
        fprintf(stderr,"Error: Cannot drop group privileges: %s!\n",strerror(errno));
        return EXIT_FAILURE;
    }
    if (seteuid(uid)) {
        fprintf(stderr,"Error: Cannot drop user privileges: %s!\n",strerror(errno));
        return EXIT_FAILURE;
    }

    strlcpy(wrappername,basename(argv[0]),NAME_MAX);

    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "argv0",         required_argument, 0,  'a' },
            { "maintenance",   no_argument,       0,  'm' },
            { "image-version", required_argument, 0,  'v' },
            { "list",          no_argument,       0,  'l' },
            { "symlink",       no_argument,       0,  's' },
            { "version",       no_argument,       0,  'V' },
            { "help",          no_argument,       0,  'h' },
            { 0,               0,                 0,  0   }
        };

        c = getopt_long(argc, argv, "+a:mlv:hVs", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'a':
                argv0 = optarg;
                break;
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
                       "     -a, --argv0 STRING             Set the argv[0] of the executed process to the specified string. Useful for wrappers.\n"
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
                return EXIT_FAILURE;
            }
            shellenv = pwinfo->pw_shell;
        }
        strlcpy(user_shell,shellenv,PATH_MAX);
    }

    if (optind < argc) {
        program = argv[optind];
        program_args = &argv[optind];
        if (argv0)
            program_args[0] = argv0;
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
            return EXIT_FAILURE;
        }

        if ((maintgrpinfo = getgrnam(MAINT_GROUP)) == NULL) {
            fprintf(stderr,"Error: Cannot get group info for maintenance group!\n");
            return EXIT_FAILURE;
        }

        if (groups == NULL) {
            fprintf(stderr,"Error: Cannot allocate memory!\n");
            return EXIT_FAILURE;
        }

        if (getgrouplist(pwinfo->pw_name, pwinfo->pw_gid, groups, &ngroups) == -1) {
            retry = realloc(groups,ngroups*sizeof(gid_t));
            if (retry == NULL) {
                fprintf(stderr,"Error: Cannot allocate memory!\n");
                free(groups);
                return EXIT_FAILURE;
            } else {
                groups = retry;
            }
            if (getgrouplist(pwinfo->pw_name, pwinfo->pw_gid, groups, &ngroups) == -1) {
                free(groups);
                fprintf(stderr,"Error: Error getting user's groups!\n");
                return EXIT_FAILURE;
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
        if ((image_name = versioned_image(clean_image_path, version, maint)) == NULL)
            return EXIT_FAILURE;
    } else {
        if (realpath(image_name,clean_image_path) == NULL) {
            fprintf(stderr,"Error: failed to get real path of image directory: %s %s\n",image_name,strerror(errno));
            return EXIT_FAILURE;
        }
        image_name = clean_image_path;
    }

    //Regain permissions
    if (seteuid(suid)) {
        fprintf(stderr,"Error: Cannot regain user privileges: %s!\n",strerror(errno));
        return EXIT_FAILURE;
    }
    if (setegid(sgid)) {
        fprintf(stderr,"Error: Cannot regain group privileges: %s!\n",strerror(errno));
        return EXIT_FAILURE;
    }

    if (setup_loop_and_mount(image_name) < 0) {
        return EXIT_FAILURE;
    }

    char linkbuf[PATH_MAX];
    char targetbuf[PATH_MAX];
    if (sym) {
        struct passwd *pwinfo;
        struct stat sb;
        if ((pwinfo = getpwuid(uid)) == NULL) {
            fprintf(stderr,"Error: Cannot get info for user!\n");
            return EXIT_FAILURE;
        }
        snprintf(linkbuf,PATH_MAX,SYMLINK_BASE "/%s",pwinfo->pw_name);
        if (mkdir_p(linkbuf,S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
            fprintf(stderr,"Error: Error creating directory %s: %s!\n",linkbuf,strerror(errno));
            return EXIT_FAILURE;
        }
        if (chown(linkbuf,uid,gid) < 0) {
            fprintf(stderr,"Error: Cannot chown %s: %s!\n",linkbuf,strerror(errno));
            return EXIT_FAILURE;
        }
        char *image = basename(image_name);
        snprintf(linkbuf,PATH_MAX, SYMLINK_BASE "/%s/%s",pwinfo->pw_name,image);
        if (unlink(linkbuf) == -1) {
            if (errno != ENOENT) {
                fprintf(stderr,"Error: Cannot remove %s!\n",linkbuf);
                return EXIT_FAILURE;
            }
        }
    }

    drop_priv_perm(uid,gid);

    RESTORE_ENV("LD_LIBRARY_PATH");
    RESTORE_ENV("LD_PRELOAD");
    RESTORE_ENV("NLSPATH");

    pid_t child_pid = fork();

    if (child_pid == 0) {
        // Child
        execvp(program,program_args);
        fprintf(stderr,"Error: Error executing %s: %s!\n",program,strerror(errno));
        _exit(EXIT_FAILURE);
    } else if (child_pid < 0) {
        fprintf(stderr,"Error: Error forking!\n");
        return EXIT_FAILURE;
    } else {
        // Parent
        if (sym) {
            snprintf(targetbuf,PATH_MAX,"/proc/%d/root" MOUNTPOINT,child_pid);
            if (symlink(targetbuf,linkbuf) == -1) {
                if (errno != EEXIST) {
                    fprintf(stderr,"Error: Cannot create symlink %s -> %s: %s\n",linkbuf,targetbuf,strerror(errno));
                    return EXIT_FAILURE;
                }
            }
        }
        int status;
        if (wait(&status) == -1) {
            fprintf(stderr,"Error: wait() failed: %s\n",strerror(errno));
            return EXIT_FAILURE;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            if (WCOREDUMP(status)) {
                fprintf(stderr,"Child terminated with signal %d. Core dumped.\n",WTERMSIG(status));
            } else {
                fprintf(stderr,"Child terminated with signal %d.\n",WTERMSIG(status));
            }
            return EXIT_FAILURE;
        }
    }
    return EXIT_FAILURE;
}

// vim: tabstop=4:shiftwidth=4:expandtab

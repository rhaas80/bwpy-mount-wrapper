//Paths and image type settings
#define IMAGE_DIR "/sw/bw/images/bwpy"
#define MAINT_GROUP "bw_seas"
#define MOUNTPOINT "/tmp/bwpy"
#define IMAGE_TYPE "ext3"
#define MODULE_LOADING
//#define ALWAYS_LOAD
//#define SYMBOL_CHECKS

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

//Paths and image type settings
#define IMAGE_DIR "/sw/bw/images/bwpy"
#define MAINT_GROUP "bw_seas"
#define MOUNTPOINT "/mnt/bwpy"
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
#define  MODULE_BASE_DIR "/opt/cray/shifter/1.0.16-1.0502.66669.3.1.gem/kmod/"

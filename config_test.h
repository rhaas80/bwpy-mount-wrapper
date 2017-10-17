//Paths and image type settings
#define IMAGE_DIR "/home/colin"
//#define MAINT_GROUP "colin" //primary group
#define MAINT_GROUP "plugdev" //secondary group
//#define MAINT_GROUP "games" //non-member
#define MOUNTPOINT "/tmp/bwpy"
#define IMAGE_TYPE "ext3"

//Image name settings
#define IMAGE_DEFAULT_FILENAME "bwpy.img"
#define IMAGE_DEFAULT IMAGE_DIR "/" IMAGE_DEFAULT_FILENAME
#define IMAGE_PREFIX "bwpy"
#define IMAGE_SUFFIX ".img"
#define IMAGE_VERSIONED IMAGE_DIR "/" IMAGE_PREFIX "-%s" IMAGE_SUFFIX

//Kernel Module settings

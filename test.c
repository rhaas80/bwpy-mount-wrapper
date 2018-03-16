#include <stdio.h>

#include "bwpy-mount-wrapper.h"

int main(int argc, char* argv[]) {
    maint = 0;
    const char* version_string = "0.3.2";
    char *vi = versioned_image(version_string, maint);
    fprintf(stdout,"%s\n",vi);
    return 0;
}

// vim: tabstop=4:shiftwidth=4:expandtab

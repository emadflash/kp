#include "kp.h"

int main(int argc, char** argv) {
    Kp_Init kp_init = {
        .project_name = "your_project_name",
        .version = "0.0.0",
        .binary_name = "your_projects_binary_name",
        .description = "project description goes here",
    };

    Kp kp;
    kp_mk(&kp, &kp_init, 1, 3);

    char** your_name = kp_arg_string(&kp, NULL, "your-name", NULL, "your name"); /* TODO(madflash) Remove default value option for args */
    bool* follow_symlinks = kp_flag_bool(&kp, false, "follow_symlinks", NULL, "should we follow symlinks ?");
    char** url = kp_flag_string(&kp, NULL, "url", "U", "your url");
    uint8_t* depth = kp_flag_uint8(&kp, 10, "depth", NULL, "max recursion depth");

    if (argc < 2) {
        kp_usage(&kp, stderr);
        kp_free(&kp);
        exit(1);
    }

    kp_parse(&kp, argv, argc);

    /*Check if the positional arg is provided on your own XD and raise error accordingly*/
    if (*your_name == NULL ) {
        fprintf(stderr, "--your-name is required\n");
        kp_free(&kp);
        exit(1);
    } else {
        // do something with "your-name" (positional arg)
        fprintf(stdout, "your name is %s\n", *your_name);
    }
    
    if (*follow_symlinks) {
        // do something if follow_symlinks is set true
    }

    if (*url != NULL) {
        // do something if we get a url
    }

    // do something with depth (it already has a default value)

    kp_free(&kp);
    return 0;
}

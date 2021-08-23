#ifndef _KP_H
#define _KP_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define KP_STRCMP(X, Y) strcmp(X, Y) == 0

#define KP_TOGGLE_BOOLEAN(X)\
    if ((X)) X = false;\
    else X = true

/********************************************************************************
  allocates new buffer and copies given string and adds null byte

  @param dest:
    ptr to the string literal

  @param size:
    number of chars to be copied

  @return: a const ptr to buffer

********************************************************************************/
const char* KP_DEEP_COPY(char* dest, size_t size) {
    size_t _size = size + 1;
    char* ret = (char*) malloc(_size* sizeof(char));
    memcpy(ret, dest, _size);
    ret[_size - 1] = '\0';
    return ret;
}


/********************************************************************************
  Kp_Usage struct, it is used by Kp_Flag_Main, Kp_Arg

    arg_description: is the formatting used for a particular instance defined
    using mk_usage function
    
    description: General usage of a flag
********************************************************************************/
typedef struct {
    char* arg_description;
    char* description;
} Kp_Usage;

/* destroy usage */
void kp_dk_usage(Kp_Usage* usage) {
    free(usage->arg_description);
}



/********************************************************************************


Kp_Flag_Main


********************************************************************************/
typedef struct {
    char* big_flag;
    char* short_flag;
    Kp_Usage usage;
} Kp_Flag_Main;


/*Replaces underscores with dashes*/
/*Returns count of segments*/
size_t kp__flag_size_of_significants(char* flag, size_t len) {
    char* begin = flag;
    char* end = flag + len;
    size_t count = 1;

    for(; begin != end; ++begin) {
        if (*begin == '_' || *begin == '-' ) {
            ++count;
        }
    }
    return count;
}


void kp__flag_get_size_for_flags(const char* big_flag, const char* short_flag, size_t* big_flag_size, size_t* short_flag_size) {
    /*Add space for two dashes*/
    size_t n_null_byte = 1;
    size_t big_n_dashes = 2;
    size_t short_n_dashes = 1;

    *big_flag_size = strlen(big_flag) + big_n_dashes + n_null_byte;

    *short_flag_size =  short_n_dashes + n_null_byte;
    if (short_flag == NULL) {
        *short_flag_size += kp__flag_size_of_significants(big_flag, strlen(big_flag));
    } else {
        *short_flag_size += strlen(short_flag);
    }
}


void kp__mk_big_flag(Kp_Flag_Main* flag, const char* big_flag, size_t big_flag_size) {
    assert(big_flag[0] != '-' && "big flag must not start with -");
    snprintf(flag->big_flag, big_flag_size, "--%s\0", big_flag);

    size_t i=0;
    for(; i < big_flag_size; ++i) {
        if (flag->big_flag[i] == '_') {
            flag->big_flag[i] = '-';
        }
    }
}


void kp__mk_short_flag(Kp_Flag_Main* flag, const char* short_flag, size_t short_flag_size) {
    if (short_flag == NULL) {
        int short_flag_counter = 0;
        char* begin = flag->big_flag + 2;
        char* end = flag->big_flag + strlen(begin);

        flag->short_flag[short_flag_counter++] = '-';
        flag->short_flag[short_flag_counter++] = *begin;
        for(; begin != end; ++begin) {
            if (*begin == '_' || *begin == '-' ) {
                assert(begin + 1 != end && "Idx out of range");
                flag->short_flag[short_flag_counter++] = *(begin + 1);
            }
        }
        flag->short_flag[short_flag_counter] = '\0';
    } else {
        assert(short_flag[0] != '-' && "short flag must not start with -");
        snprintf(flag->short_flag, short_flag_size,  "-%s\0", short_flag);
    }
}


void kp__mk_flag(Kp_Flag_Main* flag, const char* big_flag, const char* short_flag) {
    size_t big_flag_size = 0;
    size_t short_flag_size = 0;
    kp__flag_get_size_for_flags(big_flag, short_flag, &big_flag_size, &short_flag_size);

    flag->big_flag = (char*) malloc(big_flag_size * sizeof(char));
    flag->short_flag = (char*) malloc(short_flag_size * sizeof(char));

    kp__mk_big_flag(flag, big_flag, big_flag_size);
    kp__mk_short_flag(flag, short_flag, short_flag_size);
}

#define KP_FLAG_USAGE_SIZE 3


void kp__mk_flag_usage(Kp_Flag_Main* flag, const char* description) {
    flag->usage.description = description;

    size_t arg_description_size =  KP_FLAG_USAGE_SIZE + strlen(flag->big_flag) + strlen(flag->short_flag);
    flag->usage.arg_description = (char*) malloc(arg_description_size* sizeof(char));
    snprintf(flag->usage.arg_description, arg_description_size, "%s, %s\0", flag->short_flag, flag->big_flag);
}


void kp_usage_flag_main(Kp_Flag_Main* flag_main, FILE* stream) {
    fprintf(stream, "    %s\n\t\t%s\n", flag_main->usage.arg_description, flag_main->usage.description);
}


void kp_dk_flag(Kp_Flag_Main* flag) {
    free(flag->big_flag);
    free(flag->short_flag);
    kp_dk_usage(&flag->usage);
}



/********************************************************************************


Kp_Arg: A required arg which maybe optional bruh


********************************************************************************/
typedef struct {
    const char* result;     /* malloc */

    Kp_Usage usage;
} Kp_Arg;


/* make Kp_Arg usage*/
void kp_mk_arg_usage(Kp_Arg* arg, const char* arg_name, const char* description) {
    arg->usage.arg_description = arg_name;
    arg->usage.description = description;
}


/* free Kp_Arg */
void kp_dk_arg(Kp_Arg* arg) {
    if (arg->result != NULL) {
        free(arg->result);
    }
}



/********************************************************************************


Kp_Flag: A optional flag (boolean)


********************************************************************************/
typedef struct {
    Kp_Flag_Main* flag;
    bool result;    
} Kp_Flag;



/********************************************************************************


Kp_Optional_Arg: A optional flag which has types (requires a value)


********************************************************************************/
typedef struct {
    Kp_Flag_Main* flag;
    const char* result; /* malloc */
} Kp_Optional_Arg;



/********************************************************************************


Kp


********************************************************************************/
typedef struct {
    const char* project_name;
    const char* binary_name;
    const char* version;

    const char* description;
} Kp_Init;

typedef struct {
    Kp_Init* kp_init;

    /*Positional Args*/
    Kp_Arg** args;
    size_t args_count;
    size_t curr_args_count;
    

    /*Boolean flags*/
    Kp_Flag** flags;
    size_t flag_count;
    size_t curr_flag_count;


    /*Optional args*/
    Kp_Optional_Arg** optional_args;
    size_t optional_args_count;
    size_t curr_optional_args_count;
} Kp;


/* Args */
/* Prints usage of Args in Kp instance to stream */
void kp_usage_args(Kp* kp, FILE* stream) {
    int i = 0;
    for(; i < kp->args_count; ++i) {
        fprintf(stream, "     %s\n\t%s\n", kp->args[i]->usage.arg_description, kp->args[i]->usage.description);
    }
}


/* Flags */
/* Prints usage of flags in Kp instance to stream */
void kp_usage_flags(Kp* kp, FILE* stream) {
    int i = 0;
    for(; i < kp->flag_count; ++i) {
        kp_usage_flag_main(kp->flags[i]->flag, stream);
    }
}


/* Optional Args */
/* Prints usage of optional args in Kp instance to stream */
void kp_usage_optional_args(Kp* kp, FILE* stream) {
    int i = 0;
    for(; i < kp->optional_args_count; ++i) {
        kp_usage_flag_main(kp->optional_args[i]->flag, stream);
    }
}


/* Main usage function */
void kp_usage(Kp* kp, FILE* stream) {
    if (kp->args_count != 0) {
        fprintf(stream, "USAGE:\n\t%s", kp->kp_init->binary_name);
        int x;
        for(x = 0; x < kp->args_count; ++x) {
            char* _x = kp->args[x]->usage.arg_description;
            /*_kp_string_uppercase(_x, strlen(_x)); [> START HERE <]*/
            fprintf(stream, " %s", _x);
        }

        fprintf(stream, " [--flags...] [--optional_args...]\n");
    } else {
        fprintf(stream, "\nUSAGE:\n\t%s [--flags...] [--optional_args...]\n", kp->kp_init->binary_name);
    }

    if (kp->args_count != 0) {
        fprintf(stream, "\nPOSITIONAL ARGS:\n");
        kp_usage_args(kp, stream);
    }

    if (kp->optional_args_count != 0) {
        fprintf(stream, "\nOPTIONAL ARGS:\n");
        kp_usage_optional_args(kp, stream);
    }

    fprintf(stream, "\nFLAGS:\n");
    if (kp->flag_count != 0) {
        kp_usage_flags(kp, stream);
    }
    fprintf(stream, "    %s, %s\n\t\t%s\n", "-h", "--help", "prints help message");
}


/* This prints help message containing project name, version, description and options details */
void kp_usage_big(Kp* kp, FILE* stream) {
    fprintf(stream, "%s %s\n", kp->kp_init->project_name, kp->kp_init->version);
    if (kp->kp_init->description != NULL) {
        fprintf(stream, "\nDESCRIPTION:\n\t%s\n", kp->kp_init->description);
    }
    
    kp_usage(kp, stream);
}


/* Exit if flag is a help flag*/
int kp_check_help_and_exit(Kp* kp, const char* flag) {
    if (KP_STRCMP(flag, "-h")) {
        kp_usage(kp, stdout);
        exit(0);
    } else if (KP_STRCMP(flag, "--help")) {
        kp_usage_big(kp, stdout);
        exit(0);
    }
    return -1;
}



/********************************************************************************


Kp parse


********************************************************************************/
typedef enum {
    kp_parse_type_parse_arg,
    kp_parse_type_parse_flag,
    kp_parse_type_parse_optional_arg,

    /*Flag types errors*/
    kp_parse_type_invaild_no_args,
    kp_parse_type_invaild_args,
    kp_parse_type_invaild_type,
} kp_parse_type;


/* Parse boolean flags */
kp_parse_type kp_parse_flags(Kp* kp, char** args_begin, char** args_end) {
    assert(kp->curr_flag_count == kp->flag_count);

    char** args_next = args_begin + 1;

    int i = 0;
    for(; i < kp->flag_count; ++i) {
        if (KP_STRCMP(*args_begin, (kp->flags[i])->flag->big_flag) || KP_STRCMP(*args_begin, (kp->flags[i])->flag->short_flag)) {
            KP_TOGGLE_BOOLEAN(kp->flags[i]->result);
            return kp_parse_type_parse_flag;
        } 

        /* Check help flag */
        kp_check_help_and_exit(kp, *args_begin);
    }

    if (args_next != args_end) {
        return kp_parse_type_parse_optional_arg;
    }

    return kp_parse_type_parse_optional_arg; /* Check in optional flags */
}


/* Parse optional args */
kp_parse_type kp_parse_optional_args(Kp* kp, char** args_begin, char** args_end) {
    assert(kp->curr_optional_args_count == kp->optional_args_count);

    char** args_next = args_begin + 1;

    int i = 0;
    for(; i < kp->optional_args_count; ++i) {
        if (KP_STRCMP(*args_begin, (kp->optional_args[i])->flag->big_flag) || KP_STRCMP(*args_begin, (kp->optional_args[i])->flag->short_flag)) {
            if (args_next == args_end) {
                return kp_parse_type_invaild_no_args;
            } else {
                /*Checks if the next arg is not a flag if yes take that value as a result else fail*/
                if (*args_next[0] != '-') {
                    kp->optional_args[i]->result = KP_DEEP_COPY(*args_next, strlen(*args_next));
                    return kp_parse_type_parse_flag;
                } else {
                    return kp_parse_type_invaild_args;
                }
            }
        }
    }

    return kp_parse_type_invaild_type;
}



/********************************************************************************


Kp main public functions


********************************************************************************/
  
/* Initializes Kp that handles the parsing and stuff*/
void kp_mk(Kp* kp, Kp_Init* kp_init, size_t args_count, size_t flag_count, size_t optional_args_count) {
    kp->kp_init = kp_init;

    /*Positional Args*/
    kp->args_count = args_count;
    kp->curr_args_count = 0;
    kp->args = (Kp_Arg**) malloc(kp->args_count * sizeof(Kp_Arg*));

    /*Flags*/
    kp->flag_count = flag_count;
    kp->curr_flag_count = 0;
    kp->flags = (Kp_Flag**) malloc(kp->flag_count * sizeof(Kp_Flag*));

    /*Optional args*/
    kp->optional_args_count = optional_args_count;
    kp->curr_optional_args_count = 0;
    kp->optional_args = (Kp_Optional_Arg**) malloc(kp->optional_args_count * sizeof(Kp_Optional_Arg*));
}


/* free Kp */
void kp_free(Kp* kp) {
    /*Positional Args*/
    int k = 0;
    for(; k < kp->args_count; ++k) {
        kp_dk_arg(kp->args[k]);
        free(kp->args[k]);
    }
    free(kp->args);

    /*Flags*/
    int i = 0;
    for(; i < kp->flag_count; ++i) {
        kp_dk_flag(kp->flags[i]->flag);
        free(kp->flags[i]->flag);
        free(kp->flags[i]);
    }
    free(kp->flags);

    /*Optional args*/
    int j = 0;
    for(; j < kp->optional_args_count; ++j) {
        kp_dk_flag(kp->optional_args[j]->flag);
        free(kp->optional_args[j]->flag);
        if (kp->optional_args[j]->result != NULL) {
            free(kp->optional_args[j]->result);
        }
        free(kp->optional_args[j]);
    }
    free(kp->optional_args);
}


/* Initialize Kp_Arg, would be used by the usr */
Kp_Arg* kp_arg(Kp* kp, const char* arg_name, const char* description) {
    Kp_Arg* arg = (Kp_Arg*) malloc(1 * sizeof(Kp_Arg));
    /*mk_arg();*/
    kp_mk_arg_usage(arg, arg_name, description);

    arg->result = NULL;

    assert(kp->curr_args_count != kp->args_count);
    kp->args[kp->curr_args_count++] = arg;
}


/* Initializes Kp_Flag boolean like a swtich */
Kp_Flag* kp_flag(Kp* kp, const bool default_bool, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag_Main* flag_main = (Kp_Flag_Main*) malloc(1 * sizeof(Kp_Flag_Main));
    kp__mk_flag(flag_main, big_flag, short_flag);
    kp__mk_flag_usage(flag_main, description);

    Kp_Flag* flag = (Kp_Flag*) malloc(1 * sizeof(Kp_Flag));
    flag->flag = flag_main;
    flag->result = default_bool;
        
    assert(kp->curr_flag_count != kp->flag_count);
    kp->flags[kp->curr_flag_count++] = flag;
    return flag;
}


/* Initialize Kp_Optional_Arg which requires a argument right now its just string*/
Kp_Optional_Arg* kp_optional_arg(Kp* kp, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag_Main* flag_main = (Kp_Flag_Main*) malloc(1 * sizeof(Kp_Flag_Main));
    kp__mk_flag(flag_main, big_flag, short_flag);
    kp__mk_flag_usage(flag_main, description);

    Kp_Optional_Arg* optional_arg = (Kp_Optional_Arg*) malloc(1 * sizeof(Kp_Flag));
    optional_arg->flag = flag_main;
    optional_arg->result = NULL;

    assert(kp->curr_optional_args_count != kp->optional_args_count);
    kp->optional_args[kp->curr_optional_args_count++] = optional_arg;

    return optional_arg;
}


/* This is does the parsing */
void kp_parse(Kp* kp, char** argv, int argc) {
    assert(kp->curr_flag_count == kp->curr_flag_count);
    assert(kp->curr_optional_args_count == kp->optional_args_count);


    char** args_begin = argv + 1;
    char** args_end = argv + argc;
    
    /* Parse Positional Args */
    if (kp->args_count != 0) {
        if (argc < 2) {
            fprintf(stderr, "ERROR: missing args\n");
            kp_usage(kp, stderr);
            exit(1);
        }
    }

    int x;
    for(x = 0; x < kp->args_count; ++x) {
        if (args_begin != args_end) {
            if (*args_begin[0] == '-') {
                if (kp_check_help_and_exit(kp, *args_begin) < 0) {
                    fprintf(stderr, "INVAILD: arg %s\n", *args_begin);
                    exit(1);
                }
            }
        }
        kp->args[x]->result = KP_DEEP_COPY(*args_begin, strlen(*args_begin));
        args_begin++;
    }

    /* Parse flags and optional args */
    while(args_begin != args_end) {
        kp_parse_type flag_status = kp_parse_flags(kp, args_begin, args_end);

        switch (flag_status) {
            case kp_parse_type_parse_flag:
                goto CONTINUE_PARSE;
                break;

            case kp_parse_type_parse_optional_arg: 
                {
                    kp_parse_type optional_arg_status = kp_parse_optional_args(kp, args_begin, args_end);
                    switch (optional_arg_status) { 
                        case kp_parse_type_parse_flag:
                            args_begin++;
                            goto CONTINUE_PARSE;
                        case kp_parse_type_invaild_args:
                            fprintf(stderr, "INVAILD: %s requires args\n", *args_begin);
                            exit(1);
                        case kp_parse_type_invaild_no_args:
                            fprintf(stderr, "INVAILD: NO ARGS GIVEN: %s requires args\n", *args_begin);
                            exit(1);
                        case kp_parse_type_invaild_type:
                            fprintf(stderr, "INVAILD: WTF is %s bastard\n", *args_begin);
                            exit(1);
                        default:
                            fprintf(stderr, "??? %s\n", *args_begin);
                    }
                }
                break;

            case kp_parse_type_invaild_type:
                fprintf(stderr, "INVAILD: WTF is %s bastard\n", *args_begin);
                exit(1);
                break;

            default:
                fprintf(stderr, "??? %s\n", *args_begin);
        }

CONTINUE_PARSE:
        args_begin++;
    }
}

#endif

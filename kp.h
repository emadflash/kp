#ifndef __KP_H__
#define __KP_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

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
const char* kp_strdup(char* dest, size_t size) {
    size_t _size = size + 1;
    char* ret = (char*) malloc(_size* sizeof(char));
    memcpy(ret, dest, _size);
    ret[_size - 1] = '\0';
    return ret;
}


/********************************************************************************
  Kp_Flag_Usage struct, it is used by Kp_Flag, Kp_Arg

    arg_description: is the formatting used for a particular instance defined
    using mk_usage function
    
    description: General usage of a flag
********************************************************************************/
typedef struct {
    char* arg_description;
    char* arg_type;

    char* description;
} Kp_Flag_Usage;


void kp_dk_usage(Kp_Flag_Usage* usage) {
    free(usage->arg_description);
}



/********************************************************************************


Kp_Type: supported types for flags


********************************************************************************/
typedef enum {
    kp_type_string,
    kp_type_uint8,
    kp_type_bool,
} kp_type;


const char* kp_type_to_string(kp_type type) {
#define KP_TYPE_TO_STRING(X, Y)\
    case X:\
        return Y

    switch (type) {
        KP_TYPE_TO_STRING(kp_type_string, "STRING");
        KP_TYPE_TO_STRING(kp_type_uint8, "UINT8");
        KP_TYPE_TO_STRING(kp_type_bool, "BOOL");
    }
    return "???";
}



/********************************************************************************


Kp_Flag


********************************************************************************/
typedef struct {
    char* big_flag;
    char* short_flag;

    kp_type type;
    bool is_positional;
    Kp_Flag_Usage usage;

    bool result_bool;
    char* result_string;
    uint8_t result_int;
} Kp_Flag;


/*Replaces underscores with dashes and returns count of segments*/
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

void kp__mk_big_flag(Kp_Flag* flag, const char* big_flag, size_t big_flag_size) {
    assert(big_flag[0] != '-' && "big flag must not start with -");
    snprintf(flag->big_flag, big_flag_size, "--%s", big_flag);

    size_t i=0;
    for(; i < big_flag_size; ++i) {
        if (flag->big_flag[i] == '_') {
            flag->big_flag[i] = '-';
        }
    }
}

void kp__mk_short_flag(Kp_Flag* flag, const char* short_flag, size_t short_flag_size) {
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
        snprintf(flag->short_flag, short_flag_size,  "-%s", short_flag);
    }
}

void kp__mk_flag(Kp_Flag* flag, const char* big_flag, const char* short_flag) {
    size_t big_flag_size = 0;
    size_t short_flag_size = 0;
    kp__flag_get_size_for_flags(big_flag, short_flag, &big_flag_size, &short_flag_size);

    flag->big_flag = (char*) malloc(big_flag_size * sizeof(char));
    flag->short_flag = (char*) malloc(short_flag_size * sizeof(char));

    kp__mk_big_flag(flag, big_flag, big_flag_size);
    kp__mk_short_flag(flag, short_flag, short_flag_size);
}


#define KP_FLAG_USAGE_EXTRA_SIZE 6

void kp__mk_flag_usage(Kp_Flag* flag, kp_type flag_type, const char* description) {
    flag->usage.description = description;
    flag->usage.arg_type = kp_type_to_string(flag_type);

    size_t arg_description_size =  KP_FLAG_USAGE_EXTRA_SIZE + strlen(flag->usage.arg_type) + strlen(flag->big_flag) + strlen(flag->short_flag);
    flag->usage.arg_description = (char*) malloc(arg_description_size* sizeof(char));
    snprintf(flag->usage.arg_description, arg_description_size, "%s, %s [%s]", flag->short_flag, flag->big_flag, flag->usage.arg_type);
}

void kp_dk_flag(Kp_Flag* flag, bool is_free_string) {
    free(flag->big_flag);
    free(flag->short_flag);
    if (is_free_string) free(flag->result_string);
    kp_dk_usage(&flag->usage);
}



/********************************************************************************


KP


********************************************************************************/
typedef struct {
    const char* project_name;
    const char* binary_name;
    const char* version;

    const char* description;
} Kp_Init;


typedef struct {
    Kp_Init* kp_init;

    /*Args*/
    Kp_Flag** args;
    size_t args_count;
    size_t curr_args_count;
    
    /*Optionals*/
    Kp_Flag** flags;
    size_t flags_count;
    size_t curr_flags_count;
} Kp;


#define kp__usage(X, Y, Z)\
    for(int i = 0; i < Y; ++i) {\
        fprintf(Z, "\t%s\n\t\t%s\n\n", (X)[i]->usage.arg_description, (X)[i]->usage.description);\
    }

#define kp_usage_args(X, Y) kp__usage((X)->args, (X)->args_count, Y);
#define kp_usage_flags(X, Y) kp__usage((X)->flags, (X)->flags_count, Y);

void kp_usage(Kp* kp, FILE* stream) {
    assert(kp->curr_args_count == kp->args_count && "kp: Flags count must equivalent to total flags supplied"); 
    assert(kp->curr_flags_count == kp->flags_count && "kp: Flags count must equivalent to total flags supplied"); 
    fprintf(stream, "USAGE:\n\t%s [ARGS...] [OPTIONS...]\n", kp->kp_init->binary_name);

    if (kp->args_count > 0) {
        fprintf(stream, "\nARGS:\n");
        kp_usage_args(kp, stream);
    }

    fprintf(stream, "OPTIONS:\n");
    kp_usage_flags(kp, stream);
    fprintf(stream, "\t%s, %s\n\t\t%s\n", "-h", "--help [BOOL]", "show help");
}

/* This prints help message containing project name, version, description and options details */
void kp_usage_big(Kp* kp, FILE* stream) {
    fprintf(stream, "%s %s\n", kp->kp_init->project_name, kp->kp_init->version);
    if (kp->kp_init->description != NULL) {
        fprintf(stream, "\nDESCRIPTION:\n\t%s\n\n", kp->kp_init->description);
    }
    
    kp_usage(kp, stream);
}



/********************************************************************************


KP MAIN PUBLIC FUNCTIONS


********************************************************************************/
void kp_mk(Kp* kp, Kp_Init* kp_init, size_t args_count, size_t flags_count) {
    kp->kp_init = kp_init;

    kp->args_count = args_count;
    kp->curr_args_count = 0;

    kp->flags_count = flags_count;
    kp->curr_flags_count = 0;

#define kp_mk__allocate(X, Y)\
    if (Y > 0) {\
        X = (Kp_Flag**) malloc(Y * sizeof(Kp_Flag*));\
    }

#define kp_mk_allocate_args(X) kp_mk__allocate(X->args, X->args_count)
#define kp_mk_allocate_flags(X) kp_mk__allocate(X->flags, X->flags_count)

    kp_mk_allocate_args(kp);
    kp_mk_allocate_flags(kp);
}

#define kp__free_flag(X) kp_dk_flag((X)[i], false);
#define kp__free_panic_flag(X) kp_dk_flag((X)[i], true);

#define kp__free(X, Y, Z)\
    if (Y > 0) {\
        for(int i=0; i < Y; ++i) {\
            Z(X);\
            free((X)[i]);\
        }\
        free(X);\
    }

#define kp_free_args(X) kp__free((X)->args, (X)->args_count, kp__free_flag)
#define kp_free_flags(X) kp__free((X)->flags, (X)->flags_count, kp__free_flag)

#define kp_free_panic_args(X) kp__free((X)->args, (X)->args_count, kp__free_panic_flag)
#define kp_free_panic_flags(X) kp__free((X)->flags, (X)->flags_count, kp__free_panic_flag)

#define kp_free(X)\
    kp_free_args(X);\
    kp_free_flags(X)

#define kp_free_panic(X)\
    kp_free_panic_args(X);\
    kp_free_panic_flags(X)\

#define kp__flag_init(T, W, X, Y, Z)\
    T = (Kp_Flag*) malloc(sizeof(Kp_Flag));\
    T->type = W;\
    kp__mk_flag(T, X, Y);\
    kp__mk_flag_usage(T, W, Z);\
\
    T->result_int = 0;\
    T->result_string = NULL;\
    T->result_int = false;


Kp_Flag* kp_flag(Kp* kp, kp_type flag_type, const char* big_flag, const char* short_flag, const char* description) {
    assert(kp->curr_flags_count != kp->flags_count);
    kp__flag_init(kp->flags[kp->curr_flags_count], flag_type, big_flag, short_flag, description);
    return kp->flags[kp->curr_flags_count++];
}

Kp_Flag* kp_arg(Kp* kp, kp_type flag_type, const char* big_flag, const char* short_flag, const char* description) {
    assert(kp->curr_args_count != kp->args_count);
    kp__flag_init(kp->args[kp->curr_args_count], flag_type, big_flag, short_flag, description);
    return kp->args[kp->curr_args_count++];
}

bool* kp_flag_bool(Kp* kp, bool default_bool, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_flag(kp, kp_type_bool, big_flag, short_flag, description);
    flag->result_bool = default_bool;
    return &flag->result_bool;
}

bool* kp_arg_bool(Kp* kp, bool default_bool, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_arg(kp, kp_type_bool, big_flag, short_flag, description);
    flag->result_bool = default_bool;
    flag->is_positional = true;
    return &flag->result_bool;
}

char** kp_flag_string(Kp* kp, const char* default_string, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_flag(kp, kp_type_string, big_flag, short_flag, description);

    if (default_string != NULL) flag->result_string = kp_strdup(default_string, strlen(default_string));
    return &flag->result_string;
}

char** kp_arg_string(Kp* kp, const char* default_string, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_arg(kp, kp_type_string, big_flag, short_flag, description);
    flag->is_positional = true;

    if (default_string != NULL) flag->result_string = kp_strdup(default_string, strlen(default_string));
    return &flag->result_string;
}

uint8_t* kp_flag_uint8(Kp* kp, uint8_t default_int, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_flag(kp, kp_type_uint8, big_flag, short_flag, description);
    if (default_int != 0) flag->result_int = default_int;
    return &flag->result_int;
}

uint8_t* kp_arg_uint8(Kp* kp, uint8_t default_int, const char* big_flag, const char* short_flag, const char* description) {
    Kp_Flag* flag = kp_arg(kp, kp_type_uint8, big_flag, short_flag, description);
    flag->is_positional = true;
    if (default_int != 0) flag->result_int = default_int;
    return &flag->result_int;
}



/********************************************************************************


KP PARSE


********************************************************************************/
#define kp_parse_error(X, ...)\
    fprintf(stderr, "%s: ", (X)->kp_init->binary_name);\
    fprintf(stderr, __VA_ARGS__)

#define KP_PRINT_ARGUMENT_REQUIRED(X, Y, Z)\
    kp_parse_error(X, "Argument required: %s [%s]\n", Z, (Y)->usage.arg_type)

#define KP_NEXT(X) X + 1

#define KP_MAX_STRING_SIZE 255
#define KP_MAX_INT_SIZE 255

#define kp_parse_check_help(X, Y)\
    if (KP_STRCMP(Y, "-h")) {\
        kp_usage(X, stdout);\
        kp_free_panic(X);\
        exit(0);\
    } else if (KP_STRCMP(Y, "--help")) {\
        kp_usage_big(X, stdout);\
        kp_free_panic(X);\
        exit(0);\
    }

bool kp_parse_check_string_size(const char* arg, size_t max_len) {
    size_t curr_size = 0;
    while(arg[curr_size++] != '\0') {
        if (curr_size > max_len) return false;
    }
    return true;
}

Kp_Flag* kp_parse_check_flag(Kp* kp, char* args_curr) {
#define kp_parse_check_in(X, Y, Z)\
    for(int i = 0; i < Y; ++i) {\
        if (KP_STRCMP((Z), (X)[i]->big_flag) || KP_STRCMP((Z), (X)[i]->short_flag)) {\
            return (X)[i];\
        }\
    }

#define kp_parse_check_in_flags(X, Y) kp_parse_check_in((X)->flags, (X)->flags_count, Y)
#define kp_parse_check_in_args(X, Y) kp_parse_check_in((X)->args, (X)->args_count, Y)

    /* Cache it ??*/
    kp_parse_check_in_flags(kp, args_curr);
    kp_parse_check_in_args(kp, args_curr);

    return NULL;
}

void kp_parse(Kp* kp, char** argv, int argc) {
    assert(kp->curr_flags_count == kp->curr_flags_count);

    char** args_begin = argv + 1;
    char** args_end = argv + argc;

    char** args_next = NULL;

    while(args_begin != args_end) {
        args_next = KP_NEXT(args_begin);

        kp_parse_check_help(kp, *args_begin);

        Kp_Flag* flag;
        if ((flag = kp_parse_check_flag(kp, *args_begin)) != NULL) {
            switch (flag->type) {
                case kp_type_bool:
                    KP_TOGGLE_BOOLEAN(flag->result_bool);
                    goto CONTINUE_PARSE;

                case kp_type_string:
                    if (args_next != args_end && *args_next[0] != '-') {
                        if (! kp_parse_check_string_size(*args_next, KP_MAX_STRING_SIZE)) {
                            kp_parse_error(kp, "ERROR: overflowing max buffer size\n");
                            kp_free_panic(kp);
                            exit(1);
                        }

                        if (flag->result_string != NULL) free(flag->result_string);
                        flag->result_string = kp_strdup(*args_next, strlen(*args_next));
                        args_begin++;
                        goto CONTINUE_PARSE;
                    } else {
                        KP_PRINT_ARGUMENT_REQUIRED(kp, flag, *args_begin);
                        exit(1);
                    }

                case kp_type_uint8:
                    if (args_next != args_end) { 
                        if (kp_parse_check_string_size(*args_next, 3)) {
                            uint8_t _result_int = atoi(*args_next);
                            if (_result_int > INT_MAX) {
                                kp_parse_error(kp, "ERROR: 8-bit integer required\n");
                                kp_free_panic(kp);
                                exit(1);
                            }
                            flag->result_int = _result_int;
                            args_begin++;
                            goto CONTINUE_PARSE;
                        } else {
                            kp_parse_error(kp, "ERROR: 8-bit integer required\n");
                            kp_free_panic(kp);
                            exit(1);
                        }
                    } else {
                        KP_PRINT_ARGUMENT_REQUIRED(kp, flag, *args_begin);
                        kp_free_panic(kp);
                        exit(1);
                    }
            }
        } else {
            kp_parse_error(kp, "ERROR: Invaild option \"%s\"\n", *args_begin);
            kp_free_panic(kp);
            exit(1);
        }

    CONTINUE_PARSE:
            args_begin++;
    }
}

#endif

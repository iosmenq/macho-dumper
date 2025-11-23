/*
* macho.h
* Coded by iosmen (c) 2025
*/
#ifndef MACHO_H
#define MACHO_H

#include "utils.h"
#include "load_commands.h"
#include "disasm.h"
#include "csblob.h"
#include "swift.h"
#include "entitlements.h"
#include "tree.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// Mach-O context structure
typedef struct {
    void* data;
    size_t size;
    int is_64bit;
    int is_swap;
    int is_fat;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    struct load_command** load_commands;
} macho_ctx_t;

// Function prototypes
macho_error_t parse_macho(macho_ctx_t* ctx, const char* filename);
void print_header_info(const macho_ctx_t* ctx);
void free_macho_context(macho_ctx_t* ctx);
macho_error_t parse_fat_binary(macho_ctx_t* ctx, const char* filename);


#endif // MACHO_H


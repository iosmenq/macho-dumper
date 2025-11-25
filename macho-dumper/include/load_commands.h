/*
* load_commands.h
* Coded by iosmen (c) 2025
*/
#ifndef LOAD_COMMANDS_H
#define LOAD_COMMANDS_H

#include "utils.h"
#include <mach-o/loader.h>
#include <stdint.h>

#ifndef LC_ENTITLEMENTS
#define LC_ENTITLEMENTS 0x00000005
#endif

#ifndef VM_PROT_T_DEFINED
#define VM_PROT_T_DEFINED
typedef int vm_prot_t;
#endif

// Load command types
typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    void* data;
} load_command_t;

// Segment and section information
typedef struct {
    char segname[16];
    char sectname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
} section_info_t;

typedef struct {
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;
    uint32_t flags;
    section_info_t* sections;
} segment_info_t;

// Function prototypes
macho_error_t parse_load_commands(macho_ctx_t* ctx);
void print_load_commands(const macho_ctx_t* ctx);
macho_error_t parse_segment_commands(macho_ctx_t* ctx, segment_info_t** segments, uint32_t* nsegments);
void free_segments(segment_info_t* segments, uint32_t nsegments);

#endif // LOAD_COMMANDS_H

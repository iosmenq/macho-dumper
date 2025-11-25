/*
* swift.h
* Coded by iosmen (c) 2025
*/
#ifndef SWIFT_H
#define SWIFT_H

#include "utils.h"
#include <mach-o/loader.h>
#include "macho.h"           // macho_ctx_t
#include "load_commands.h"   // segment_info_t ve parse_segment_commands
#include "csblob.h"          // CS_SuperBlob ve CS_BlobIndex

#include <string.h>
#include <stdlib.h>

// Swift metadata struct
typedef struct {
    uint32_t version;
    uint32_t flags;
    void* data;
    uint32_t size;
    uint32_t type_descriptor_offset;
    uint32_t protocol_conformance_offset;
    uint32_t method_descriptor_offset;
} swift_metadata_t;

// Function prototypes
macho_error_t find_swift_metadata(const macho_ctx_t* ctx, swift_metadata_t* metadata);
void print_swift_metadata(const swift_metadata_t* metadata);

#endif // SWIFT_H

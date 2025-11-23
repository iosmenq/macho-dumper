/*
* csblob.h
* Codded by iosmen (c) 2025
*/
#ifndef CSBLOB_H
#define CSBLOB_H

#include "utils.h"
#include <mach-o/loader.h>

// Code Signature structures
typedef struct __BlobIndex {
    uint32_t type;
    uint32_t offset;
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct __CodeDirectory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    // Variable data follows
} CS_CodeDirectory;

// Function prototypes
macho_error_t parse_code_signature(const macho_ctx_t* ctx);
macho_error_t find_code_signature(const macho_ctx_t* ctx, uint32_t* offset, uint32_t* size);
void print_code_signature_info(const CS_SuperBlob* superblob);


#endif // CSBLOB_H

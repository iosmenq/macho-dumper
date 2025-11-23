/*
* csblob.c
* Coded by iosmen (c) 2025
*/
#include "../include/csblob.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Code signature magic numbers
#define CSMAGIC_CODEDIRECTORY 0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171

// Find code signature in Mach-O file
macho_error_t find_code_signature(const macho_ctx_t* ctx, uint32_t* offset, uint32_t* size) {
    if (!ctx || !offset || !size) return ERROR_READ_FAILED;
    
    *offset = 0;
    *size = 0;
    
    // Search for LC_CODE_SIGNATURE load command
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        
        if (cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
            *offset = ctx->is_swap ? swap32(cs_cmd->dataoff) : cs_cmd->dataoff;
            *size = ctx->is_swap ? swap32(cs_cmd->datasize) : cs_cmd->datasize;
            
            if (*offset + *size > ctx->size) {
                return ERROR_NO_CODE_SIGNATURE;
            }
            
            return SUCCESS;
        }
    }
    
    return ERROR_NO_CODE_SIGNATURE;
}

// Parse code signature blob
macho_error_t parse_code_signature(const macho_ctx_t* ctx) {
    if (!ctx || !ctx->data) return ERROR_READ_FAILED;
    
    uint32_t cs_offset, cs_size;
    macho_error_t err = find_code_signature(ctx, &cs_offset, &cs_size);
    if (err != SUCCESS) {
        printf("Code Signature: Not found\n");
        return err;
    }
    
    printf("Code Signature:\n");
    printf("  Offset: 0x%x\n", cs_offset);
    printf("  Size: %u bytes\n", cs_size);
    
    // Parse SuperBlob structure
    CS_SuperBlob* superblob = (CS_SuperBlob*)((char*)ctx->data + cs_offset);
    
    // Check magic
    uint32_t magic = ctx->is_swap ? swap32(superblob->magic) : superblob->magic;
    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) {
        printf("  Error: Invalid code signature magic (0x%x)\n", magic);
        return ERROR_NO_CODE_SIGNATURE;
    }
    
    uint32_t length = ctx->is_swap ? swap32(superblob->length) : superblob->length;
    uint32_t count = ctx->is_swap ? swap32(superblob->count) : superblob->count;
    
    printf("  SuperBlob Length: %u\n", length);
    printf("  Number of Blobs: %u\n", count);
    
    // Parse each blob in the SuperBlob
    for (uint32_t i = 0; i < count; i++) {
        CS_BlobIndex* index = &superblob->index[i];
        uint32_t blob_type = ctx->is_swap ? swap32(index->type) : index->type;
        uint32_t blob_offset = ctx->is_swap ? swap32(index->offset) : index->offset;
        
        // Get blob header
        struct __Blob {
            uint32_t magic;
            uint32_t length;
        } *blob = (struct __Blob*)((char*)superblob + blob_offset);
        
        uint32_t blob_magic = ctx->is_swap ? swap32(blob->magic) : blob->magic;
        uint32_t blob_length = ctx->is_swap ? swap32(blob->length) : blob->length;
        
        const char* type_name = "UNKNOWN";
        switch (blob_type) {
            case 0: type_name = "Code Directory"; break;
            case 1: type_name = "Info Slots"; break;
            case 2: type_name = "Requirements"; break;
            case 3: type_name = "Resource Directory"; break;
            case 4: type_name = "Application Specific"; break;
            case 5: type_name = "Entitlements"; break;
            default: type_name = "Unknown"; break;
        }
        
        printf("  Blob %u:\n", i);
        printf("    Type: %s (%d)\n", type_name, blob_type);
        printf("    Offset: 0x%x\n", blob_offset);
        printf("    Magic: 0x%x\n", blob_magic);
        printf("    Length: %u\n", blob_length);
        
        // Parse Code Directory if present
        if (blob_type == 0 && blob_magic == CSMAGIC_CODEDIRECTORY) {
            CS_CodeDirectory* cd = (CS_CodeDirectory*)blob;
            uint32_t version = ctx->is_swap ? swap32(cd->version) : cd->version;
            uint32_t flags = ctx->is_swap ? swap32(cd->flags) : cd->flags;
            uint32_t hashOffset = ctx->is_swap ? swap32(cd->hashOffset) : cd->hashOffset;
            uint32_t identOffset = ctx->is_swap ? swap32(cd->identOffset) : cd->identOffset;
            uint32_t nSpecialSlots = ctx->is_swap ? swap32(cd->nSpecialSlots) : cd->nSpecialSlots;
            uint32_t nCodeSlots = ctx->is_swap ? swap32(cd->nCodeSlots) : cd->nCodeSlots;
            uint32_t codeLimit = ctx->is_swap ? swap32(cd->codeLimit) : cd->codeLimit;
            uint8_t hashSize = cd->hashSize;
            uint8_t hashType = cd->hashType;
            
            const char* identifier = (const char*)cd + identOffset;
            
            printf("    Code Directory:\n");
            printf("      Version: %u\n", version);
            printf("      Flags: 0x%x\n", flags);
            printf("      Hash Offset: 0x%x\n", hashOffset);
            printf("      Identifier: %s\n", identifier);
            printf("      Special Slots: %u\n", nSpecialSlots);
            printf("      Code Slots: %u\n", nCodeSlots);
            printf("      Code Limit: 0x%x\n", codeLimit);
            printf("      Hash Size: %u\n", hashSize);
            printf("      Hash Type: %u\n", hashType);
        }
        
        // Parse entitlements blob if present
        if (blob_type == 5 && blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS) {
            printf("    Entitlements Blob Found\n");
            // Entitlements parsing is handled in entitlements.c
        }
    }
    
    return SUCCESS;
}

// Print code signature information
void print_code_signature_info(const CS_SuperBlob* superblob) {
    if (!superblob) return;
    // Implementation for detailed code signature info

}

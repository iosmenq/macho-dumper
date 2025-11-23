/*
* entitlements.c
* Coded by iosmen (c) 2025
*/
#include "../include/entitlements.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

// Find entitlements in code signature
macho_error_t find_entitlements_blob(const macho_ctx_t* ctx, uint32_t* offset, uint32_t* size) {
    if (!ctx || !offset || !size) return ERROR_READ_FAILED;
    
    uint32_t cs_offset, cs_size;
    macho_error_t err = find_code_signature(ctx, &cs_offset, &cs_size);
    if (err != SUCCESS) {
        return err;
    }
    
    // Parse SuperBlob to find entitlements
    CS_SuperBlob* superblob = (CS_SuperBlob*)((char*)ctx->data + cs_offset);
    uint32_t count = ctx->is_swap ? swap32(superblob->count) : superblob->count;
    
    for (uint32_t i = 0; i < count; i++) {
        CS_BlobIndex* index = &superblob->index[i];
        uint32_t blob_type = ctx->is_swap ? swap32(index->type) : index->type;
        uint32_t blob_offset = ctx->is_swap ? swap32(index->offset) : index->offset;
        
        if (blob_type == 5) { // Entitlements blob type
            struct __Blob {
                uint32_t magic;
                uint32_t length;
            } *blob = (struct __Blob*)((char*)superblob + blob_offset);
            
            uint32_t blob_magic = ctx->is_swap ? swap32(blob->magic) : blob->magic;
            if (blob_magic == 0xfade7171) { // CSMAGIC_EMBEDDED_ENTITLEMENTS
                *offset = cs_offset + blob_offset + 8; // Skip magic and length
                *size = (ctx->is_swap ? swap32(blob->length) : blob->length) - 8;
                return SUCCESS;
            }
        }
    }
    
    return ERROR_NO_CODE_SIGNATURE;
}

// Parse entitlements from Mach-O file
macho_error_t parse_entitlements(const macho_ctx_t* ctx, entitlements_t** entitlements) {
    if (!ctx || !entitlements) return ERROR_READ_FAILED;
    
    uint32_t entitlements_offset, entitlements_size;
    macho_error_t err = find_entitlements_blob(ctx, &entitlements_offset, &entitlements_size);
    if (err != SUCCESS) {
        printf("Entitlements: Not found\n");
        return err;
    }
    
    printf("Entitlements found at offset 0x%x, size: %u bytes\n", 
           entitlements_offset, entitlements_size);
    
    // Allocate entitlements structure
    *entitlements = calloc(1, sizeof(entitlements_t));
    if (!*entitlements) {
        return ERROR_READ_FAILED;
    }
    
    // Extract entitlements data (this is a simplified version)
    // In a full implementation, you would parse the plist data here
    char* entitlements_data = (char*)ctx->data + entitlements_offset;
    
    // For demonstration, we'll just show the raw data exists
    printf("Entitlements data (first 100 bytes):\n");
    for (uint32_t i = 0; i < entitlements_size && i < 100; i++) {
        printf("%c", entitlements_data[i]);
    }
    printf("\n");
    
    // Note: Full plist parsing would require libplist or similar
    // This is a simplified implementation
    
    return SUCCESS;
}

// Print entitlements information
void print_entitlements(const entitlements_t* entitlements) {
    if (!entitlements || !entitlements->head) {
        printf("No entitlements found\n");
        return;
    }
    
    printf("Entitlements (%u):\n", entitlements->count);
    
    entitlement_t* current = entitlements->head;
    while (current) {
        printf("  %s: %s\n", current->key, current->value);
        current = current->next;
    }
}

// Free entitlements memory
void free_entitlements(entitlements_t* entitlements) {
    if (!entitlements) return;
    
    entitlement_t* current = entitlements->head;
    while (current) {
        entitlement_t* next = current->next;
        if (current->key) free(current->key);
        if (current->value) free(current->value);
        free(current);
        current = next;
    }
    
    free(entitlements);

}

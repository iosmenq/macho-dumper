/*
* macho.c
* Coded by iosmen (c) 2025
*/
#include "../include/macho.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Parse Mach-O or FAT binary
macho_error_t parse_macho(macho_ctx_t* ctx, const char* filename) {
    if (!ctx || !filename) return ERROR_READ_FAILED;
    
    memset(ctx, 0, sizeof(macho_ctx_t));
    
    // Read file into memory
    ctx->data = read_file(filename, &ctx->size);
    if (!ctx->data) return ERROR_FILE_NOT_FOUND;
    
    // Check magic number
    uint32_t magic = *(uint32_t*)ctx->data;
    if (!validate_magic(magic)) {
        free_file(ctx->data);
        return ERROR_INVALID_MAGIC;
    }
    
    // Handle FAT binaries
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        ctx->is_fat = 1;
        // For simplicity, we'll use the first architecture in FAT binary
        struct fat_header* fat_header = (struct fat_header*)ctx->data;
        struct fat_arch* arch = (struct fat_arch*)(fat_header + 1);
        
        if (magic == FAT_CIGAM) {
            arch->offset = swap32(arch->offset);
            arch->size = swap32(arch->size);
            arch->cputype = swap32(arch->cputype);
        }
        
        // Use the first architecture
        void* macho_data = (char*)ctx->data + arch->offset;
        size_t macho_size = arch->size;
        
        // Create a new context for the thin binary
        void* thin_data = malloc(macho_size);
        if (!thin_data) {
            free_file(ctx->data);
            return ERROR_READ_FAILED;
        }
        memcpy(thin_data, macho_data, macho_size);
        
        free_file(ctx->data);
        ctx->data = thin_data;
        ctx->size = macho_size;
        ctx->is_fat = 0;
        
        // Re-check magic for the thin binary
        magic = *(uint32_t*)ctx->data;
    }
    
    // Determine architecture and endianness
    ctx->is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    ctx->is_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    
    // Parse Mach-O header
    if (ctx->is_64bit) {
        struct mach_header_64* header = (struct mach_header_64*)ctx->data;
        ctx->cputype = ctx->is_swap ? swap32(header->cputype) : header->cputype;
        ctx->cpusubtype = ctx->is_swap ? swap32(header->cpusubtype) : header->cpusubtype;
        ctx->filetype = ctx->is_swap ? swap32(header->filetype) : header->filetype;
        ctx->ncmds = ctx->is_swap ? swap32(header->ncmds) : header->ncmds;
        ctx->sizeofcmds = ctx->is_swap ? swap32(header->sizeofcmds) : header->sizeofcmds;
        ctx->flags = ctx->is_swap ? swap32(header->flags) : header->flags;
    } else {
        struct mach_header* header = (struct mach_header*)ctx->data;
        ctx->cputype = ctx->is_swap ? swap32(header->cputype) : header->cputype;
        ctx->cpusubtype = ctx->is_swap ? swap32(header->cpusubtype) : header->cpusubtype;
        ctx->filetype = ctx->is_swap ? swap32(header->filetype) : header->filetype;
        ctx->ncmds = ctx->is_swap ? swap32(header->ncmds) : header->ncmds;
        ctx->sizeofcmds = ctx->is_swap ? swap32(header->sizeofcmds) : header->sizeofcmds;
        ctx->flags = ctx->is_swap ? swap32(header->flags) : header->flags;
    }
    
    // Parse load commands
    return parse_load_commands(ctx);
}

// Print Mach-O header information
void print_header_info(const macho_ctx_t* ctx) {
    if (!ctx) return;
    
    printf("Mach-O Header Information:\n");
    printf("  Architecture: %s\n", ctx->is_64bit ? "64-bit" : "32-bit");
    printf("  CPU Type: 0x%x\n", ctx->cputype);
    printf("  CPU Subtype: 0x%x\n", ctx->cpusubtype);
    printf("  File Type: 0x%x\n", ctx->filetype);
    printf("  Number of Load Commands: %u\n", ctx->ncmds);
    printf("  Size of Load Commands: %u\n", ctx->sizeofcmds);
    printf("  Flags: 0x%x\n", ctx->flags);
    printf("  FAT Binary: %s\n", ctx->is_fat ? "Yes" : "No");
    printf("  Byte Swap: %s\n", ctx->is_swap ? "Yes" : "No");
}

// Free Mach-O context
void free_macho_context(macho_ctx_t* ctx) {
    if (!ctx) return;
    
    if (ctx->data) {
        free_file(ctx->data);
    }
    
    if (ctx->load_commands) {
        for (uint32_t i = 0; i < ctx->ncmds; i++) {
            if (ctx->load_commands[i]) {
                free(ctx->load_commands[i]);
            }
        }
        free(ctx->load_commands);
    }

}


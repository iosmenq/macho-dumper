/*
* load_commands.c
* Codded by iosmen (c) 2025
*/
#include "../include/load_commands.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Parse load commands from Mach-O file
macho_error_t parse_load_commands(macho_ctx_t* ctx) {
    if (!ctx || !ctx->data) return ERROR_READ_FAILED;
    
    // Allocate array for load commands
    ctx->load_commands = calloc(ctx->ncmds, sizeof(struct load_command*));
    if (!ctx->load_commands) return ERROR_READ_FAILED;
    
    // Calculate load commands offset
    uintptr_t offset = ctx->is_64bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    uintptr_t end_offset = offset + ctx->sizeofcmds;
    
    if (end_offset > ctx->size) {
        free(ctx->load_commands);
        return ERROR_INVALID_SEGMENT;
    }
    
    // Parse each load command
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        if (offset + sizeof(struct load_command) > ctx->size) {
            break;
        }
        
        struct load_command* lc = (struct load_command*)((char*)ctx->data + offset);
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        uint32_t cmdsize = ctx->is_swap ? swap32(lc->cmdsize) : lc->cmdsize;
        
        if (cmdsize < sizeof(struct load_command) || offset + cmdsize > ctx->size) {
            break;
        }
        
        // Copy load command data
        ctx->load_commands[i] = malloc(cmdsize);
        if (!ctx->load_commands[i]) {
            // Cleanup on failure
            for (uint32_t j = 0; j < i; j++) {
                free(ctx->load_commands[j]);
            }
            free(ctx->load_commands);
            return ERROR_READ_FAILED;
        }
        memcpy(ctx->load_commands[i], lc, cmdsize);
        
        offset += cmdsize;
    }
    
    return SUCCESS;
}

// Print load command information
void print_load_commands(const macho_ctx_t* ctx) {
    if (!ctx || !ctx->load_commands) return;
    
    printf("Load Commands:\n");
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        uint32_t cmdsize = ctx->is_swap ? swap32(lc->cmdsize) : lc->cmdsize;
        
        const char* cmd_name = "UNKNOWN";
        switch (cmd) {
            case LC_SEGMENT: cmd_name = "LC_SEGMENT"; break;
            case LC_SEGMENT_64: cmd_name = "LC_SEGMENT_64"; break;
            case LC_SYMTAB: cmd_name = "LC_SYMTAB"; break;
            case LC_DYSYMTAB: cmd_name = "LC_DYSYMTAB"; break;
            case LC_LOAD_DYLIB: cmd_name = "LC_LOAD_DYLIB"; break;
            case LC_CODE_SIGNATURE: cmd_name = "LC_CODE_SIGNATURE"; break;
            case LC_ENTITLEMENTS: cmd_name = "LC_ENTITLEMENTS"; break;
        }
        
        printf("  Command %u: %s (0x%x), Size: %u\n", i, cmd_name, cmd, cmdsize);
    }
}

// Parse segment commands
macho_error_t parse_segment_commands(macho_ctx_t* ctx, segment_info_t** segments, uint32_t* nsegments) {
    if (!ctx || !segments || !nsegments) return ERROR_READ_FAILED;
    
    *segments = NULL;
    *nsegments = 0;
    
    // First pass: count segments
    uint32_t seg_count = 0;
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            seg_count++;
        }
    }
    
    if (seg_count == 0) return SUCCESS;
    
    // Allocate segments array
    *segments = calloc(seg_count, sizeof(segment_info_t));
    if (!*segments) return ERROR_READ_FAILED;
    
    // Second pass: parse segments
    uint32_t seg_index = 0;
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        
        if (cmd == LC_SEGMENT) {
            struct segment_command* seg = (struct segment_command*)lc;
            segment_info_t* info = &(*segments)[seg_index];
            
            strncpy(info->segname, seg->segname, 16);
            info->vmaddr = ctx->is_swap ? swap32(seg->vmaddr) : seg->vmaddr;
            info->vmsize = ctx->is_swap ? swap32(seg->vmsize) : seg->vmsize;
            info->fileoff = ctx->is_swap ? swap32(seg->fileoff) : seg->fileoff;
            info->filesize = ctx->is_swap ? swap32(seg->filesize) : seg->filesize;
            info->maxprot = ctx->is_swap ? swap32(seg->maxprot) : seg->maxprot;
            info->initprot = ctx->is_swap ? swap32(seg->initprot) : seg->initprot;
            info->nsects = ctx->is_swap ? swap32(seg->nsects) : seg->nsects;
            info->flags = ctx->is_swap ? swap32(seg->flags) : seg->flags;
            
            // Parse sections if any
            if (info->nsects > 0) {
                info->sections = calloc(info->nsects, sizeof(section_info_t));
                if (!info->sections) {
                    free_segments(*segments, seg_index);
                    return ERROR_READ_FAILED;
                }
                
                struct section* sections = (struct section*)(seg + 1);
                for (uint32_t j = 0; j < info->nsects; j++) {
                    section_info_t* sinfo = &info->sections[j];
                    strncpy(sinfo->segname, sections[j].segname, 16);
                    strncpy(sinfo->sectname, sections[j].sectname, 16);
                    sinfo->addr = ctx->is_swap ? swap32(sections[j].addr) : sections[j].addr;
                    sinfo->size = ctx->is_swap ? swap32(sections[j].size) : sections[j].size;
                    sinfo->offset = ctx->is_swap ? swap32(sections[j].offset) : sections[j].offset;
                    sinfo->align = ctx->is_swap ? swap32(sections[j].align) : sections[j].align;
                    sinfo->reloff = ctx->is_swap ? swap32(sections[j].reloff) : sections[j].reloff;
                    sinfo->nreloc = ctx->is_swap ? swap32(sections[j].nreloc) : sections[j].nreloc;
                    sinfo->flags = ctx->is_swap ? swap32(sections[j].flags) : sections[j].flags;
                }
            }
            
            seg_index++;
        }
        else if (cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            segment_info_t* info = &(*segments)[seg_index];
            
            strncpy(info->segname, seg->segname, 16);
            info->vmaddr = ctx->is_swap ? swap64(seg->vmaddr) : seg->vmaddr;
            info->vmsize = ctx->is_swap ? swap64(seg->vmsize) : seg->vmsize;
            info->fileoff = ctx->is_swap ? swap64(seg->fileoff) : seg->fileoff;
            info->filesize = ctx->is_swap ? swap64(seg->filesize) : seg->filesize;
            info->maxprot = ctx->is_swap ? swap32(seg->maxprot) : seg->maxprot;
            info->initprot = ctx->is_swap ? swap32(seg->initprot) : seg->initprot;
            info->nsects = ctx->is_swap ? swap32(seg->nsects) : seg->nsects;
            info->flags = ctx->is_swap ? swap32(seg->flags) : seg->flags;
            
            // Parse sections if any
            if (info->nsects > 0) {
                info->sections = calloc(info->nsects, sizeof(section_info_t));
                if (!info->sections) {
                    free_segments(*segments, seg_index);
                    return ERROR_READ_FAILED;
                }
                
                struct section_64* sections = (struct section_64*)(seg + 1);
                for (uint32_t j = 0; j < info->nsects; j++) {
                    section_info_t* sinfo = &info->sections[j];
                    strncpy(sinfo->segname, sections[j].segname, 16);
                    strncpy(sinfo->sectname, sections[j].sectname, 16);
                    sinfo->addr = ctx->is_swap ? swap64(sections[j].addr) : sections[j].addr;
                    sinfo->size = ctx->is_swap ? swap64(sections[j].size) : sections[j].size;
                    sinfo->offset = ctx->is_swap ? swap32(sections[j].offset) : sections[j].offset;
                    sinfo->align = ctx->is_swap ? swap32(sections[j].align) : sections[j].align;
                    sinfo->reloff = ctx->is_swap ? swap32(sections[j].reloff) : sections[j].reloff;
                    sinfo->nreloc = ctx->is_swap ? swap32(sections[j].nreloc) : sections[j].nreloc;
                    sinfo->flags = ctx->is_swap ? swap32(sections[j].flags) : sections[j].flags;
                }
            }
            
            seg_index++;
        }
    }
    
    *nsegments = seg_count;
    return SUCCESS;
}

// Free segments memory
void free_segments(segment_info_t* segments, uint32_t nsegments) {
    if (!segments) return;
    
    for (uint32_t i = 0; i < nsegments; i++) {
        if (segments[i].sections) {
            free(segments[i].sections);
        }
    }
    free(segments);

}


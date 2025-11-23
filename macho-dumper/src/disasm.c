/*
* disasm.c
* Coded by iosmen (c) 2025
*/
#include "../include/disasm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Initialize Capstone disassembler
macho_error_t init_disassembler(disasm_ctx_t* ctx, cs_arch arch, cs_mode mode) {
    if (!ctx) return ERROR_DISASM_FAILED;
    
    cs_err err = cs_open(arch, mode, &ctx->handle);
    if (err != CS_ERR_OK) {
        debug_print("Failed to initialize Capstone: %s\n", cs_strerror(err));
        return ERROR_DISASM_FAILED;
    }
    
    // Enable detailed mode
    cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    ctx->base_address = 0;
    ctx->code_size = 0;
    ctx->code = NULL;
    
    debug_print("Capstone disassembler initialized successfully\n");
    return SUCCESS;
}

// Free disassembler resources
void free_disassembler(disasm_ctx_t* ctx) {
    if (!ctx) return;
    
    if (ctx->handle) {
        cs_close(&ctx->handle);
    }
    
    if (ctx->code) {
        free(ctx->code);
        ctx->code = NULL;
    }
    
    ctx->base_address = 0;
    ctx->code_size = 0;
}

// Find __text section in Mach-O file
macho_error_t find_text_section(const macho_ctx_t* ctx, uint8_t** code, 
                               size_t* size, uint64_t* address) {
    if (!ctx || !code || !size || !address) return ERROR_DISASM_FAILED;
    
    segment_info_t* segments = NULL;
    uint32_t nsegments = 0;
    macho_error_t err = parse_segment_commands(ctx, &segments, &nsegments);
    if (err != SUCCESS) {
        return err;
    }
    
    // Search for __TEXT segment and __text section
    for (uint32_t i = 0; i < nsegments; i++) {
        if (strcmp(segments[i].segname, "__TEXT") == 0) {
            for (uint32_t j = 0; j < segments[i].nsects; j++) {
                if (strcmp(segments[i].sections[j].sectname, "__text") == 0) {
                    section_info_t* text_section = &segments[i].sections[j];
                    
                    // Validate section data
                    if (text_section->offset + text_section->size > ctx->size) {
                        free_segments(segments, nsegments);
                        return ERROR_INVALID_SECTION;
                    }
                    
                    // Allocate memory for code copy
                    *code = malloc(text_section->size);
                    if (!*code) {
                        free_segments(segments, nsegments);
                        return ERROR_READ_FAILED;
                    }
                    
                    // Copy code data
                    memcpy(*code, (char*)ctx->data + text_section->offset, text_section->size);
                    *size = text_section->size;
                    *address = text_section->addr;
                    
                    free_segments(segments, nsegments);
                    return SUCCESS;
                }
            }
        }
    }
    
    free_segments(segments, nsegments);
    return ERROR_INVALID_SECTION;
}

// Disassemble a specific section
macho_error_t disassemble_section(disasm_ctx_t* ctx, const char* section_name, 
                                 const uint8_t* code, size_t size, uint64_t address) {
    if (!ctx || !ctx->handle || !code || size == 0) return ERROR_DISASM_FAILED;
    
    printf("Disassembly of %s section (address: 0x%llx, size: %zu bytes):\n", 
           section_name, address, size);
    printf("--------------------------------------------------------------------------------\n");
    
    // Disassemble the code
    cs_insn* insn = cs_malloc(ctx->handle);
    if (!insn) {
        return ERROR_DISASM_FAILED;
    }
    
    size_t code_size = size;
    const uint8_t* code_ptr = code;
    uint64_t current_addr = address;
    size_t count = 0;
    const size_t max_instructions = 100; // Limit output for large sections
    
    while (code_size > 0 && count < max_instructions) {
        // Disassemble one instruction at a time
        if (!cs_disasm_iter(ctx->handle, &code_ptr, &code_size, &current_addr, insn)) {
            break;
        }
        
        // Print instruction
        printf("  0x%llx: ", insn->address);
        
        // Print bytes (up to 8 bytes)
        for (size_t j = 0; j < 8; j++) {
            if (j < insn->size) {
                printf("%02x ", insn->bytes[j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" %-8s %s\n", insn->mnemonic, insn->op_str);
        count++;
    }
    
    if (code_size > 0 && count >= max_instructions) {
        printf("  [Disassembly truncated after %zu instructions]\n", max_instructions);
    }
    
    cs_free(insn, 1);
    printf("--------------------------------------------------------------------------------\n");
    printf("Total instructions disassembled: %zu\n", count);
    
    return SUCCESS;
}

// Disassemble ARM64 code from Mach-O file
macho_error_t disassemble_macho_arm64(const macho_ctx_t* ctx) {
    if (!ctx) return ERROR_DISASM_FAILED;
    
    // Check if this is ARM64 architecture
    if (ctx->cputype != CPU_TYPE_ARM64) {
        printf("Not an ARM64 binary (CPU type: 0x%x)\n", ctx->cputype);
        return ERROR_DISASM_FAILED;
    }
    
    disasm_ctx_t disasm_ctx;
    macho_error_t err = init_disassembler(&disasm_ctx, CS_ARCH_ARM64, CS_MODE_ARM);
    if (err != SUCCESS) {
        return err;
    }
    
    // Find and disassemble __text section
    uint8_t* code = NULL;
    size_t code_size = 0;
    uint64_t code_addr = 0;
    
    err = find_text_section(ctx, &code, &code_size, &code_addr);
    if (err == SUCCESS) {
        disassemble_section(&disasm_ctx, "__text", code, code_size, code_addr);
        free(code);
    } else {
        printf("Could not find __text section for disassembly\n");
    }
    
    free_disassembler(&disasm_ctx);
    return err;

}



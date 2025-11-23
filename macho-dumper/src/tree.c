/*
* tree.c
* Coded by iosmen (c) 2025
*/
#include "../include/tree.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Find dynamic library dependencies
macho_error_t find_dylib_dependencies(const macho_ctx_t* ctx, char*** dylibs, uint32_t* count) {
    if (!ctx || !dylibs || !count) return ERROR_READ_FAILED;
    
    *dylibs = NULL;
    *count = 0;
    
    // First pass: count dylib commands
    uint32_t dylib_count = 0;
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || 
            cmd == LC_REEXPORT_DYLIB || cmd == LC_LAZY_LOAD_DYLIB) {
            dylib_count++;
        }
    }
    
    if (dylib_count == 0) {
        return SUCCESS;
    }
    
    // Allocate array for dylib names
    *dylibs = calloc(dylib_count, sizeof(char*));
    if (!*dylibs) {
        return ERROR_READ_FAILED;
    }
    
    // Second pass: extract dylib names
    uint32_t index = 0;
    for (uint32_t i = 0; i < ctx->ncmds; i++) {
        struct load_command* lc = ctx->load_commands[i];
        if (!lc) continue;
        
        uint32_t cmd = ctx->is_swap ? swap32(lc->cmd) : lc->cmd;
        if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || 
            cmd == LC_REEXPORT_DYLIB || cmd == LC_LAZY_LOAD_DYLIB) {
            
            struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
            uint32_t name_offset = ctx->is_swap ? swap32(dylib_cmd->dylib.name.offset) : dylib_cmd->dylib.name.offset;
            
            if (name_offset >= sizeof(struct dylib_command)) {
                char* name = (char*)dylib_cmd + name_offset;
                
                // Validate string length
                size_t max_len = (char*)lc + dylib_cmd->cmdsize - name;
                size_t name_len = strnlen(name, max_len);
                
                if (name_len < max_len) {
                    (*dylibs)[index] = strdup(name);
                    index++;
                }
            }
        }
    }
    
    *count = index;
    return SUCCESS;
}

// Build dependency tree (simplified version)
macho_error_t build_dependency_tree(const macho_ctx_t* ctx, dylib_node_t** root) {
    if (!ctx || !root) return ERROR_READ_FAILED;
    
    char** dylibs = NULL;
    uint32_t dylib_count = 0;
    macho_error_t err = find_dylib_dependencies(ctx, &dylibs, &dylib_count);
    if (err != SUCCESS) {
        return err;
    }
    
    // Create root node (the main binary)
    *root = calloc(1, sizeof(dylib_node_t));
    if (!*root) {
        for (uint32_t i = 0; i < dylib_count; i++) {
            free(dylibs[i]);
        }
        free(dylibs);
        return ERROR_READ_FAILED;
    }
    
    (*root)->name = strdup("Main Binary");
    (*root)->path = NULL;
    (*root)->dependencies = calloc(dylib_count, sizeof(dylib_node_t*));
    (*root)->dep_count = dylib_count;
    
    // Create dependency nodes (simplified - no recursive loading)
    for (uint32_t i = 0; i < dylib_count; i++) {
        dylib_node_t* dep = calloc(1, sizeof(dylib_node_t));
        if (dep) {
            dep->name = strdup(dylibs[i]);
            dep->path = strdup(dylibs[i]); // In real implementation, resolve path
            dep->dependencies = NULL;
            dep->dep_count = 0;
            (*root)->dependencies[i] = dep;
        }
        free(dylibs[i]);
    }
    
    free(dylibs);
    return SUCCESS;
}

// Print dependency tree with indentation
void print_dependency_tree(const dylib_node_t* node, int depth) {
    if (!node) return;
    
    // Create indentation
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
    
    printf("└─ %s", node->name);
    if (node->path && strcmp(node->name, node->path) != 0) {
        printf(" (%s)", node->path);
    }
    printf("\n");
    
    // Print dependencies
    for (uint32_t i = 0; i < node->dep_count; i++) {
        print_dependency_tree(node->dependencies[i], depth + 1);
    }
}

// Free dependency tree memory
void free_dependency_tree(dylib_node_t* node) {
    if (!node) return;
    
    if (node->name) free(node->name);
    if (node->path) free(node->path);
    
    for (uint32_t i = 0; i < node->dep_count; i++) {
        free_dependency_tree(node->dependencies[i]);
    }
    
    if (node->dependencies) {
        free(node->dependencies);
    }
    
    free(node);

}


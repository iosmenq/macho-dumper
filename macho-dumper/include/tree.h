/*
* tree.h
* Coded by iosmen (c) 2025
*/
#ifndef TREE_H
#define TREE_H

#include "utils.h"

// Dependency tree node
typedef struct dylib_node {
    char* name;
    char* path;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
    struct dylib_node** dependencies;
    uint32_t dep_count;
} dylib_node_t;

// Function prototypes
macho_error_t build_dependency_tree(const macho_ctx_t* ctx, dylib_node_t** root);
void print_dependency_tree(const dylib_node_t* node, int depth);
void free_dependency_tree(dylib_node_t* node);
macho_error_t find_dylib_dependencies(const macho_ctx_t* ctx, char*** dylibs, uint32_t* count);


#endif // TREE_H


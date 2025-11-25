/*
* entitlements.h
* Coded by iosmen (c) 2025
*/
#ifndef ENTITLEMENTS_H
#define ENTITLEMENTS_H

#include "utils.h"
#include "macho.h"

// Entitlements structure
typedef struct entitlement {
    char* key;
    char* value;
    struct entitlement* next;
} entitlement_t;

typedef struct {
    entitlement_t* head;
    uint32_t count;
} entitlements_t;

// Function prototypes
macho_error_t parse_entitlements(const macho_ctx_t* ctx, entitlements_t** entitlements);
void print_entitlements(const entitlements_t* entitlements);
void free_entitlements(entitlements_t* entitlements);

#endif // ENTITLEMENTS_H

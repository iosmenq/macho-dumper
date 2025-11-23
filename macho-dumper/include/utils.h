#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdio.h>

typedef enum {
    SUCCESS = 0,
    ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_MAGIC,
    ERROR_READ_FAILED,
    ERROR_INVALID_SEGMENT,
    ERROR_INVALID_SECTION,
    ERROR_NO_CODE_SIGNATURE,
    ERROR_INVALID_SWIFT_DATA,
    ERROR_DISASM_FAILED
} macho_error_t;

void* read_file(const char* filename, size_t* size);
void free_file(void* data);
int validate_magic(uint32_t magic);

uint32_t swap32(uint32_t value);
uint64_t swap64(uint64_t value);

const char* macho_strerror(macho_error_t error);

#ifdef DEBUG
#define debug_print(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...)
#endif

#endif // UTILS_H
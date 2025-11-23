/*
* utils.c
* Codded by iosmen (c) 2025
*/
#include "../include/utils.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

// Read file into memory with error handling
void* read_file(const char* filename, size_t* size) {
    if (!filename || !size) return NULL;
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        debug_print("Failed to open file: %s\n", strerror(errno));
        return NULL;
    }
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        debug_print("Failed to stat file: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }
    
    if (st.st_size == 0) {
        debug_print("File is empty\n");
        close(fd);
        return NULL;
    }
    
    void* data = malloc(st.st_size);
    if (!data) {
        debug_print("Memory allocation failed\n");
        close(fd);
        return NULL;
    }
    
    ssize_t bytes_read = read(fd, data, st.st_size);
    if (bytes_read != st.st_size) {
        debug_print("Read incomplete: %zd/%lld bytes\n", bytes_read, st.st_size);
        free(data);
        close(fd);
        return NULL;
    }
    
    close(fd);
    *size = st.st_size;
    debug_print("Successfully read %zu bytes from %s\n", *size, filename);
    return data;
}

// Free file data
void free_file(void* data) {
    free(data);
}

// Validate Mach-O magic number
int validate_magic(uint32_t magic) {
    switch (magic) {
        case MH_MAGIC:
        case MH_CIGAM:
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        case FAT_MAGIC:
        case FAT_CIGAM:
            return 1;
        default:
            return 0;
    }
}

// Byte swapping functions
uint32_t swap32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x000000FF) << 24);
}

uint64_t swap64(uint64_t value) {
    return ((value & 0xFF00000000000000ULL) >> 56) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x00000000000000FFULL) << 56);
}

// Get CPU type name
const char* get_cpu_type_name(cpu_type_t cputype) {
    switch (cputype) {
        case CPU_TYPE_ANY: return "ANY";
        case CPU_TYPE_VAX: return "VAX";
        case CPU_TYPE_MC680x0: return "MC680x0";
        case CPU_TYPE_X86: return "X86";
        case CPU_TYPE_X86_64: return "X86_64";
        case CPU_TYPE_MC98000: return "MC98000";
        case CPU_TYPE_HPPA: return "HPPA";
        case CPU_TYPE_ARM: return "ARM";
        case CPU_TYPE_ARM64: return "ARM64";
        case CPU_TYPE_ARM64_32: return "ARM64_32";
        case CPU_TYPE_MC88000: return "MC88000";
        case CPU_TYPE_SPARC: return "SPARC";
        case CPU_TYPE_I860: return "I860";
        case CPU_TYPE_POWERPC: return "POWERPC";
        case CPU_TYPE_POWERPC64: return "POWERPC64";
        default: return "UNKNOWN";
    }
}

// Get file type name
const char* get_file_type_name(uint32_t filetype) {
    switch (filetype) {
        case MH_OBJECT: return "OBJECT";
        case MH_EXECUTE: return "EXECUTE";
        case MH_FVMLIB: return "FVMLIB";
        case MH_CORE: return "CORE";
        case MH_PRELOAD: return "PRELOAD";
        case MH_DYLIB: return "DYLIB";
        case MH_DYLINKER: return "DYLINKER";
        case MH_BUNDLE: return "BUNDLE";
        case MH_DYLIB_STUB: return "DYLIB_STUB";
        case MH_DSYM: return "DSYM";
        case MH_KEXT_BUNDLE: return "KEXT_BUNDLE";
        default: return "UNKNOWN";
    }
}

// Convert error code to string
const char* macho_strerror(macho_error_t error) {
    switch (error) {
        case SUCCESS: return "Success";
        case ERROR_FILE_NOT_FOUND: return "File not found or cannot be accessed";
        case ERROR_INVALID_MAGIC: return "Invalid Mach-O magic number";
        case ERROR_READ_FAILED: return "File read operation failed";
        case ERROR_INVALID_SEGMENT: return "Invalid segment data";
        case ERROR_INVALID_SECTION: return "Invalid section data";
        case ERROR_NO_CODE_SIGNATURE: return "No code signature found";
        case ERROR_INVALID_SWIFT_DATA: return "Invalid Swift metadata";
        case ERROR_DISASM_FAILED: return "Disassembly failed";
        default: return "Unknown error";
    }
}

// Safe memory copy with bounds checking
void* safe_memcpy(void* dest, const void* src, size_t n, const void* base, size_t total_size) {
    if (!dest || !src || !base) return NULL;
    
    uintptr_t dest_addr = (uintptr_t)dest;
    uintptr_t src_addr = (uintptr_t)src;
    uintptr_t base_addr = (uintptr_t)base;
    
    // Check if source and destination are within bounds
    if (src_addr < base_addr || src_addr + n > base_addr + total_size) {
        return NULL;
    }
    if (dest_addr < base_addr || dest_addr + n > base_addr + total_size) {
        return NULL;
    }
    
    return memcpy(dest, src, n);
}

// Calculate padding
size_t calculate_padding(size_t offset, size_t alignment) {
    if (alignment == 0) return 0;
    return (alignment - (offset % alignment)) % alignment;

}

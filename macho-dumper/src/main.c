/*
* main.c
* Coded by iosmen (c) 2025
*/
#include "../include/macho.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Print usage information
void print_usage(const char* program_name) {
    printf("Usage: %s <macho_file> [options]\n", program_name);
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -l, --load-cmds     Show load commands\n");
    printf("  -s, --segments      Show segment information\n");
    printf("  -d, --dependencies  Show library dependencies\n");
    printf("  -c, --codesign      Show code signature information\n");
    printf("  -e, --entitlements  Show entitlements\n");
    printf("  -a, --all           Show all information\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Check for help
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    const char* filename = argv[1];
    int show_all = 0;
    int show_load_cmds = 0;
    int show_segments = 0;
    int show_deps = 0;
    int show_codesign = 0;
    int show_entitlements = 0;

    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            show_all = 1;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--load-cmds") == 0) {
            show_load_cmds = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--segments") == 0) {
            show_segments = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dependencies") == 0) {
            show_deps = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--codesign") == 0) {
            show_codesign = 1;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--entitlements") == 0) {
            show_entitlements = 1;
        }
    }

    // If no specific options, show all
    if (argc == 2) {
        show_all = 1;
    }

    macho_ctx_t ctx = {0};
    macho_error_t err = parse_macho(&ctx, filename);
    
    if (err != SUCCESS) {
        printf("Error: %s\n", macho_strerror(err));
        return 1;
    }

    printf("=== Mach-O Analyzer ===\n");
    printf("File: %s\n\n", filename);
    
    // Always show header
    print_header_info(&ctx);
    printf("\n");

    // Show requested information
    if (show_all || show_load_cmds) {
        print_load_commands(&ctx);
        printf("\n");
    }

    if (show_all || show_segments) {
        segment_info_t* segments = NULL;
        uint32_t nsegments = 0;
        if (parse_segment_commands(&ctx, &segments, &nsegments) == SUCCESS) {
            printf("Segments: %u\n", nsegments);
            for (uint32_t i = 0; i < nsegments; i++) {
                printf("  %s: vmaddr=0x%llx, vmsize=0x%llx, fileoff=0x%llx, filesize=0x%llx\n",
                       segments[i].segname, segments[i].vmaddr, segments[i].vmsize,
                       segments[i].fileoff, segments[i].filesize);
            }
            free_segments(segments, nsegments);
            printf("\n");
        }
    }

    if (show_all || show_deps) {
        char** dylibs = NULL;
        uint32_t dylib_count = 0;
        if (find_dylib_dependencies(&ctx, &dylibs, &dylib_count) == SUCCESS) {
            printf("Dependencies: %u\n", dylib_count);
            for (uint32_t i = 0; i < dylib_count; i++) {
                printf("  %s\n", dylibs[i]);
                free(dylibs[i]);
            }
            free(dylibs);
            printf("\n");
        }
    }

    if (show_all || show_codesign) {
        parse_code_signature(&ctx);
        printf("\n");
    }

    if (show_all || show_entitlements) {
        entitlements_t* entitlements = NULL;
        if (parse_entitlements(&ctx, &entitlements) == SUCCESS) {
            print_entitlements(entitlements);
            free_entitlements(entitlements);
            printf("\n");
        }
    }

    free_macho_context(&ctx);
    return 0;

}


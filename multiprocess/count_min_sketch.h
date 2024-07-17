#ifndef COUNT_MIN_SKETCH_H
#define COUNT_MIN_SKETCH_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define WIDTH 256
#define DEPTH 4

typedef struct {
    uint32_t **table;
    uint32_t width;
    uint32_t depth;
} CountMinSketch;

void init_count_min_sketch(CountMinSketch *cms, uint32_t width, uint32_t depth) {
    cms->width = width;
    cms->depth = depth;
    cms->table = (uint32_t **)malloc(depth * sizeof(uint32_t *));
    for (uint32_t i = 0; i < depth; ++i) {
        cms->table[i] = (uint32_t *)malloc(width * sizeof(uint32_t));
        memset(cms->table[i], 0, width * sizeof(uint32_t));
    }
}

void update_count_min_sketch(CountMinSketch *cms, uint32_t key, const char *value) {
    for (uint32_t i = 0; i < cms->depth; ++i) {
        uint32_t hash = (key + i) % cms->width;
        cms->table[i][hash]++;
    }
}

void save_sketch_to_file(CountMinSketch *cms, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Failed to open sketch file: %s\n", filename);
        return;
    }

    for (uint32_t i = 0; i < cms->depth; ++i) {
        for (uint32_t j = 0; j < cms->width; ++j) {
            fprintf(file, "%u ", cms->table[i][j]);
        }
        fprintf(file, "\n");
    }

    fclose(file);
}

void destroy_count_min_sketch(CountMinSketch *cms) {
    for (uint32_t i = 0; i < cms->depth; ++i) {
        free(cms->table[i]);
    }
    free(cms->table);
}

#endif

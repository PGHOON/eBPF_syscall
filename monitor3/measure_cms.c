#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <time.h>
#include <limits.h>

#define MAX_FILES 256
#define HASH_SEED 1934

typedef struct {
    int **table;
    int width;
    int depth;
} CountMinSketch;

static FILE *csv_files[MAX_FILES];
static char csv_file_names[MAX_FILES][PATH_MAX];
static int file_count = 0;

unsigned int hash(const char *str, int seed, int width) {
    unsigned long hash = seed;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % width;
}

void initCMS(CountMinSketch *cms, int width, int depth) {
    cms->width = width;
    cms->depth = depth;
    cms->table = (int **)malloc(depth * sizeof(int *));
    for (int i = 0; i < depth; i++) {
        cms->table[i] = (int *)calloc(width, sizeof(int));
    }
}

void freeCMS(CountMinSketch *cms) {
    for (int i = 0; i < cms->depth; i++) {
        free(cms->table[i]);
    }
    free(cms->table);
}

void updateCMS(CountMinSketch *cms, const char *item) {
    for (int i = 0; i < cms->depth; i++) {
        int index = hash(item, HASH_SEED + i, cms->width);
        cms->table[i][index]++;
    }
}

int queryCMS(CountMinSketch *cms, const char *item) {
    int minCount = cms->table[0][hash(item, HASH_SEED, cms->width)];
    for (int i = 1; i < cms->depth; i++) {
        int index = hash(item, HASH_SEED + i, cms->width);
        if (cms->table[i][index] < minCount) {
            minCount = cms->table[i][index];
        }
    }
    return minCount;
}

void printCMS(CountMinSketch *cms) {
    printf("Count-Min Sketch Table:\n");
    for (int i = 0; i < cms->depth; i++) {
        for (int j = 0; j < cms->width; j++) {
            printf("%d ", cms->table[i][j]);
        }
        printf("\n");
    }
}

void saveCMSToCSV(CountMinSketch *cms, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    for (int i = 0; i < cms->depth; i++) {
        for (int j = 0; j < cms->width; j++) {
            fprintf(file, "%d", cms->table[i][j]);
            if (j < cms->width - 1) {
                fprintf(file, ",");
            }
        }
        fprintf(file, "\n");
    }

    fclose(file);
}

void processCSVFiles(CountMinSketch *cms, const char *directory) {
    struct dirent *entry;
    DIR *dp = opendir(directory);

    if (dp == NULL) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s", directory, entry->d_name);
            FILE *file = fopen(filepath, "r");
            if (file == NULL) {
                perror("fopen");
                continue;
            }

            char line[1024];
            while (fgets(line, sizeof(line), file)) {
                char *system_call = strtok(line, "\n");
                if (system_call != NULL) {
                    updateCMS(cms, system_call);
                }
            }
            fclose(file);
        }
    }

    closedir(dp);
}

void print_resource_usage(struct rusage *start, struct rusage *end, double total_time) {
    double user_time = (end->ru_utime.tv_sec - start->ru_utime.tv_sec) + 
                       (end->ru_utime.tv_usec - start->ru_utime.tv_usec) / 1e6;
    double sys_time = (end->ru_stime.tv_sec - start->ru_stime.tv_sec) + 
                      (end->ru_stime.tv_usec - start->ru_stime.tv_usec) / 1e6;

    double user_cpu_usage = (user_time / total_time) * 100.0;
    double sys_cpu_usage = (sys_time / total_time) * 100.0;

    printf("User CPU time used: %f seconds (%.2f%%)\n", user_time, user_cpu_usage);
    printf("System CPU time used: %f seconds (%.2f%%)\n", sys_time, sys_cpu_usage);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <W> <D>\n", argv[0]);
        return 1;
    }

    int W = atoi(argv[1]);
    int D = atoi(argv[2]);

    struct stat st = {0};
    if (stat("./dataset", &st) == -1) {
        mkdir("./dataset", 0777);
    }

	struct rusage usage_start, usage_end;
    clock_t clock_start, clock_end;

    getrusage(RUSAGE_SELF, &usage_start);
    clock_start = clock();

    CountMinSketch cms;
    initCMS(&cms, W, D);

    processCSVFiles(&cms, "./dataset");

    clock_end = clock();
    getrusage(RUSAGE_SELF, &usage_end);

    printCMS(&cms);
    
    if (stat("./dataset/cms", &st) == -1) {
        mkdir("./dataset/cms", 0777);
    }
    
    saveCMSToCSV(&cms, "./dataset/cms/sketch.csv");
    freeCMS(&cms);

    double time_spent = (double)(clock_end - clock_start) / CLOCKS_PER_SEC;
    printf("Total time spent: %f seconds\n", time_spent);

    print_resource_usage(&usage_start, &usage_end, time_spent);

	return 0;
}

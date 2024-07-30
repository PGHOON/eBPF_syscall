#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "monitor2.h"
#include "monitor2.skel.h"
#include "time.h"
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define COMMAND_LEN 16
#define MAX_FILES 256
#define HASH_SEED 1934

/*
TEST CODE
*/
typedef struct {
    char processName[16];
    float benign;
    float malware;
} ProcessRecord;

static FILE *csv_files[MAX_FILES];
static char csv_file_names[MAX_FILES][PATH_MAX];
static int file_count = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct data_t *m = data;
    char file_name[PATH_MAX];
    snprintf(file_name, sizeof(file_name), "dataset/%.256s.csv", m->command);

    FILE *csv_file = NULL;
    for (int i = 0; i < file_count; ++i) {
        if (strcmp(csv_file_names[i], file_name) == 0) {
            csv_file = csv_files[i];
            break;
        }
    }

    if (!csv_file) {
        if (file_count >= MAX_FILES) {
            fprintf(stderr, "Maximum number of files reached\n");
            return;
        }
        csv_file = fopen(file_name, "w");
        if (!csv_file) {
            //fprintf(stderr, "Failed to open file: %s\n", file_name);
            return;
        }
        strcpy(csv_file_names[file_count], file_name);
        csv_files[file_count++] = csv_file;
        fprintf(csv_file, "SYSTEM_CALL\n");
    }

    fprintf(csv_file, "%s\n", m->syscall);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz){}

unsigned int hash(const char *str, int seed, int width) {
    unsigned long hash = seed;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % width;
}

typedef struct {
    int **table;
    int width;
    int depth;
} CountMinSketch;

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

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <TIME> <W> <D>\n", argv[0]);
        return 1;
    }

    int TIME = atoi(argv[1]);
    int W = atoi(argv[2]);
    int D = atoi(argv[3]);

	printf("Collecting system calls...\n");
	int init = system("rm -f dataset/*.csv");
	if (init != 0) {
		printf("Fail to initialize CSV files\n");
		return 1;
	}

    struct stat st = {0};
    if (stat("./dataset", &st) == -1) {
        mkdir("./dataset", 0777);
    }

	time_t start_time, current_time = 0;
	time(&start_time);

    struct monitor2_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);
	
	skel = monitor2_bpf__open_opts(&opts);

	err = monitor2_bpf__load(skel);
	
	if (err) {
		printf("Failed to load BPF object\n");
		monitor2_bpf__destroy(skel);
		return 1;
	}

	// Attach the progams to the events
	err = monitor2_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		monitor2_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		monitor2_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			printf("Receive SIGINT: *Detection Cancled\n");
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		time(&current_time);
		if (difftime(current_time, start_time) >= TIME){
			err = 0;
			break;
		}
	}

    for (int i = 0; i < file_count; ++i) {
        if (csv_files[i]) {
            fclose(csv_files[i]);
        }
    }
	perf_buffer__free(pb);
	monitor2_bpf__destroy(skel);

	CountMinSketch cms;
    initCMS(&cms, W, D);

    processCSVFiles(&cms, "./dataset");

    printCMS(&cms);
    
    if (stat("./dataset/cms", &st) == -1) {
        mkdir("./dataset/cms", 0777);
    }
    
    saveCMSToCSV(&cms, "./dataset/cms/sketch.csv");
    freeCMS(&cms);

	return -err;
}

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "monitor4.h"
#include "monitor4.skel.h"
#include "time.h"
#include "string.h"
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define COMMAND_LEN 16
#define MAX_FILES 256

#define TIME 300
#define INTERVAL_T 10

/*
TEST CODE
*/
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

int main()
{
	printf("Collecting system calls...\n");
	int init = system("rm -f dataset/*");
	if (init != 0) {
		printf("Fail to initialize CSV files\n");
		return 1;
	}
    struct stat st = {0};
    if (stat("./dataset", &st) == -1) {
        mkdir("./dataset", 0777);
    }

	time_t start_time, current_time = 0, time_stamp = 0;
	time(&start_time);
    time_stamp = start_time;

    struct monitor4_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);
	
	skel = monitor4_bpf__open_opts(&opts);

	err = monitor4_bpf__load(skel);
	
	if (err) {
		printf("Failed to load BPF object\n");
		monitor4_bpf__destroy(skel);
		return 1;
	}

	// Attach the programs to the events
	err = monitor4_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		monitor4_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		monitor4_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			printf("Receive SIGINT: *Detection Canceled\n");
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		time(&current_time);
		if (difftime(current_time, time_stamp) >= INTERVAL_T) {
			for (int i = 0; i < file_count; ++i) {
                if (csv_files[i]) {
                    fprintf(csv_files[i], "TIMESTAMP\n");
                }
            }
			time_stamp = current_time;
		}
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
	monitor4_bpf__destroy(skel);

	return -err;
}


#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "dcars.h"
#include "dcars.skel.h"
#include "time.h"
#include "string.h"
#include <limits.h>
#include <stdlib.h>

#define COMMAND_LEN 16      //*DO NOT MODIFY unless it differ from your TASK_COMM_LEN.
#define MAX_FILES 256
#define TERMINATION_T 300   //Using multiples of the interval time is advised
#define INTERVAL_T 30       //TIMESTAMP interval

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

/*
################################################
Event Handler for Monitoring a Specific Process.
################################################
static FILE *csv_file;

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;
	if(strncmp(m->command, "1b29", 4) == 0){
	fprintf(csv_file, "%s\n", m->message);
	}
}
*/

/*
################################################
Event Handler for Monitoring All Processes.
################################################
*/
static FILE *csv_files[MAX_FILES];
static char csv_file_names[MAX_FILES][PATH_MAX];
time_t file_timestamps[MAX_FILES];
static int file_count = 0;

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct data_t *m = data;
    char file_name[6 + COMMAND_LEN + 4 + 1];
    snprintf(file_name, sizeof(file_name), "dataset/%.256s.csv", m->command);

    FILE *csv_file = NULL;
    int file_index = -1;
    for (int i = 0; i < file_count; ++i) {
        if (strcmp(csv_file_names[i], file_name) == 0) {
            csv_file = csv_files[i];
            file_index = i;
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
        if (file_count >= MAX_FILES) {
            fprintf(stderr, "Maximum number of files reached\n");
            return;
        }
        csv_file = fopen(file_name, "w");
/*
################################################
Debuggin Code, Disabled to Remove Noise.
################################################
        if (!csv_file) {
            fprintf(stderr, "Failed to open file: %s\n", file_name);
            return;
        }
*/
        strcpy(csv_file_names[file_count], file_name);
        csv_files[file_count] = csv_file;
        file_timestamps[file_count] = time(NULL);
        file_index = file_count;
        file_count++;
        fprintf(csv_file, "SYSTEM_CALL\n");
    }
        strcpy(csv_file_names[file_count], file_name);
        csv_files[file_count++] = csv_file;
        fprintf(csv_file, "SYSTEM_CALL\n");
    }

/*
################################################
TIMESTAMP
################################################
*/
    time_t current_time = time(NULL);
    if (difftime(current_time, file_timestamps[file_index]) >= INTERVAL_T) {
        fprintf(csv_file, "TIMESTAMP\n");
        file_timestamps[file_index] = current_time;
    }

    fprintf(csv_file, "%s\n", m->syscall);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
	printf("lost event\n");
}

int main() {
    printf("Collecting system calls...\n");
	time_t start_time, current_time = 0;
	time(&start_time);


    struct dcars_bpf *skel;
    int err;
    struct perf_buffer *pb = NULL;

    libbpf_set_print(libbpf_print_fn);

    char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

    skel = dcars_bpf__open_opts(&opts);
	err = dcars_bpf__load(skel);

    if (err) {
		printf("Failed to load BPF object\n");
		dcars_bpf__destroy(skel);
		return 1;
	}

	err = dcars_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		dcars_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		dcars_bpf__destroy(skel);
        return 1;
	}

    while (true) {
        err = perf_buffer__poll(pb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        time(&current_time);
        if (difftime(current_time, start_time) >= TERMINATION_T) {
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
	dcars_bpf__destroy(skel);
	return -err;
}

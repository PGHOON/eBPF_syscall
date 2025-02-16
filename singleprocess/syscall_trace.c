#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "syscall_trace.h"
#include "syscall_trace.skel.h"
#include "time.h"

#define COMMAND_LEN 16      //*DO NOT MODIFY unless it differ from your TASK_COMM_LEN.
#define INTERVAL_T 1		//TIMESTAMP interval
#define TERMINATION_T 10	//(INTERVAL_T * n) value is advised

static char command_prefix[COMMAND_LEN];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;
	if (strncmp(m->command, command_prefix, COMMAND_LEN) == 0) {
        char filename[256];
        snprintf(filename, sizeof(filename), "dataset/%s.csv", m->command);
        FILE *csv_file = fopen(filename, "a");
        if (!csv_file) {
            perror("Error opening file\n");
            return;
        }

        fprintf(csv_file, "%s\n", m->message);
        fclose(csv_file);
	}
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
	printf("lost event\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
        fprintf(stderr, "Usage: %s <process name>\n", argv[0]);
        return 1;
    }

	strncpy(command_prefix, argv[1], COMMAND_LEN);
    command_prefix[COMMAND_LEN] = '\0';

	printf("Collecting system calls...\n");
	time_t start_time, current_time, time_stamp = 0;
	time(&start_time);

    struct syscall_trace_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);
	
	skel = syscall_trace_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = syscall_trace_bpf__load(skel);
	if (err) {
		printf("Failed to load BPF object\n");
		syscall_trace_bpf__destroy(skel);
		return 1;
	}

	err = syscall_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		syscall_trace_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		syscall_trace_bpf__destroy(skel);
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
		if (difftime(current_time, time_stamp) >= INTERVAL_T) {
			char filename[256];
			snprintf(filename, sizeof(filename), "dataset/%s.csv", command_prefix);
			FILE *csv_file = fopen(filename, "a");
			if (csv_file) {
				fprintf(csv_file, "TIMESTAMP\n");
				fclose(csv_file);
			}
			time_stamp = current_time;
		}
		if (difftime(current_time, start_time) >= TERMINATION_T){
			err = 0;
			break;
		}
	}

	printf("Processing data...\n");

	perf_buffer__free(pb);
	syscall_trace_bpf__destroy(skel);
	return -err;
}

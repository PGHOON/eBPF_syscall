#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>  // 추가된 헤더 파일
#include "syscall_trace_all.h"
#include "syscall_trace_all.skel.h"
#include "time.h"
#include "string.h"
#include <limits.h>
#include <stdlib.h>

#define COMMAND_LEN 16          //*DO NOT MODIFY unless it differ from your TASK_COMM_LEN
#define MAX_FILES 256
#define TERMINATION_T 10   //Using multiples of the interval time is advised
#define INTERVAL_T 1       //TIMESTAMP interval

static FILE *csv_files[MAX_FILES];
static char csv_file_names[MAX_FILES][PATH_MAX];
static int file_count = 0;

// skel을 글로벌 변수로 선언
static struct syscall_trace_all_bpf *skel;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        if (level >= LIBBPF_DEBUG)
                return 0;

        return vfprintf(stderr, format, args);
}

void update_count_min_sketch(struct count_min_sketch *cms, unsigned int key, const char *value) {
    unsigned int hash = key;
    for (unsigned int i = 0; i < cms->depth; i++) {
        hash += (i + 1) * 0x9e3779b9;
        hash = (hash ^ (hash >> 16)) * 0x85ebca6b;
        hash = (hash ^ (hash >> 13)) * 0xc2b2ae35;
        hash = hash ^ (hash >> 16);
        unsigned int index = hash % cms->width;
        cms->table[i][index]++;
    }
    cms->size++;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct data_t *m = data;
    int fd = bpf_map__fd(skel->maps.cms_map);
    struct count_min_sketch cms = {};
    unsigned int key = m->mnt_ns;

    if (bpf_map_lookup_elem(fd, &key, &cms) != 0) {
        memset(&cms, 0, sizeof(cms));
    }

    update_count_min_sketch(&cms, key, m->syscall);

    if (bpf_map_update_elem(fd, &key, &cms, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update count_min_sketch\n");
        return;
    }

    char file_name[64];
    snprintf(file_name, sizeof(file_name), "dataset/%.16s.csv", m->command);

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
            fprintf(stderr, "Failed to open file: %s\n", file_name);
            return;
        }
        strcpy(csv_file_names[file_count], file_name);
        csv_files[file_count++] = csv_file;
        fprintf(csv_file, "SYSTEM_CALL,MNT_NS,PID_NS\n");
    }

    fprintf(csv_file, "%s,%u,%u\n", m->syscall, m->mnt_ns, m->pid_ns);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz){}

int main()
{
        printf("Collecting system calls...\n");
        int init = system("rm -f dataset/*.csv");
        if (init != 0) {
                printf("Fail to initialize CSV files\n");
                return 1;
        }

        time_t start_time, current_time = 0;
        time(&start_time);

    // struct syscall_trace_all_bpf *skel;
    int err;
        struct perf_buffer *pb = NULL;

        libbpf_set_print(libbpf_print_fn);

        char log_buf[64 * 1024];
        LIBBPF_OPTS(bpf_object_open_opts, opts,
                .kernel_log_buf = log_buf,
                .kernel_log_size = sizeof(log_buf),
                .kernel_log_level = 1,
        );

        skel = syscall_trace_all_bpf__open_opts(&opts);

        err = syscall_trace_all_bpf__load(skel);

        if (err) {
                printf("Failed to load BPF object\n");
                syscall_trace_all_bpf__destroy(skel);
                return 1;
        }

        // Attach the progams to the events
        err = syscall_trace_all_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
                syscall_trace_all_bpf__destroy(skel);
        return 1;
        }

        pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
        if (!pb) {
                err = -1;
                fprintf(stderr, "Failed to create ring buffer\n");
                syscall_trace_all_bpf__destroy(skel);
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
                if (difftime(current_time, start_time) >= TERMINATION_T){
                        err = 0;
                        break;
                }
        }
        printf("Processing data...\n");

    for (int i = 0; i < file_count; ++i) {
        if (csv_files[i]) {
            fclose(csv_files[i]);
        }
    }
        perf_buffer__free(pb);
        syscall_trace_all_bpf__destroy(skel);

        return -err;
}

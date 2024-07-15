#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include "syscall_trace_all.h"
#include "syscall_trace_all.skel.h"

#define MAX_FILES 1024
#define TERMINATION_T 30

typedef struct {
    int width;
    int depth;
    int **table;
} CountMinSketch;

static CountMinSketch cms;

void init_count_min_sketch(CountMinSketch *cms, int width, int depth) {
    cms->width = width;
    cms->depth = depth;
    cms->table = malloc(depth * sizeof(int *));
    for (int i = 0; i < depth; ++i) {
        cms->table[i] = calloc(width, sizeof(int));
    }
}

void update_count_min_sketch(CountMinSketch *cms, unsigned int key) {
    for (int i = 0; i < cms->depth; ++i) {
        unsigned int hash = (key + i) % cms->width;
        __sync_fetch_and_add(&cms->table[i][hash], 1);
    }
}

void save_count_min_sketch_to_file(const char *filename, CountMinSketch *cms) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open count min sketch file");
        return;
    }
    for (int i = 0; i < cms->depth; ++i) {
        for (int j = 0; j < cms->width; ++j) {
            fprintf(file, "%d ", cms->table[i][j]);
        }
        fprintf(file, "\n");
    }
    fclose(file);
}

char* get_container_id(pid_t pid, char *container_id, size_t size) {
    char path[6 + PATH_MAX + 4 + 1];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *file = fopen(path, "r");
    if (!file) {
        return NULL;
    }
    while (fgets(path, sizeof(path), file)) {
        char *ptr = strstr(path, "docker/");
        if (ptr) {
            strncpy(container_id, ptr + strlen("docker/"), size - 1);
            container_id[size - 1] = '\0';
            strtok(container_id, "\n"); // Remove the newline character
            fclose(file);
            return container_id;
        }
    }
    fclose(file);
    return NULL;
}

char* get_container_name(const char *container_id, char *container_name, size_t size) {
    char command[6 + PATH_MAX + 4 + 1];
    snprintf(command, sizeof(command), "docker inspect --format '{{.Name}}' %s", container_id);
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        return NULL;
    }
    if (fgets(container_name, size, pipe)) {
        strtok(container_name, "\n"); // Remove the newline character
        pclose(pipe);
        return container_name;
    }
    pclose(pipe);
    return NULL;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct data_t *event = data;
    char csv_filename[6 + PATH_MAX + 4 + 1];
    char container_id[64] = {0};
    char container_name[64] = {0};

    if (get_container_id(event->pid, container_id, sizeof(container_id))) {
        if (get_container_name(container_id, container_name, sizeof(container_name))) {
            snprintf(csv_filename, sizeof(csv_filename), "./dataset/%s.csv", container_name);
        } else {
            snprintf(csv_filename, sizeof(csv_filename), "./dataset/unknown.csv");
        }
    } else {
        snprintf(csv_filename, sizeof(csv_filename), "./dataset/unknown.csv");
    }

    FILE *csv_file = fopen(csv_filename, "a");
    if (csv_file) {
        fprintf(csv_file, "PID: %d, UID: %d, Command: %s, Syscall: %s\n",
                event->pid, event->uid, event->command, event->syscall);
        fclose(csv_file);
    }

    update_count_min_sketch(&cms, event->pid);
}

int main(int argc, char **argv) {
    struct syscall_trace_all_bpf *skel;
    struct perf_buffer *pb = NULL;
    time_t start_time, current_time;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = syscall_trace_all_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (syscall_trace_all_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    if (syscall_trace_all_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        return 1;
    }

    init_count_min_sketch(&cms, 1000, 5);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        return 1;
    }

    printf("Collecting system calls...\n");
    time(&start_time);

    while (1) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        time(&current_time);
        if (difftime(current_time, start_time) >= TERMINATION_T) {
            break;
        }
    }

    save_count_min_sketch_to_file("./dataset/count_min_sketch.txt", &cms);

    syscall_trace_all_bpf__destroy(skel);
    return 0;
}

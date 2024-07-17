#ifndef SYSCALL_TRACE_ALL_H
#define SYSCALL_TRACE_ALL_H

#define TASK_COMM_LEN 16
#define MAX_SYSCALL_LEN 32
#define COMMAND_LEN 16
#define DEPTH 4
#define WIDTH 1024

struct count_min_sketch {
    unsigned int table[DEPTH][WIDTH];
    unsigned int width;
    unsigned int depth;
    unsigned int size;
};

struct data_t {
    unsigned int pid;
    unsigned int uid;
    char command[TASK_COMM_LEN];
    char syscall[MAX_SYSCALL_LEN];
    unsigned int mnt_ns;
    unsigned int pid_ns;
};

// update_count_min_sketch 함수의 원형 선언
void update_count_min_sketch(struct count_min_sketch *cms, unsigned int key, const char *value);

#endif /* SYSCALL_TRACE_ALL_H */

#ifndef __SYSCALL_TRACE_ALL_H
#define __SYSCALL_TRACE_ALL_H

#define TASK_COMM_LEN 16
#define SYSCALL_NAME_LEN 32

struct data_t {
    __u32 pid;
    __u32 uid;
    char command[TASK_COMM_LEN];
    char syscall[SYSCALL_NAME_LEN];
};

#endif /* __SYSCALL_TRACE_ALL_H */

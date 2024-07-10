# 사용방법

eBPF_syscall/multiprocess/ 디렉토리에서 make를 하시면 "syscall_trace_all"이라는 실행파일을 만드실 수 있습니다.

실행방법은 ./syscall_trace_all 입니다.

실행시 syscall_trace_all.c 상의 종료 시간(TERMINATION_T), 중간기록 시간(INTERVAL_T)에 따라서 실해이됩니다.

결과값은 ./dataset/ 디렉토리에 현재 실행중인 모든 프로세스에 대해서 <프로세스_이름>.csv이름으로 저장됩니다.

<프로세스_이름>.csv에는 상단에 SYSTEM_CALL이 출력되며, 그 이후로는 시스템콜과 INTERVAL_T의 간격으로 TIMESTAMP가 출되어 저장됩니다.

# English description in case of a Korean encoding error

In the directory eBPF_syscall/multiprocess/, you can create an executable file named "syscall_trace_all" by running make.

To execute it, use ./syscall_trace_all

When executed, tracing and loging will operate based on the termination time (TERMINATION_T) and interval recording time (INTERVAL_T) defined in the syscall_trace_all.c file.

The results are saved in the ./dataset/ directory as <process_name>.csv for all currently running processes.

In <process_name>.csv, the header will display SYSTEM_CALL, followed by system calls and timestamps recorded at intervals defined by INTERVAL_T.
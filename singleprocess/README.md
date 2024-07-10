eBPF_syscall/singleprocess/ 디렉토리에서 make를 하시면 syscall_trace라는 실행파일을 만드실 수 있습니다.

실행방법은 ./syscall_trace <타켓팅 프로세스의 이름>
//example: ./syscall_trace dockerd

실행시 syscall_trace.c 상의 종료 시간(TERMINATION_T), 중간기록 시간(INTERVAL_T)에 따라서 실해이됩니다.

결과값은 ./dataset/ 디렉토리에 test.csv이름으로 고정해서 저장됩니다.
//example: test.csv

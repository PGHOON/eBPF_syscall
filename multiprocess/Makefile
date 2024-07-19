.PHONY: all clean

all: syscall_trace_all

syscall_trace_all: syscall_trace_all.c syscall_trace_all.bpf.o syscall_trace_all.skel.h
	gcc -Wall -o syscall_trace_all syscall_trace_all.c -L../libbpf/src -l:libbpf.a -lelf -lz

syscall_trace_all.skel.h: syscall_trace_all.bpf.o
	bpftool gen skeleton syscall_trace_all.bpf.o > syscall_trace_all.skel.h

syscall_trace_all.bpf.o: syscall_trace_all.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c syscall_trace_all.bpf.c -o syscall_trace_all.bpf.o
	llvm-strip -g syscall_trace_all.bpf.o

clean:
	rm -f syscall_trace_all syscall_trace_all.bpf.o syscall_trace_all.skel.h

#!/bin/bash

# 시스템 업데이트 및 필수 패키지 설치
sudo apt-get update
sudo apt-get install -y \
    pkg-config \
    gcc \
    clang \
    llvm \
    libelf-dev \
    make \
    git \
    wget \
    lsb-release \
    software-properties-common \
    gnupg

# 최신 clang 및 llvm 설치
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh

sudo apt-get update
sudo apt-get install -y clang-18 llvm-18 libclang-18-dev

# 환경 변수 설정
export CC=clang-18
export LLVM=llvm-18
export CLANG=clang-18

# libbpf 설치
git clone https://github.com/PGHOON/eBPF_syscall.git ~/eBPF_syscall
cd ~/eBPF_syscall/libbpf/src
sudo make install

# bpftool 설치
git clone --recurse-submodules https://github.com/libbpf/bpftool.git ~/bpftool
cd ~/bpftool/src
sudo make install

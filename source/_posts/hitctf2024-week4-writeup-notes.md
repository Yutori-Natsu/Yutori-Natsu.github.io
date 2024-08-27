---
title: hitctf2024-week4-writeup-notes
date: 2024-08-27 22:05:42
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
cover: https://yutori-natsu.github.io/images/wp4.png
---

## Reverse

### ezVM

一眼模拟指令集，Z3 启动

### Confusion

花指令一号之 jmp -> jz + jnz，nop 中段的多余字节码恢复
NepCTF 的超级大号 obf：https://mp.weixin.qq.com/s/W9c87MXbVBdUOTY8gAtKsA

### OldEight

dnSpy 反编译 C# 工具链
NepCTF 的时候遇到了通过 il2cpp 生成的 Unity 应用，此时不能直接用 dnSpy，需要用 il2cppdumper 之类的工具

## Crypto

格密码专场，可恶的数学

### Lattice-1

### Lattice-2

### Lattice-3

## Pwn

### IOFILE

write 不能覆写，而且没有 free 无法 UAF，但是 read 和 write 中对 idx 的检查存在漏洞。
IDA 发现 bss 段的开头有一个指向自己的 __dso_handle，因此可以通过这个地址进行负 idx 的读写来 leak 其它地址。在这后面紧跟的是 stdout, stdin 和 stderr 三个指针，分别指向 libc 中的 `_IO_2_1_stdout_`, `_IO_2_1_stdin_` 和 `_IO_2_1_stderr_`，可以用于计算 libcbase，进而得到 __environ 的地址，其中存储的是一个指向栈上的存储环境变量的指针数组，因此可以得到栈地址。通过负 idx 写来伪造一个任意地址写就能完成 onegadget 的注入，得到 flag。
后半段可能还可以通过覆盖 `_IO_2_1_stdout_` 的 vtable 来注入 onegadget？不能直接注入，因为 libc >= 2.24，会触发 `Fatal error: glibc detected an invalid stdio handle`
https://ctf-wiki.org/pwn/linux/user-mode/io-file/exploit-in-libc2.24/#_io_str_jumps-overflow
可以将 vtable 修改为此处的 `_IO_str_jumps`，然后修改 `_IO_2_1_stdout_` 来触发 shell

### LargeBinAttack
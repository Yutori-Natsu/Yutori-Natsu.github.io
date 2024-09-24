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

有 `c = (a * m) mod p`，给定 `c` 和 `p` 求 `m`

推式子

![a](./lattice1-1.png)

因此构造如下的格矩阵

![a](./lattice1-2.png)

令 `A = 1, B = -1`，规约后可以得到对应的 `(m, C)`

Trivia: 此处的 `C` 可以用于联立解出先前的 `r`

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

方法好像蛮多的，先试了一下 [House of Banana](https://xz.aliyun.com/t/12876)，具体来说就是利用 largebin attack 更改 ld 中的 `_rtld_global._dl_ns->_ns_loaded`，这是一个程序通过 exit 等流程退出之后在 ld 中的 `_dl_fini` 会检查、处理并执行的链表。正常情况下，这个链表一共有四项，其第 1、2、4 项位于 ld 段内，第 3 项位于 mmap 出的段内，这意味着最常用的攻击方式是修改第一项到可控制的地址上，在此处便是 largebin attack 的堆段内。伪造的 link_map 结构可以执行一系列的函数，其特点是对应的 gadget 需要倒序插入（对应 `_dl_fini` 中的 `while(--i)`）。参数规则似乎需要自行寻找对应的 gadget。接下来的部分在于不同机器在开启 ASLR 之后 libc 段与 ld 段之间偏移值的第 13~20 位需要进行爆破，因此需要将 ld 中的偏移使用 ld 内的地址，分别计算每次的 ld_base，最后再一起计算 `_ns_loaded_addr` 和 `link_map_2_addr`。

[用了别人的模板](https://www.hkbinbin.fun/2023/10/06/house-of-banana/)

[House of apple2](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)
[2](https://zikh26.github.io/posts/19609dd.html#house-of-apple2)

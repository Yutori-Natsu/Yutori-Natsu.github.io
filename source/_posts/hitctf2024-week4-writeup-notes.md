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

![a](https://yutori-natsu.github.io/2024/08/27/hitctf2024-week4-writeup-notes/lattice1-1.png)

因此构造如下的格矩阵

![a](https://yutori-natsu.github.io/2024/08/27/hitctf2024-week4-writeup-notes/lattice1-2.png)

令 `A = 1, B = -1`，规约后可以得到对应的 `(m, C)`

Trivia: 此处的 `C` 可以用于联立解出先前的 `r`

### Lattice-2

一个很巧妙的轮换构造，三个参数也是这个结构下所需要的

`d' * e' = 1 + kabcdef`，根据 n1, n2, n3 的特点可以转化为三个形如 `d' * e' + An[i] = B` 的等式，构造格求解得到 `d'`，由 `d' * e' = 1 + kabcdef = 1 (mod phi(n1))` 完成 RSA 解密

```python
c = ...
e = ...
n1 = ...
n2 = ...
n3 = ...
B = 2**(4*-180)
L = matrix([
    [1,B*e,B*e,B*e],
    [0,B*n1,0,0],
    [0,0,B*n2,0],
    [0,0,0,B*n3]
])
res = L.LLL()
print(-res[0,0])
```

精彩之处在于此处对于大小为 k 的格，其在 Hermit 定理中的决定值大约在 `(B + 0x600) * (k-1) / k` bit，而目标向量的大小在 `max(0x210, 0x510 + B)` bit，此时 k = 3 是存在能够用于配平 Hermit 定理的 B 的最小值。

### Lattice-3

究极暴力之我寻思应该能行之力

可以将加密过程改写如下：`C = M * T mod p`，进而通过 seed 得到 16 个已知的 `C[i]`。因此尝试根据如下恒等式构造格：

![a](https://yutori-natsu.github.io/2024/08/27/hitctf2024-week4-writeup-notes/lattice3-1.png)

其中 T 为根据已有的 C 截取的系数矩阵。会发现这个格无论如何缩放都无法满足 Hermit 定理的要求，故进一步将格改为如下的格：

![a](https://yutori-natsu.github.io/2024/08/27/hitctf2024-week4-writeup-notes/lattice3-2.png)

根据构造，由于明文为 ASCII，其大小约为 8 bit，而 k 为 线性组合之和除以 p 的商，大小一般在 8 + 5 = 13 bit，左边格的决定式如下，大约为 35 bit（在这组数据下大约为 34.67 bit），故可以直接进行规约，结果的第一行即为所求答案。

![a](https://yutori-natsu.github.io/2024/08/27/hitctf2024-week4-writeup-notes/lattice3-3.png)

```python
import random
p = 319091779869475374911695228423324530997
random.seed(0xcafebabe)

vec_zero = [0] * 32
vec_temp = [i for i in range(32)]
vec_co = []
vec_inv = []

for i in range(32):
    vec_co.append(vec_zero.copy())
    vec_inv.append(vec_zero.copy())
    vec_co[i][i] = 1

for _ in range(100000):
    x = random.randint(0, 31)
    y = random.randint(0, 31)
    for i in range(32):
        vec_co[x][i] += vec_co[y][i] # construct T
        vec_co[x][i] %= p

r = random.sample(vec_temp, 16)
sample = [246415812587807955719465288044201719150, 
          25823418688747119552867703202077954742, 
          273975173174872667670349301602909925041, 
          74819122900362508301812012519072346089, 
          307025913230811949362183799087621378605, 
          111756507561379169428585335542438410208, 
          31014035928821611988689266381114681052, 
          158160784389144362309073339510431518439, 
          189909043056878233059107613293511107477, 
          272974060341572186018916149825627429126, 
          182856029478269321082003604921397866989, 
          259589248922429513367122588418587486935, 
          92189739655863216285857342016549552902, 
          123449160885669287608440168940251472197, 
          242452497155050148384372661588046551814, 
          112859548971181667550169123431601320680]

extra_size = 2 * len(r)
final_size = 32 + extra_size
vec_final = [0] * final_size
mat_lll = [vec_final.copy() for i in range(final_size)]

for i in range(0, 32): # set M[[_, 0, ?],[0, ?, ?],[0, 0, ?]] = E[32*32]
    mat_lll[i][i] = 1
for i in range(32, 32 + len(r)): # set M[[E, 0, ?],[0, _, ?],[0, 0, ?]] = E[16*16]
    mat_lll[i][i] = 1
for i in range(32 + len(r), final_size): # set M[[E, 0, ?],[0, E, ?],[0, 0, _]] = C
    mat_lll[i][i] = sample[i - 32 - len(r)]
for i in range(32 + len(r), final_size):
    for j in range(0, 32): # set M[[E, 0, _],[0, E, _],[0, 0, C]] = T, P
        mat_lll[j][i] = vec_co[r[i - 32 - len(r)]][j]
    mat_lll[i - len(r)][i] = p

M = matrix(mat_lll) # [[E, 0, T],[0, E, P],[0, 0, C]]
res = M.LLL()
print(res)
for i in range(32):
    print(chr(-res[0][i]), end='') # flag{sucH_a_s1mp1e_L@t111cCeeEE}
```

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

---
title: hitctf2024-week2-writeup&notes
date: 2024-08-06 18:08:12
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
katex: true
---
## Reverse

### Top5

五种不同的数据加密方法。enc1 与 enc3 为 TEA 系列加密方法，主要流程为将输入的 **8 字节明文**解析为 2 个 int64 进行若干次循环自然溢出增量。每次某个 int64 的增量均为另一个 int64 位移变换之后与某个字典值的异或结果。记两个 int64 为 a 和 b，则 TEA 系列加密算法最大的特征就是每轮循环的**三次更新**：a, b 与 index.

```python

# psuedo code
v1 = input[0:4]
v2 = input[4:8]
for i in range(0, PARAM_ROUNDS):
    v1 += F(v2) ^ Dict(index)
    v2 += F(v1) ^ Dict(index)
    index += delta
input[0:4] = v1
input[4:8] = v2

```

enc2 在 IDA 反汇编后暴露出了大小写字母+数字+符号的字典，推测为 base-x 类算法。此处使用的是最常见的 base64，其主要思想为将原文的**比特流**每 6 位作为一个数，在字典内进行编码。由于整除性质不一定总被满足，所以此处需要在结尾进行全 0 的 padding，最后的 padding 数可以由 000000 对应的字典字符在结尾连续出现的次数得出。

### Ez_maze

加壳。IDA 动态分析会有问题，原因未知。使用 OllyDbg 进行动态调试，通过 Step in till return 找到程序本身流程，分析为迷宫。

### sinke

CE 动态分析。对于这种动态的窗口程序，使用 Cheat Engine 也可以完成 IDA，OllyDbg 等调试器的基本功能（查看汇编、寄存器等）。CE 本身的封装使得对于内存值的动态调试更容易进行。
程序本身为图形化的贪吃蛇，动态分析加分前不变的内存值+加分后增加了的内存值，得到一个唯一结果。分析其相关内存和汇编行为发现目标分数的地址，因此在每次加分时的汇编处打上断点，在某次加分后修改内存，步进至完成流程后复原内存得到 flag.

## Web

### babyssrf

### tp

## Pwn

### EasyHeap

大坑！
前置知识：堆上分配内存块结构、内存块管理方式
内存块（chunk）主要包含 chunk header 和 user data，chunk header 中分别是 prev_size 和 size，user data 在该块闲置时开头为前向指针 fd 和后向指针 bk，结尾为按照块大小分类的前后向指针。
管理方式：主要分为 small / large / unsorted bin，fastbin 和 tcache(libc > 2.26)。tcache 是 64 个按照 chunk 大小分别建立的栈，安全性检查最少；fastbin 是优先级低于 tcache 的 chunk 栈，而剩余的 bin 是根据 chunk 大小和释放时机分别归类的三个 chunk 队列。
本题为 libc 2.27，故先申请若干个（此处为 10 个）chunk 和一个大 chunkS，然后依次释放前 8 个 chunk。此时 chunk 1 到 chunk 7 均位于 tcache，同时由于 chunk 8 大小较小，它会暂时位于 fast bin。此时再释放 chunkS，由于某些原因，在 chunkS 与 top chunk 合并后，chunk 8 会被置于 unsorted bin。由于 unsorted bin 的特性，此时 chunk 8 的 fd 指针会指向 unsorted bin 的初始节点，通过 Use After Free 可以得到一个和 main_arena 结构具有固定偏移的地址，当中保存的是 top chunk 的地址，然后是 unsorted bin 初始节点的前向与后向指针，然后是 small / large bin 等。此处使用了一个投机取巧的方法：程序的 ASLR 范围似乎不仅限于后 12 位，在这里达到了 20 位，且 libc 的基址与前文中 UAF 泄露的地址具有固定偏移量 `0x3ebca0`，故此处较为轻松地得到了 libc 的基址。
接下来的部分是基于 tcache 的 alloc to any address。释放一个 tcache 的 chunk 会导致 tcache 的栈顶指向该 chunk，从 tcache 中取出 chunk 进行分配时则会将该 chunk 的 fd 指针赋予栈顶。此处通过 UAF 对已经释放的 chunk 进行覆写，可以得到两个分别指向 `__malloc_hook` 和 `__realloc_hook` 的 chunk，通过 realloc 调整栈帧后由 onegadget 远程执行 shell。
观察内存，发现 `__realloc_hook` 处已有数据（貌似是特供版 libc 自带的默认值？），而 `__malloc_hook` 内没有，所以选择先构造指向 `__malloc_hook` 的 chunk，再构造指向 `__realloc_hook` 的 chunk，这样可以避免脏数据导致的一系列问题（又是一个以后再填的坑）。此处先将 chunk 7 的 fd 覆写为 `__malloc_hook`，然后调用两次 malloc，第一次malloc 会分配到 chunk 7，并导致 tcache 的栈顶指向 `__malloc_hook`，第二次 malloc 就能分配到指向 `__malloc_hook` 的 chunk 了。接下来 tcache 内还有 5 个已释放的 chunk，但栈顶已经指向了 NULL，所以此处需要额外释放别的 chunk。此处我选择的是依次释放 chunk 6 和 chunk 5，完成后栈顶指向 chunk 5，同样的覆写分配流程后就能得到指向 `__realloc_hook` 的 chunk，最后分别改写两处 hook 就能完成攻击流程。

## Crypto

### photoenc

加密的命令行指令为 `sm4-ecb`，将加密后的图片文件头修改为 `.bmp` 的文件头后就可以辨识flag.
TBD: ecb-

### mountain

线性组合加密，每 8 bytes 为一个 chunk，将该 chunk 作为一个 `1x8` 的行向量，右乘一个 `8x8` 的变换矩阵得到对应的加密行向量。逆向时由明文和密文可以对变换矩阵的每一列建立一个八元一次方程组来解出变换矩阵。获得变换矩阵后由于密文是由明文右乘变换矩阵得到的，故将密文右乘其伴随矩阵后乘以其行列式的逆元，在 mod n 意义下即为该 chunk 的明文。注意大数运算时初始值最好用 MMA 计算得到结果后直接写死，否则容易遇到浮点问题。

```plain
m[i] * K = c[i] 
m[i] * K * adjK = m[i] * |K| = c[i] * adjK
m[i] = c[i] * adjK * |K|^-1
```

### easybag

子集和问题，flag 被 AES 加密，而 AES 的密钥由背包方法加密。将密钥 key 的比特流看做一个 `1x64` 的行向量，生成 64 个随机数作为公钥向量与 key 向量求点积后的结果作为密文。用空间换时间可以有一个时空 `O(2^n/2)` 的暴力方法。
通过 LLL 算法可以做到高效求解子集和问题？ TBD

### broadcast

类 RSA 算法，记明文为 m，`x = m^11`，给定 12 组 (r, p) 对满足 `x mod p[i] = r[i]`，求明文 m。
12 组 (r, p) 对可以直接解出 x，用 MMA 解这组同余方程后暴力对每个可能的答案求 `x^1/11`

### ex-ddddhm

比较复杂的 RSA 题。
给定各项参数：`n ~ 2^{1024}, e1 = 65537, c = m1^e1 mod n, e2 = 7,  bits(d2) = 1024, e1*d1 = e2*d2 = 1 (mod (p-1)(q-1))`
突破口在于第二组明文 `m2 = ddddhm` 以及对应的密文 `sig = m2^d2 mod n`，以及一组伪密文：`sigf[i] = m2^d2(i), d2(i) = d2 xor 1<<i, i \in {0,1,...,1024*2/3}`。由伪密文可以求出 d2 的低若干比特位：

```plain
若 d2[i]=0, 则 d2(i) = d2 + 1<<i, sigf[i] = m2^(d2 + 1<<i) = sig * m2^(1<<i) (mod n)
```

由于 `e2 = 7` 过小，考虑到 `e2*d2 = 1 (mod (p-1)(q-1))`，即 `e2*d2 = k(p-1)(q-1) + 1`，可以枚举 k，判断是否符合得到的低比特位，拼接得到完整的 d2。由于 `(p-1)(q-1) < pq = n`，可以解出 `k = 5`，进而解出 p, q，得到 d1 解密 flag

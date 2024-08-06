---
title: hitctf2024-week2-writeup&notes
date: 2024-08-06 18:08:12
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
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

## Crypto

### photoenc

加密的命令行指令为 `sm4-ecb`，将加密后的图片文件头修改为 `.bmp` 的文件头后就可以辨识flag.
TBD: ecb-

### mountain

线性组合加密，每 8 bytes 为一个 chunk，将该 chunk 作为一个 $1\times8$ 的行向量，右乘一个 $8\times8$ 的变换矩阵得到对应的加密行向量。逆向时由明文和密文可以对变换矩阵的每一列建立一个八元一次方程组来解出变换矩阵。注意大数运算时初始值最好用 MMA 计算得到结果后直接写死，否则容易遇到浮点问题。

$$
m_i \times K = c_i \\
m_i \times K \times K^{-1} = m_i \times |K|^{-1} = c_i \times K^{-1} \\
m_i = c_i \times K^{-1} \times |K|
$$

### easybag

子集和问题，flag 被 AES 加密，而 AES 的密钥由背包方法加密。将密钥 key 的比特流看做一个 $1\times 64$ 的行向量，生成 64 个随机数作为公钥向量与 key 向量求点积后的结果作为密文。用空间换时间可以有一个时空 $O(2^{\frac n2})$ 的暴力方法。

### broadcast

类 RSA 算法，记明文为 $m$，$x=m^{11}$，给定 12 组 $(r, p)$ 对满足 $x \mod p_i = r_i$，求明文 $m$。
12 组 $(r,p)$ 对可以直接解出 $x$，用 MMA 解这组同余方程后暴力对每个可能的答案求 $^{11}\sqrt{x}$

### ex-ddddhm

比较复杂的 RSA 题。
给定各项参数：$n\approx2^{1024}, e_1=65537, c=m_1^{e_1}\mod n, e_2=7,  bits(d_2)=1024, e_1d_1=e_2d_2=1\ (\mod (p-1)(q-1))$
突破口在于第二组明文 $m_2=ddddhm$ 以及对应的密文 $sig=m_2^{d_2}\mod n$，以及一组伪密文：$sigf_i=m_2^{d_2(i)},d_2(i)=d_2\ xor\ 2^i,i\in\{0,1,\cdots,1024\times2/3\}$。由伪密文可以求出 $d_2$ 的低若干比特位：
$$
若 d_2[i]=0,则d_2(i)=d_2+2^i,sigf_i=m_2^{d_2+2^i}=sig\times m_2^{2^i}\ (\mod n)
$$
由于 $e_2=7$ 过小，考虑到 $e_2d_2=1\ (\mod (p-1)(q-1))$，即 $e_2d_2=k(p-1)(q-1)+1$，可以枚举 $k$，判断是否符合得到的低比特位，拼接得到完整的 $d_2$。由于 $(p-1)(q-1)<pq=n$，可以解出 $k=5$，进而解出 $p,q$，得到 $d_1$ 解密 flag
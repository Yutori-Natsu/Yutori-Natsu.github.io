---
title: hitctf2024-week3-writeup-notes
date: 2024-08-12 10:01:37
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
cover: https://yutori-natsu.github.io/images/wp3.jpeg
---

## Misc

Python 沙盒专集，参考资料 [1](https://zhuanlan.zhihu.com/p/578966149) [2](https://blog.csdn.net/Jayjay___/article/details/132436072)
基础知识：魔术方法列表、内置函数

```python
dir(x): 给出 x 的所有属性和方法
getattr(x, a): 相当于 x.__getattr__(a)，当明文中不能出现下划线时可以用于获取属性
o.__subclasses__: 给出 o 的所有父类（所有继承了 o 类并实现了更多内容的类），可以用于寻找其它模块
o.__globals__: 给出属于 o 的命名空间内的所有属性方法
o.__init__: 给出 o 的初始化函数，一般用于 o.__init__.__globals__ 找到某个其它内置模块的属性方法
```

### OJ：肖申克的救赎

明文过滤，`sys` 和 `sys.modules` 均被污染，基本上没有办法完成 `import`
过滤下划线，使用 `getattr` 代替 `.__<>__`。打印 `object.__subclasses__` 发现环境内实现了一个父类 `os._wrap_close`，因此通过 `object.__subclasses__[140].__init__.__globals__` 获得 `os` 模块内的所有方法，无需 `imoprt os` 就能调用其中的 `system` 函数，完成 RCE

### OJ：It's My钩!!!!!

`sys.addaudithook` 绕过，内置的 `__loader__.load_module` 可以不触发 `imoprt`，`_posixsubprocess` 作为 python 的底层交互接口可以不触发 `system` 等黑名单。在 `_posixsubprocess` 内有 `fork_exec` 方法，用于执行外部文件时需要传入 `*(os.pipe())`，由于 `os` 被 `sys.modues` 污染，需要用上一题的方法获取 `module os`，完成后续 RCE

## Reverse

### whereThel1b

瞎试能发现输出和 base64 非常像，此处还增加了根据长度决定的盐，每次爆破 3 字节得到 flag.

### obfsudan

真得动态调试而不是不调试
输入一个长 81 的字符串，给定若干组约束条件求解
`pip install z3-solver`
记得 `import` 什么不要和文件本身重名了

### Patience

断点测试发现关键过程为蒙特卡洛计算圆周率值，patch 后执行获得 flag.

## Pwn 

### TopChunkMaster

House of Orange (top chunk leak) + House of Force (top chunk Anywhere Allocate) + tcache
由于没有 free 没有 UAF 的途径，需要通过 House of Orange 创造 free chunk 机会。

```plain
    机制：当一次 malloc 在所有 bin 中都找不到可用 chunk，此时会尝试在 top chunk 中分配。
        1. 假如此时的 top chunk size 大于需要分配的空间，直接进行分配
        2. 假如此时的 top chunk size 小于需要分配的空间，这个 top chunk 会直接被 free 后
           进入 unsorted bin，由系统新分配一个 top chunk
```

House of Orange 在利用时对 top chunk 的 size 有对齐要求，因此将 size 的高位写 0 后 malloc 一个比较大的 chunk 就可以创造一个 unsorted bin chunk. 由 unsorted bin 中第一个 chunk 的特性，可以从中取得 `main_arena+96` 的地址，获取 libc 和各种 offset.
House of Force: 将 top chunk size 覆写为 -1，由于 size_t 是无符号数，可以 bypass 大部分后续的 malloc 参数检查。

```plain
    main_arena+96 处的结构依次是：top chunk address, unsorted bin->fd/bk, small bin, large bin
```

在覆写 size 后，试图 malloc 一个大小为负数的 chunk 能够成功，并且能够减小 top chunk address. 运行环境的 libc 版本下有 tcache 实现，所以如果通过 House of Orange 创造了多个 unsorted/small bin chunk，经过一次 malloc 分配其中的 chunk 会导致剩下的 chunk 进入 tcache. 由于 tcache 位于所有堆空间的最底端（一个 size 为 `0x250` 的 chunk），可以通过 House of Force 分配一个可以直接控制 tcache 地址表的 chunk. 
因此，通过 House of Orange 创造两个 unsorted bin chunk，然后通过 House of Force 获取一个可以控制 tcache 地址表的 chunk，在后续的一次 malloc 将剩余 chunk 写入 tcache 后，可以将原本指向这个剩余 chunk 的 tcache 地址表改为指向 __realloc_hook 的地址，第二次 malloc 获取对 __realloc_hook 和 __malloc_hook 的控制权。
具体实现时（可能）需要将两个 unsorted bin chunk 的 size 覆写为更小的值（如 `0x20`），为 House of Orange 和 House of Force 的 padding chunk 留出正常 malloc 的空间。

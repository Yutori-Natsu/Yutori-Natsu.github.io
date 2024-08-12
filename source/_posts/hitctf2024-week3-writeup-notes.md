---
title: hitctf2024-week3-writeup-notes
date: 2024-08-12 10:01:37
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
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

### obfsudan

真得动态调试而不是不调试
输入一个长 81 的字符串，给定若干组约束条件求解
`pip install z3-solver`

### Patience

断点测试发现关键过程为蒙特卡洛计算圆周率值，patch 后执行获得 flag.
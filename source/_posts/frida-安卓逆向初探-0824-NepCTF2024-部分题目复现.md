---
title: frida 安卓逆向初探 + 0824 NepCTF2024 部分题目复现
date: 2025-01-28 09:41:59
categories:
    - 实操记录
    - writeup
tags:
    - android
    - frida
    - writeup
cover: https://yutori-natsu.github.io/images/frida1.jpeg
---

### Reverse

#### ezAndroid

[文件备份](https://karasutoraipu.lanzouu.com/iHAtQ2m8v8na)

apk 的解析在[官方 wp](https://mp.weixin.qq.com/s/W9c87MXbVBdUOTY8gAtKsA) 中写的都很详细，这里就不重新写一遍。总之，在和 ddms/monitor 怎么样都不能显示进程之后用 frida 试了一下，最后也是功成圆满做了出来。

```js
// frida-hook-script.js
Java.perform(function() {
    Process.enumerateModules({
        onMatch: function(module) {
            if (module.name.startsWith('lib'))
                console.log(module.name);
        },
        onComplete: function() {
            console.log('end');
        }
    });

    const libc = Module.findBaseAddress('libc.so');
    if (libc) {
        console.log('libc.so base address:', libc);

        const randPtr = Module.findExportByName('libc.so', 'rand');

        if (randPtr) {
            console.log('rand() address:', randPtr);

            Interceptor.attach(randPtr, {
                onLeave: function(retval) {
                    console.log('rand() returned ', retval.toInt32());
                }
            });
        } else {
            console.error('rand() not found in libc.so!');
        }
    } else {
        console.error('libc.so not found!');
    }

    const mamba = Module.findBaseAddress('libBlackMamBa.so');
    if (mamba) {
        console.log('libBlackMamBa.so base address:', mamba);
        var funcaddr = mamba.add(0x8b4);
        console.log(funcaddr);
        if (funcaddr != null) {
            Interceptor.attach(funcaddr, {
                onEnter: function(args) {
                    console.log('arg0:', args[0]);
                    console.log('arg1:', args[1]);
                    console.log('arg2:', args[2]);
                },
                onLeave: function(retval) {
                    console.log(retval.toInt32());
                }
            })
        }
        var dumpaddr = mamba.add(0x978);
        Interceptor.attach(dumpaddr, {
            onEnter: function(args) {
                const context = this.context;
                console.log('tmp1=v5 = ', context.x22);
            }
        });
        var dumpaddr = mamba.add(0x9a4);
        Interceptor.attach(dumpaddr, {
            onEnter: function(args) {
                const context = this.context;
                console.log('rand mod = ', context.x8.toInt32());
            }
        });
        var dumpaddr = mamba.add(0x9e4);
        Interceptor.attach(dumpaddr, {
            onEnter: function(args) {
                const context = this.context;
                console.log('tmp1 = ', context.x8);
            }
        });
        var dumpaddr = mamba.add(0x9c0);
        Interceptor.attach(dumpaddr, {
            onEnter: function(args) {
                const context = this.context;
                console.log('tmp2 = ', context.x8);
            }
        });
        // const randPtr = Module.findExportByName('libc.so', 'rand');

        // if (randPtr) {
        //     console.log('rand() address:', randPtr);

        //     Interceptor.attach(randPtr, {
        //         onLeave: function(retval) {
        //             console.log('rand() returned ', retval.toInt32());
        //         }
        //     });
        // } else {
        //     console.error('rand() not found in libc.so!');
        // }
    } else {
        console.error('libBlackMamBa.so not found!');
    }
});
```

```python
import frida
import sys

# JavaScript 脚本
JS_CODE = ''.join(open('test.js').readlines())

# 处理从 JavaScript 发送的消息
def on_message(message, data):
    # if message['type'] == 'send':
    #     payload = message['payload']
    #     if payload['type'] == 'rand-return':
    #         print(f"function returned: {payload['value']}")
    # else:
    print(message)

# 连接到设备并附加到目标进程
def main():
    # 获取 USB 设备
    device = frida.get_usb_device()

    mode_start = False

    if mode_start == True:
        # 附加到目标进程（替换为目标应用的包名）
        pid = device.spawn(["com.example.test"])  # 如果应用未运行，使用 spawn
        session = device.attach(pid)
    else:
        session = device.attach("test")  # 直接附加到已经运行的进程

    # 创建脚本
    script = session.create_script(JS_CODE)

    # 注册消息处理函数
    script.on("message", on_message)


    # 如果使用 spawn，恢复目标进程
    if mode_start == True:
        device.resume(pid)

    # 加载脚本
    script.load() # adjusted to after resume cause System.loadLibrary

    # 保持脚本运行
    print("Press Ctrl+C to stop...")
    sys.stdin.read()

if __name__ == "__main__":
    main()
```

感觉总体上用 frida 去 hook 某些地址上某些寄存器的值/函数的返回值都有一些固定的模板？问大语言模型应该都能找到用例。

这个脚本主要 hook 后就做了两件事：确定输入字符串是如何转化为数值的和异或加密的 rand() 返回值，最后可以发现是将输入字符串假定为二进制字符串，最后加密和数值比较。frida 的操作流程在 52 上能找到很详细的解析，这里也不重复了。

除此之外，在 python 脚本里还有一个细节：script.load() 需要放在 device.resume() 上，因为 apk 中导入 so 文件是在类创建之后才进行的。

#### easyobf

[附件](https://karasutoraipu.lanzouu.com/iibqk2m8xm8b)

用 cutter 可以恢复 __libc_start_main 和 main，把 main 当中的巨量花指令 patch 完就可以分析了（真轻松呢）

[patch结果](https://karasutoraipu.lanzouu.com/iibqk2m8xm8b)

官方 wp 说里面还混了 ollvm，后面分析感觉是其它静态链接的函数被 ollvm 了？main 里面貌似没有这种特征。

### Pwn

[附件合集](https://karasutoraipu.lanzouu.com/i8igH2m8xqgd)

#### NepBox

用 ptrace 实现的简单沙箱，侧信道即可完成 orw

作为第一次打的比赛，当时遇到一大串的 ptrace 人都晕了，现在看来其实非常 simple，还是要大胆尝试

#### NepSSH

sigaction 实现了自定义的 signalid 10 的处理程序（一个简单的自创 malloc-free），可以实现任意地址分配。docker 一直起不来最后就没有做测试。

一个小趣事：这题是通过 socket listen 实现的主逻辑，如果有可能的话这题开两个不同的连接会触发非线程安全的 bug，但是这里不能利用。

#### FileManager

非常有意思的题，在 pwn 里考察了 /proc 伪文件系统的利用，具体可以参考官方 wp

#### hrpos

一个伪语言解释器，逆几下会发现这个语言支持 malloc/free 的同时有很严重的 UAF 问题，但是最后懒得写交互了

#### godrouter

web pwn，利用点在注册时构造一下用户名密码可以导致 sprintf 取出用户权限时字段被覆盖，后面再根据用户名留了一个格式化字符串，但是也没写完

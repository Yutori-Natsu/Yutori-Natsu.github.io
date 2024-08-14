---
title: 记一次 docker 配置远程 PHP 解释器
date: 2024-08-14 10:35:33
categories:
    - 实操记录
tags:
    - docker
    - php
---

[参考](https://pikaball.cc/posts/php%E5%AE%B9%E5%99%A8%E8%BF%9C%E7%A8%8B%E8%B0%83%E8%AF%95%E6%8C%87%E5%8C%97/)

### Docker 部分

```dockerfile
FROM php:8
COPY debian.sources /etc/apt/sources.list.d
# COPY run.sh /
# COPY phpstorm_xdebug_validator.zip ./phpstorm_xdebug.zip
RUN apt update
RUN apt install -y vim
RUN apt install -y openssh-server
RUN apt install unzip
# Create an SSH user
RUN useradd -rm -d /home/sshuser -s /bin/bash -g root -G sudo -u 1000 sshuser
RUN usermod -aG root sshuser
# Set the SSH user's password (replace "password" with your desired password)
RUN echo 'sshuser:password' | chpasswd
# Allow SSH access
RUN mkdir /var/run/sshd
# Expose the SSH port
EXPOSE 22
# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
EXPOSE 8000
EXPOSE 9003
# RUN unzip ./phpstorm_xdebug.zip -d .
# RUN rm -f ./phpstorm_xdebug.zip
```

需要 Dockerfile 文件同目录下有镜像源列表 debian.sources，建立镜像 `docker build -t rmphp .`
docker 运行命令 `docker run -d -p 2222:22 -p 8000:8000 -p 9003:9003  --mount type=bind,source=<src>,target=/think rmphp`，此处的 src 需要为绝对路径，保证每次对项目的修改能够被直接映射到容器的项目文件内。
docker 后台更改 root 密码 `passwd`
安装 xdebug，运行如下脚本：

```bash
pecl install xdebug
mkdir /conf.d
docker-php-ext-enable xdebug
vim /usr/local/etc/php/conf.d/xdebug.ini
```

ini 文件基本配置如下：

```ini
zend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20230831/xdebug.so 
; 此处路径改为上方 pecl install xdebug 后回显的路径
; You should add "zend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20230831/xdebug.so" to php.ini
xdebug.idekey=PHPSTORM
; 进行调试所需要携带的IDEKEY
xdebug.discover_client_host = On
xdebug.client_host="host.docker.internal"
; 这里是物理机，即IDE所在机器的ip
; docker run 中如果添加了主机的 IP 映射可能可以使用相应的 IP?
xdebug.mode=profile,trace,debug
xdebug.start_with_request=yes
xdebug.client_port = 9003
xdebug.remote_handler = dbgp
xdebug.log = /tmp/xdebug.log
xdebug.remote_enable=1
xdebug.remote_port = 9003
```

### PHPStorm 部分

IDE 需要自行寻找学习版下载。
Settings -> PHP -> CLI 解释器，添加一个新的 SSH 配置，容器 IP 为 `127.0.0.1`（如果在上文的 `docker run` 中添加 IP 映射可能可以使用不同的 IP 地址？），端口为 `2222`，用户名 `sshuser`，密码为 Dockerfile 中的配置（此处为 `password`）。解释器中 PHP 可执行文件路径为 `/usr/local/bin/php`.
Settings -> PHP - 服务器，添加新服务器，地址为 `127.0.0.1:8000`，调试器为 XDebug，路径映射本机的源文件夹到服务器上的 `/think`.（如果配置容器时容器内的项目文件夹有不同名称可能需要相应修改）
Settings -> PHP - 调试，Xdebug 调试端口 9003
Settings -> PHP - 调试 -> DBGp 代理，IDE 键 `PHPSTORM`，主机端口 `127.0.0.1:9003`.
项目设置运行实参为 `php`，这样每次运行时会在远程服务器执行命令 `/usr/local/bin/php /think/think run`，点击执行观察是否成功执行。
点击调试，此时可能会报错端口被占用，打开 Settings -> PHP - 调试，将 Xdebug 的调试端口改为新增的端口，修改容器的 `xdebug.ini`，将 `xdebug.remote_port` 和 `xdebug.client_port` 都改为新端口，查看能否成功提醒断点。

配置完成后记得使用 `docker commit <container-name>` 保存该映像

# gohttpdns

DNS 服务器，接收标准 DNS 查询请求，然后通过查询 http dns 获取结果返回给客户端。

[![Build Status](https://travis-ci.org/vinsonzou/gohttpdns.svg?branch=master)](https://travis-ci.org/vinsonzou/gohttpdns)

### 主要特性

1. 对外通过 http dns 查询，避免 DNS 劫持
2. 提供标准 DNS 查询接口，可以直接将机器的 dns 配置到 gohttpdns
3. DNS 查询结果根据 TTL 进行缓存
4. 对外 DNS 查询请求归并
5. 提供详细的审计日志，包括请求来源 IP、缓存个数、请求的域名、TTL、响应时间以及解析结果
6. 支持 hosts 文件与本地文件，可以通过文件名设置 TTL，比如 `hosts.600` 设置 TTL 为 600 秒
7. http dns 查询失败改用默认的 DNS 查询
8. 请求domain 为 `myip` 返回客户端的来源 IP


### 如何安装

	go get -v github.com/vinsonzou/gohttpdns

### 如何使用

	sudo gohttpdns

* 默认监听53端口需要管理员权限，可以增加`-bind "127.0.0.1:8053"`改变监听端口

### 测试

使用 dig 进行 dns 查询


```bash
$ dig +short @127.0.0.1 google.com
216.58.200.46
$ dig +short @127.0.0.1 google.com
216.58.200.46
$ dig +short @127.0.0.1 baidu.com
180.149.132.47
220.181.57.217
111.13.101.208
123.125.114.144
$ dig +short @127.0.0.1 baidu.com
180.149.132.47
220.181.57.217
111.13.101.208
123.125.114.144
```

程序日志输出

```bash
$ sudo gohttpdns
2017/04/09 22:37:49 dns server running at 0.0.0.0:53
2017/04/09 22:37:53 127.0.0.1:59022	139s	24.213ms	google.com.	[216.58.200.46]
2017/04/09 22:37:54 127.0.0.1:50891	138s	0.075ms	google.com.	[216.58.200.46]
2017/04/09 22:37:58 127.0.0.1:56055	98s	22.455ms	baidu.com.	[180.149.132.47 220.181.57.217 111.13.101.208 123.125.114.144]
2017/04/09 22:37:59 127.0.0.1:55850	97s	0.057ms	baidu.com.	[180.149.132.47 220.181.57.217 111.13.101.208 123.125.114.144]
```

### TODO

* 支持配置文件

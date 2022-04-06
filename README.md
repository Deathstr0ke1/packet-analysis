# 抓包分析程序
## packet-analysis

本程序完成了对本地保存的抓包文件pcapng的分析，并具有以下功能：

- 命令行参数选择指定文件
- 命令行选择背景流量文件用于过滤流量
- 命令行参数选择分析的协议类型
- 命令行参数选择打印原始报文

需要的C/C++头文件/库有：

- [libpcap](https://www.tcpdump.org/)
- [PcapPlusPlus](https://pcapplusplus.github.io/)

编译参数需要(./build.sh可以直接编译)：

```shell
g++ -o panalysis *.cc -std=c++11 -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -I/usr/local/include/pcapplusplus
```

使用方法：

```shell
panalysis usage:
./panalysis <-p pcap filename> <-t application protocol> {Options}

Notes:
  <> is mandatory
  {} is optional
  application protocol option: http, dns, ftp, pop, telnet, https, ssl, private, other

 Options:
  -r show raw packet data
  -b <background pcap filename> is for filtering background data

 EXAMPLES:
  ./panalysis -p maimai.pcapng -t http
  ./panalysis -p maimai.pcapng -t http -b maimai_background.pcapng
```

我使用的实际例子：

```shell
./panalysis -p ./datas/maimai/maimai_browse.pcapng -t http -b ./datas/maimai/backgroud_regesiter.pcapng -r
```

该例子意为，使用panalysis分析maimai_browse.pcapng，并且使用backgroud_regesiter.pcapng**过滤背景流量**，指定协议为HTTP，并打印出**原始报文**。




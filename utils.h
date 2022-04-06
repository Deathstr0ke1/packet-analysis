#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <set>
#include <string>

//用于控制台输出颜色
#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define YELLOW               "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define CYAN                 "\e[0;36m"
#define L_CYAN               "\e[1;36m"
#define GRAY                 "\e[0;37m"
#define WHITE                "\e[1;37m"
#define BOLD                 "\e[1m"
#define UNDERLINE            "\e[4m"
#define BLINK                "\e[5m"
#define REVERSE              "\e[7m"
#define HIDE                 "\e[8m"
#define CLEAR                "\e[2J"
#define CLRLINE              "\r\e[K"

#define HTTP_PROTO 0
#define DNS_PROTO 1

// 这三个协议没有实现，因为我抓的包没有相应协议的数据
#define FTP_PROTO 2
#define POP_PROTO 3
#define TELNET_PROTO 4

#define HTTPS_PROTO 5
#define SSL_PROTO 6

#define PRIVATE_PROTO 7

#define OTHER_PROTO 8

//提示使用方法
void print_usage(char *cmd);

//背景流量处理
void background_packet_handler(pcap_t *background_fp, std::set<std::string> &ip_addrs_str_set);

void packet_handler(pcap_t *data_fp, std::set<std::string> &ip_addrs_str_set, int proto_type, bool is_print_raw);

void print_stats_summary(int proto_type);
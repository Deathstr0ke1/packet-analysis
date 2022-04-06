// #include <iostream>

#include "utils.h"
#include "pcapplus.h"

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];  //错误缓冲区
    char pcap_file_name[64];

    const char *optstr  = "p:t:b:r";   //对应的参数
    int opt;                        //选项

    bool is_print_raw = false;

    int proto_type = -1;

    pcap_t *data_fp = NULL;
    pcap_t *background_fp= NULL;

    std::set<std::string> ip_addrs_str_set; 

    if(argc == 1)
	{
		print_usage(argv[0]);
		return 1;
	}

    //处理选项
	while ((opt = getopt(argc, argv, optstr)) != -1)
	{
        switch(opt)
        {
            case 'p':
                strcpy(pcap_file_name, optarg);
                data_fp = pcap_open_offline(optarg, errbuf);
                if (data_fp == NULL)
                {
                    fprintf(stderr, RED "\nOpen pcap file failed: %s\n" NONE, errbuf);
                    return 1;
                }
                break;
            case 't':
                if (strcmp(optarg, "http") == 0)
                {
                    proto_type = HTTP_PROTO;
                }
                else if (strcmp(optarg, "dns") == 0)
                {
                    proto_type = DNS_PROTO;
                }
                else if (strcmp(optarg, "ftp") == 0)
                {
                    proto_type = FTP_PROTO;
                }
                else if (strcmp(optarg, "pop") == 0)
                {
                    proto_type = POP_PROTO;
                }
                else if (strcmp(optarg, "telnet") == 0)
                {
                    proto_type = TELNET_PROTO;
                }
                else if (strcmp(optarg, "https") == 0)
                {
                    proto_type = HTTPS_PROTO;
                }
                else if (strcmp(optarg, "ssl") == 0)
                {
                    proto_type = SSL_PROTO;
                }
                else if (strcmp(optarg, "private") == 0)
                {
                    proto_type = PRIVATE_PROTO;
                }
                else if (strcmp(optarg, "other") == 0)
                {
                    proto_type = OTHER_PROTO;
                }
                else
                {
                    proto_type = -1;
                }
                break;
            case 'b':
                background_fp = pcap_open_offline(optarg, errbuf);
                if (data_fp == NULL)
                {
                    fprintf(stderr, RED "\nOpen pcap file failed: %s\n" NONE, errbuf);
                    return 1;
                }
                break;
            case 'r':
                is_print_raw = true;
                break;
            case '?':
                print_usage(argv[0]);
			    return 1;
            default:
                print_usage(argv[0]);
			    return 1;
        }
	}
    if(proto_type == -1)
    {
        fprintf(stderr, RED "\nWrong application protocol select, please select one!\n" NONE);
        print_usage(argv[0]);
        return 1;
    }

    if(background_fp != NULL)
    {
        background_packet_handler(background_fp, ip_addrs_str_set);
    }

    // 调用pcap++
    if(proto_type == HTTPS_PROTO || proto_type == SSL_PROTO)
    {
        packet_handler(data_fp, ip_addrs_str_set, proto_type, is_print_raw);
        ssl_packet_collector(pcap_file_name, ip_addrs_str_set);
    }
    else
    {
        packet_handler(data_fp, ip_addrs_str_set, proto_type, is_print_raw);
        print_stats_summary(proto_type);
    }

    pcap_close(background_fp);
    pcap_close(data_fp);

	return 0;
}
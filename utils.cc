#include "utils.h"

int http_count = 0;
std::set<std::string> http_ports;
std::set<std::string> http_ip_addrs;
std::set<std::string> user_agents;
std::set<std::string> hosts;
std::set<std::string> content_types;

int dns_count = 0;
// DNS服务器地址没有意义，它是对局域网的DNS服务器发送的
std::set<std::string> dns_contents;

int private_count = 0;
std::set<std::string> private_contacts;

void print_usage(char *path)
{
	char progname[20];

	int i;
	int loca;

	for(i = 0; i < strlen(path); i++)
	{
		if(path[i] == '/')
		{
			loca = i;
		}
	}
	strncpy(progname, path + loca + 1, strlen(path) - loca);
    
	fprintf(stdout, L_RED "\n%s usage:\n" NONE, progname);
	fprintf(stdout, L_GREEN "%s " NONE, path);
    fprintf(stdout, L_BLUE "<-p pcap filename> " NONE);
    fprintf(stdout, "<-t application protocol> ");
    fprintf(stdout, "{Options}\n");
	fprintf(stdout, UNDERLINE "\nNotes:\n" NONE);
	fprintf(stdout, BOLD "  <> is mandatory\n" NONE);
	fprintf(stdout, "  {} is optional\n");
    fprintf(stdout, "  application protocol option: http, dns, ftp, pop, telnet, https, ssl, private, other\n\n");
	fprintf(stdout, " Options:\n");
    fprintf(stdout, "  -r show raw packet data\n");
	fprintf(stdout, "  -b <background pcap filename> is for filtering background data\n\n");
	fprintf(stdout, " EXAMPLES:\n");
	fprintf(stdout, "  ./%s -p maimai.pcapng -t http\n", progname);
	fprintf(stdout, "  ./%s -p maimai.pcapng -t http -b maimai_background.pcapng\n\n", progname);
}

bool is_local_addr(std::string ip_addr_str)
{
    if((ip_addr_str.substr(0, 3) == "10.") || (ip_addr_str.substr(0, 4) == "172.") || (ip_addr_str.substr(0, 8) == "192.168."))
    {
        return true;
    }
    else
    {
        return false;
    }
}   

void background_packet_handler(pcap_t *background_fp, std::set<std::string> &ip_addrs_str_set)
{
    struct pcap_pkthdr *pkthdr;
    const u_char *bytes;

    const struct ether_header *ethhdr;
    const struct ip *iphdr;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    int res;

    while((res = pcap_next_ex(background_fp, &pkthdr, &bytes)) >= 0)
    {
        ethhdr = (struct ether_header*)bytes;
        // IP packet
        if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) 
        {
            iphdr = (struct ip*)(bytes + sizeof(struct ether_header));
            inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
            // fprintf(stdout, "src_ip: %s ", src_ip);

            inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
            // fprintf(stdout, "dst_ip: %s \n", dst_ip);

            std::string src_ip_str = std::string(src_ip);
            if(!is_local_addr(src_ip_str))
            {
                ip_addrs_str_set.insert(src_ip_str);
            }

            std::string dst_ip_str = std::string(dst_ip);
            if(!is_local_addr(dst_ip_str))
            {
                ip_addrs_str_set.insert(dst_ip_str);
            }
        }
    }

    return;
}

int find_enter(std::string data_str)
{
    char *c = const_cast<char*>(data_str.c_str());
    int loca = 0;
    for(loca = 0; loca < data_str.length(); loca++)
    {
        if(c[loca] == 0x0a)
        {
            return loca;
        }
    }
}

void http_collector(std::string data_str)
{
    int loca;
    std::string ua = "User-Agent:";
    std::string host = "Host:";
    std::string content_type = "Content-Type:";

    if((loca = data_str.find(ua)) != std::string::npos)
    {
        std::string tmp_str = data_str.substr(loca);
        tmp_str = tmp_str.substr(ua.length(), find_enter(tmp_str) - ua.length());
        user_agents.insert(tmp_str);
    }
    if((loca = data_str.find(host)) != std::string::npos)
    {
        std::string tmp_str = data_str.substr(loca);
        tmp_str = tmp_str.substr(host.length(), find_enter(tmp_str) - host.length());;
        hosts.insert(tmp_str);
    }
    if((loca = data_str.find(content_type)) != std::string::npos)
    {
        std::string tmp_str = data_str.substr(loca);
        tmp_str = tmp_str.substr(content_type.length(), find_enter(tmp_str) - content_type.length());
        content_types.insert(tmp_str);
    }
}

std::string ascii_to_string(int total_len, const u_char *data)
{
    std::string data_str = "";

    int i;

	for(i = 0; i < total_len; i++)
	{
        if(isprint(data[i]))
        {
            data_str += data[i];
        }
        else
        {
            data_str += '.';
        }
    }

    return data_str;
}

void dns_collector(int total_len, const u_char *data)
{
    std::string data_str = "";

    int i;

	for(i = 0; i < total_len; i++)
	{
        if(isprint(data[i]))
        {
            data_str += data[i];
        }
        else
        {
            data_str += '.';
        }
        if((i % 48) == 0)
        {
            data_str += '\n';
        }
    }

    dns_contents.insert(data_str);
}

void print_packet_head(char *src_ip, char *dst_ip, int proto_type, const struct tcphdr *tcphdr, const struct udphdr *udphdr)
{
    char protocol[32];
    switch (proto_type)
    {
        case HTTP_PROTO:
            strcpy(protocol, "HTTP");
            break;
        case DNS_PROTO:
            strcpy(protocol, "DNS");
            break;
        case FTP_PROTO:
            strcpy(protocol, "FTP");
            break;
        case POP_PROTO:
            strcpy(protocol, "POP");
            break;
        case TELNET_PROTO:
            strcpy(protocol, "Telnet");
            break;
        case HTTPS_PROTO:
            strcpy(protocol, "HTTPS");
            break;
        case SSL_PROTO:
            strcpy(protocol, "SSL");
            break;
        case PRIVATE_PROTO:
            strcpy(protocol, "Private");
            break;
        case OTHER_PROTO:
            strcpy(protocol, "Other");
            break;
        default:
            break;
    }
    fprintf(stdout, "=====================================================================================\n");
    fprintf(stdout, GREEN"Protocol type: %s\n\n" NONE, protocol);

    if(tcphdr != NULL)
    {
        fprintf(stdout, "Source IP   : %s\n", src_ip);
        fprintf(stdout, "Dest   IP   : %s\n", dst_ip);
        fprintf(stdout, "Source Port : %d\n", ntohs(tcphdr->source));
        fprintf(stdout, "Dest   Port : %d\n", ntohs(tcphdr->dest));

        fprintf(stdout, "TCP SYN FLAG: %d\n", tcphdr->syn);
        fprintf(stdout, "TCP ACK FLAG: %d\n", tcphdr->ack);
        fprintf(stdout, "TCP RST FLAG: %d\n", tcphdr->rst);
        fprintf(stdout, "TCP FIN FLAG: %d\n\n", tcphdr->fin);
    }
    else if (udphdr != NULL)
    {
        fprintf(stdout, "Source IP   : %s\n", src_ip);
		fprintf(stdout, "Dest   IP   : %s\n", dst_ip);
        fprintf(stdout, "Source Port : %d\n", ntohs(udphdr->source));
		fprintf(stdout, "Dest   Port : %d\n", ntohs(udphdr->dest));
    }
}

bool is_print_ascii(char letter)
{
	if(isprint(letter) != 0)
		return true;
	else
		return false;
}

void print_packet_data(int total_len, const u_char *data)
{
    int i = 0;
	int j;
	int start = i;
	int end = (total_len - 0) % 16;
	fprintf(stdout, "Data:\n");
	for(i = 0; i < total_len; ++i)
	{
		fprintf(stdout, "%02x ", data[i]);
		if((i - 0 + 1) % 16 == 0)
		{
			int j;
			fprintf(stdout, "      ");
			for(j = start; j < start + 16; j++)
			{
                if(is_print_ascii(data[j]))
				    fprintf(stdout, "%c ", data[j]);
                else
                    fprintf(stdout, GRAY". " NONE);
			}
			start = i + 1;
			fprintf(stdout, "\n");
		}
	}
	for(j = 0; j < 16 - end; j++)
	{
		fprintf(stdout, "   ");
	}
	fprintf(stdout, "      ");
	for(j = (total_len - end); j < total_len; j++)
	{
		if(is_print_ascii(data[j]))
			fprintf(stdout, "%c ", data[j]);
        else
            fprintf(stdout, GRAY". " NONE);
	}
	fprintf(stdout, "\n");

    fprintf(stdout, "=====================================================================================\n\n");
}

void datagram_handler(const u_char *bytes, const struct ip *iphdr, int total_len, int proto_type, bool is_print_raw)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    const struct tcphdr *tcphdr;
    const struct udphdr *udphdr;

    u_char *data;

    u_int src_port, dst_port;

    if((iphdr->ip_p == IPPROTO_TCP) && (proto_type == HTTP_PROTO || proto_type == FTP_PROTO || proto_type == POP_PROTO || proto_type == TELNET_PROTO || proto_type == PRIVATE_PROTO || proto_type == OTHER_PROTO || proto_type == HTTPS_PROTO || proto_type == SSL_PROTO))
    {
        tcphdr = (struct tcphdr*)(bytes + sizeof(struct ether_header) + iphdr->ip_hl * 4);
        src_port = ntohs(tcphdr->source);
        dst_port = ntohs(tcphdr->dest);

        data = (u_char*)(bytes + sizeof(struct ether_header) + iphdr->ip_hl * 4 + sizeof(struct tcphdr));

        // HTTP
        if(proto_type == HTTP_PROTO)
        {
            if (src_port == 80 || dst_port == 80)   
            {
                http_count++;
                http_ports.insert(std::to_string(80));
                std::string data_str = std::string(reinterpret_cast<char*>(data));

                inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

                std::string src_ip_str = std::string(src_ip);
                if(!is_local_addr(src_ip_str))
                {
                    http_ip_addrs.insert(src_ip_str);
                }

                std::string dst_ip_str = std::string(dst_ip);
                if(!is_local_addr(dst_ip_str))
                {
                    http_ip_addrs.insert(dst_ip_str);
                }

                http_collector(data_str);
                
                if(is_print_raw)
                {
                    print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                    print_packet_data(total_len, data);
                }

                return;
            }
            // 非80端口的情况
            else
            {
                std::string httphdr = "HTTP/";
                std::string data_str = std::string(reinterpret_cast<char*>(data));

                if(data_str.find(httphdr) != std::string::npos)
                {
                    http_count++;

                    inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

                    std::string src_ip_str = std::string(src_ip);
                    if(!is_local_addr(src_ip_str))
                    {
                        http_ip_addrs.insert(src_ip_str);
                        http_ports.insert(std::to_string(src_port));
                    }

                    std::string dst_ip_str = std::string(dst_ip);
                    if(!is_local_addr(dst_ip_str))
                    {
                        http_ip_addrs.insert(dst_ip_str);
                        http_ports.insert(std::to_string(dst_port));
                    }
                    
                    if(is_print_raw)
                    {
                        print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                        print_packet_data(total_len, data);
                    }

                    http_collector(data_str);
                }
                return;
            }
        }

        // HTTPS
        if(proto_type == HTTPS_PROTO || proto_type == SSL_PROTO)
        {
            if (src_port == 443 || dst_port == 443)   
            {
                inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
                
                if(is_print_raw)
                {
                    print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                    print_packet_data(total_len, data);
                }

                return;
            }
        }

        // 私有协议 
        if(proto_type == PRIVATE_PROTO)
        {
            std::string private_contact = "";
            private_contact += "TCP ";
            private_count++;

            inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            std::string src_ip_str = std::string(src_ip);
            private_contact += "src: ";
            private_contact += src_ip_str;
            private_contact += ":";
            private_contact += std::to_string(src_port);
            private_contact += " ";

            std::string dst_ip_str = std::string(dst_ip);
            private_contact += "dst: ";
            private_contact += dst_ip_str;
            private_contact += ":";
            private_contact += std::to_string(dst_port);
            private_contact += " ";
            
            if(is_print_raw)
            {
                print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                print_packet_data(total_len, data);
            }

            private_contacts.insert(private_contact);
        }

        // 其他协议寻找手机信息
        if(proto_type == OTHER_PROTO)
        {
            std::string key1 = "HONOR";
            std::string key2 = "honor";
            std::string data_str1 = std::string(reinterpret_cast<char*>(data));
            std::string data_str2 = ascii_to_string(total_len, data);

            inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            if((data_str1.find(key1) != std::string::npos) || (data_str2.find(key1) != std::string::npos) || (data_str2.find(key2) != std::string::npos) || (data_str2.find(key2) != std::string::npos))
            {   
                print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                print_packet_data(total_len, data);
            }
        }

    }
    else if((iphdr->ip_p == IPPROTO_UDP) && (proto_type == DNS_PROTO || proto_type == PRIVATE_PROTO || proto_type == OTHER_PROTO))
    {   
        udphdr = (struct udphdr*)(bytes + sizeof(struct ether_header) + iphdr->ip_hl * 4);
        src_port = ntohs(udphdr->source);
        dst_port = ntohs(udphdr->dest);

        data = (u_char*)(bytes + sizeof(struct ether_header) + iphdr->ip_hl * 4 + sizeof(struct udphdr));

        // DNS
        if(proto_type == DNS_PROTO)
        {
            // DNS
            if (src_port == 53 || dst_port == 53)   
            {
                dns_count++;

                inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

                dns_collector(total_len, data);      

                if(is_print_raw)
                {
                    print_packet_head(src_ip, dst_ip, proto_type, NULL, udphdr);
                    print_packet_data(total_len, data);
                }

                return;
            }
        }
        
        // 私有协议 
        if(proto_type == PRIVATE_PROTO)
        {
            std::string private_contact = "";
            private_contact += "UDP ";
            private_count++;

            inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            std::string src_ip_str = std::string(src_ip);
            private_contact += "src: ";
            private_contact += src_ip_str;
            private_contact += ":";
            private_contact += std::to_string(src_port);
            private_contact += " ";

            std::string dst_ip_str = std::string(dst_ip);
            private_contact += "dst: ";
            private_contact += dst_ip_str;
            private_contact += ":";
            private_contact += std::to_string(dst_port);
            private_contact += " ";
            
            if(is_print_raw)
            {
                print_packet_head(src_ip, dst_ip, proto_type, tcphdr, NULL);
                print_packet_data(total_len, data);
            }

            private_contacts.insert(private_contact);
        }

        // 其他协议寻找手机信息
        if(proto_type == OTHER_PROTO)
        {
            std::string key1 = "HONOR";
            std::string key2 = "honor";
            std::string data_str1 = std::string(reinterpret_cast<char*>(data));
            std::string data_str2 = ascii_to_string(total_len, data);

            inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            if((data_str1.find(key1) != std::string::npos) || (data_str2.find(key1) != std::string::npos) || (data_str2.find(key2) != std::string::npos) || (data_str2.find(key2) != std::string::npos))
            {   
                print_packet_head(src_ip, dst_ip, proto_type, NULL, udphdr);
                print_packet_data(total_len, data);
            }
        }
    }
    return;
}

void packet_handler(pcap_t *data_fp, std::set<std::string> &ip_addrs_str_set, int proto_type, bool is_print_raw)
{
    struct pcap_pkthdr *pkthdr;
    const u_char *bytes;

    const struct ether_header *ethhdr;
    const struct ip *iphdr;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    std::string src_ip_str, dst_ip_str;
    
    int res;

    if(ip_addrs_str_set.empty())
    {
        while((res = pcap_next_ex(data_fp, &pkthdr, &bytes)) >= 0)
        {
            ethhdr = (struct ether_header*)bytes;
            // IP packet
            if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) 
            {
                int total_len = (int) pkthdr->caplen;

                iphdr = (struct ip*)(bytes + sizeof(struct ether_header));
                // inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                // inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

                datagram_handler(bytes, iphdr, total_len, proto_type, is_print_raw);
            }
        }
    }
    else
    {
        while((res = pcap_next_ex(data_fp, &pkthdr, &bytes)) >= 0)
        {
            ethhdr = (struct ether_header*)bytes;
            // IP packet
            if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) 
            {
                int total_len = (int) pkthdr->caplen;
                iphdr = (struct ip*)(bytes + sizeof(struct ether_header));
                inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
                // fprintf(stdout, "src_ip: %s ", src_ip);

                inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
                // fprintf(stdout, "dst_ip: %s \n", dst_ip);

                src_ip_str = std::string(src_ip);
                dst_ip_str = std::string(dst_ip);

                if((ip_addrs_str_set.count(src_ip_str) == 0) && (ip_addrs_str_set.count(dst_ip_str) == 0))
                {
                    datagram_handler(bytes, iphdr, total_len, proto_type, is_print_raw);
                }
                else
                {
                    continue;
                }
            }
        }
    }
    
    return;
}

void print_set(std::set<std::string> str_set)
{
    std::set<std::string>::iterator v = str_set.begin();
    while( v != str_set.end()) {
        std::string el;
        el = *v;
        char *c = const_cast<char*>(el.c_str());
        int space_count = 0;
        for(int i = 0; i < el.length(); i++)
        {
            if(isspace(c[i]))
            {
                space_count++;
            }
            else  
            {
                break;
            }
        }
        for(int i = 0; i < 2 - space_count; i++)
        {
            printf(" ");
        }
        printf("%s\n", c);
        v++;
    } 
}

void print_http_stats()
{
    fprintf(stdout, GREEN "\n\nHTTP STATS SUMMARY\n" NONE);
    fprintf(stdout, "=============\n\n");

    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  HTTP ports\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(http_ports);
    fprintf(stdout, "----------------------------------------------------\n\n");

    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  IP Addresses\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(http_ip_addrs);
    fprintf(stdout, "----------------------------------------------------\n\n");

    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  User Agent\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(user_agents);
    fprintf(stdout, "----------------------------------------------------\n\n");

    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  Host\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(hosts);
    fprintf(stdout, "----------------------------------------------------\n\n");
    
    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  Content-Type\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(content_types);
    fprintf(stdout, "----------------------------------------------------\n\n");

}

void print_dns_stats()
{
    fprintf(stdout, BLUE "\n\nDNS STATS SUMMARY\n" NONE);
    fprintf(stdout, "=============\n\n");
    
    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  DNS Contents\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(dns_contents);
    fprintf(stdout, "----------------------------------------------------\n\n");
}

void private_private_stats()
{
    fprintf(stdout, RED "\n\nPRIVATE STATS SUMMARY\n" NONE);
    fprintf(stdout, "=============\n\n");
    
    fprintf(stdout, "----------------------------------------------------\n");
    fprintf(stdout, "  Private contacts\n");
    fprintf(stdout, "----------------------------------------------------\n");
    print_set(private_contacts);
    fprintf(stdout, "----------------------------------------------------\n\n");

}

void print_stats_summary(int proto_type)
{
    switch (proto_type)
    {
        case HTTP_PROTO:
            if(http_count > 0)
            {
                print_http_stats();
            }
            else
            {
                fprintf(stdout, RED "No any http packet captured! \n" NONE);
            }
            break;
        case DNS_PROTO:
            if(dns_count > 0)
            {
                print_dns_stats();
            }
            else
            {
                fprintf(stdout, RED "No any dns packet captured! \n" NONE);
            }
            break;
        case PRIVATE_PROTO:
            private_private_stats();
            break;
        default:
            break;
    }
}


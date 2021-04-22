#include <iostream>
#include <iomanip>
#include <getopt.h>
#include <cstring>
#include <time.h> 
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h> 
#include <net/if_arp.h>

//TODO: ipv6, ctrl+c, timezone

#define SIZE_ETHERNET 14
#define LINE_WIDTH 16

class ArgumentParser {
    public:
        std::string interface = "";
        int port = -1;
        unsigned n = 1;
        bool tcp = false;
        bool udp = false;
        bool arp = false;
        bool icmp = false;
        bool showInterface = false;
    
        void printHelp(){
            std::cout << "pepga\n";
        }

        int argumentParser(int argc, char *argv[]){
            const char* const shortOps = ":i:p:tun:;";
            const struct option longOpts[] = {
                {"interface", optional_argument, nullptr, 'i'},
                {"tcp", no_argument, nullptr, 't'},
                {"udp", no_argument, nullptr, 'u'},
                {"arp", no_argument, nullptr, 0},
                {"icmp", no_argument, nullptr, 0},
                {"help", no_argument, nullptr, 'h'},
                {nullptr, 0, nullptr, 0}
            };

            if (argc == 1){
                showInterface = true;
                return 0;
            }
            int opt = 0, optionIndex;
            while ((opt = getopt_long(argc, argv, shortOps, longOpts, &optionIndex)) != EOF) {
                switch (opt) {
                    case 'i':
                        interface = optarg;
                        break;
                    case ':':
                        showInterface = true;
                        break;
                    case 'p':
                        try{
                            port = std::stoi(optarg);
                            if (port < 0 || port > 65535) {
                                std::cerr << "Invalid argument " << optarg << "\n";
                            }
                        }
                        catch (const std::invalid_argument& ia){
                            std::cerr << "Invalid argument " << optarg << "\n";
                            return 1;
                        }
                        catch (const std::out_of_range& oor){
                            std::cerr << "Argument " << optarg << " out of range\n";
                            return 1;
                        }
                        break;
                    case 'n':
                        try{
                            n = std::stoi(optarg);
                            if (n <= 0 ) {
                                std::cerr << "Invalid argument " << optarg << "\n";
                            }
                        }
                        catch (const std::invalid_argument& ia){
                            std::cerr << "Invalid argument " << optarg << "\n";
                            return 1;
                        }
                        catch (const std::out_of_range& oor){
                            std::cerr << "Argument " << optarg << " out of range\n";
                            return 1;
                        }
                        break;
                    case 't':
                        tcp = true;
                        break;
                    case 'u':
                        udp = true;
                        break;
                    case 0:
                        if (longOpts[optionIndex].flag != 0){
                            break;
                        }
                        if (strcmp(longOpts[optionIndex].name, "arp") == 0){
                            arp = true;
                            break;
                        }else if (strcmp(longOpts[optionIndex].name, "icmp") == 0){
                            icmp = true;
                            break;
                        }
                        break;
                    case 'h':
                        printHelp();
                        return 0;
                    case '?':
                    default:
                        std::cerr << "Invalid arguments\n";
                        return 1;
                }
            }
            if (interface != "" && showInterface){
                std::cerr << "Invalid arguments\n";
                return 1;
            }
            return 0;
        }
};

int printDevices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

    if (pcap_findalldevs(&interfaces, errbuf) != PCAP_ERROR){
        for (pcap_if_t* interface = interfaces; interface; interface = interface->next){
            std::cout << interface->name << "\n";
        }
        pcap_freealldevs(interfaces);
    } else {
        std::cerr << errbuf << "\n";
        return 1;
    }
    return 0;
}

std::string getTime(const struct pcap_pkthdr *header){
    time_t time_sec = header->ts.tv_sec;
    const struct tm* locTime = localtime(&time_sec);
    const struct tm* globTime = gmtime(&time_sec);
    int i = (globTime->tm_hour) - locTime->tm_hour;
    std::string timezone;
    if (i == 0){
        timezone = "z";
    }else timezone = std::to_string(i);

    std::string time = std::to_string(locTime->tm_hour) + ":" + std::to_string(locTime->tm_min) + ":" + std::to_string(locTime->tm_sec) + "." + std::to_string(header->ts.tv_usec) + timezone;
    std::string year = std::to_string(locTime->tm_year + 1900) + "-" + std::to_string(locTime->tm_mon + 1) + "-" + std::to_string(locTime->tm_mday) + "T";
    std::string timestamp = year + time;
    return timestamp;
}

void printHeaderIP(const struct pcap_pkthdr *header, const struct ip *iph, const u_char *packet, u_int8_t type){
    std::string src = inet_ntoa(iph->ip_src);
    std::string dst = inet_ntoa(iph->ip_dst);
    std::string srcPort;
    std::string dstPort;
    
    if (type == IPPROTO_TCP){
        struct tcphdr* tcph = (struct tcphdr*)(packet + (iph->ip_hl * 4) + SIZE_ETHERNET);
        srcPort = std::to_string(ntohs(tcph->source));
        dstPort = std::to_string(ntohs(tcph->dest));
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << src << " : " << srcPort << " > " << dst << " : " << dstPort << ", length " << header->len << " bytes" << "\n\n";
    }else if (type == IPPROTO_UDP){
        struct udphdr* udph = (struct udphdr*)(packet + (iph->ip_hl * 4) + SIZE_ETHERNET);
        srcPort = std::to_string(ntohs(udph->source));
        dstPort = std::to_string(ntohs(udph->dest));
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << src << " : " << srcPort << " > " << dst << " : " << dstPort << ", length " << header->len << " bytes" << "\n\n";
    }else if (type == IPPROTO_ICMP){
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << src << " > " << dst << ", length " << header->len << " bytes" << "\n\n";
    }
}

void printHeaderIPV6(const struct pcap_pkthdr *header, const struct ip6_hdr *iph, const u_char *packet, u_int8_t type){
    std::string srcPort;
    std::string dstPort;
    char srcIP6[INET_ADDRSTRLEN];
    char dstIP6[INET_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(iph->ip6_src), srcIP6, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(iph->ip6_dst), dstIP6, INET6_ADDRSTRLEN);

    if (type == IPPROTO_TCP){
        struct tcphdr* tcph = (struct tcphdr*)(packet + 40 + SIZE_ETHERNET);
        srcPort = std::to_string(ntohs(tcph->source));
        dstPort = std::to_string(ntohs(tcph->dest));
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << srcIP6 << " : " << srcPort << " > " << dstIP6 << " : " << dstPort << ", length " << header->len << " bytes" << "\n\n";
    }else if (type == IPPROTO_UDP){
        struct udphdr* udph = (struct udphdr*)(packet + 40 + SIZE_ETHERNET);
        srcPort = std::to_string(ntohs(udph->source));
        dstPort = std::to_string(ntohs(udph->dest));
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << srcIP6 << " : " << srcPort << " > " << dstIP6 << " : " << dstPort << ", length " << header->len << " bytes" << "\n\n";
    }else if (type == IPPROTO_ICMPV6){
        std::string timestamp = getTime(header);
        std::cout << timestamp << " " << srcIP6 << " > " << dstIP6 << ", length " << header->len << " bytes" << "\n\n";
    }

}

void printHeaderARP(const struct pcap_pkthdr *header, const struct ether_arp *arph){
    std::string timestamp = getTime(header);
    std::cout << timestamp << " ";
    for (int i = 0; i < ETH_ALEN; i++){
        printf("%02x", arph->arp_sha[i]);
        if (i < ETH_ALEN - 1){
            printf(":");
        } 
    }
    std::cout << " > "; 
    for (int i = 0; i < ETH_ALEN; i++){
        printf("%02x", arph->arp_tha[i]);
        if (i < ETH_ALEN - 1){
            printf(":");
        } 
    }
    std::cout << ", length " << header->len << " bytes" << std::endl << std::endl;;
}

void printLine(const u_char *packet, size_t len, int offset){
	size_t i;
    const u_char *character;
    
    std::cout << "0x" << std::setfill('0') << std::setw(4) << std::hex << offset << ": ";
	character = packet;
	for(i = 0; i < len; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(unsigned char)*character << " ";
		character++;
	}

    for(; i < LINE_WIDTH; i++) {
	    std::cout << "   ";
    }
    std::cout << " ";

	character = packet;
	for(i = 0; i < len; i++) {
		if (isprint(*character))
            std::cout << *character;
		else
			std::cout << ".";
		character++;
	}
	std::cout << std::endl;
    return;
}

void printPacket(const u_char *packet, size_t len){
	size_t len_rem = len;		
	size_t line_len;
	int offset = 0;					
	const u_char *character = packet;

	if (len != 0){
        if (len <= LINE_WIDTH) {
            printLine(character, len, offset);
            return;
        }
        while(true) {
            line_len = LINE_WIDTH % len_rem;
            printLine(character, line_len, offset);
            len_rem = len_rem - line_len;
            character = character + line_len;
            offset = offset + LINE_WIDTH;
            if (len_rem <= LINE_WIDTH) {
                printLine(character, len_rem, offset);
                break;
            }
        }
    }
    std::cout << std::endl;
    return;
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *p = (struct ether_header *)packet;
    size_t size = header->len;    
    
	if (ntohs(p->ether_type) == ETHERTYPE_IP) {
        struct ip *iph = (struct ip*)(packet + SIZE_ETHERNET);
        printHeaderIP(header, iph, packet, iph->ip_p);
        printPacket(packet, size);
    }else if (ntohs(p->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arph = (struct ether_arp *)(packet + SIZE_ETHERNET);
        printHeaderARP(header, arph);
        printPacket(packet, size);
    }else if(ntohs(p->ether_type) == ETHERTYPE_IPV6) {
        struct ip6_hdr *iph = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
        printHeaderIPV6(header, iph, packet, iph->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        printPacket(packet, size);
        
    }
}

std::string buildFilter(ArgumentParser args){
    std::string filter = "";
    
    if (args.arp) {
        filter += "(arp";
    }
    if (args.icmp) {
        if (args.arp){
            filter += " or (icmp or icmp6))";
        }else filter += "(icmp or icmp6)";
    }
    if (args.port != -1) {
        if (args.icmp || args.arp){
            filter += " or port " + std::to_string(args.port);
        }else filter += "port " + std::to_string(args.port);
    }
    if (args.tcp) {
        if (args.port != -1){
            filter += " and (tcp";
        }else filter += "(tcp";
    }

    if (args.udp) {
        if (args.tcp) {
            filter += " or udp";
        }else if (args.port != -1){
            filter += " and (udp";
        }else filter += "(udp";
    }
    
    if (args.tcp || args.udp || args.arp){
        filter += ")";
    }
    return filter;
}

int runSniffer(ArgumentParser args){
    char errbuf[PCAP_ERRBUF_SIZE];
    const std::string filter = buildFilter(args);
    struct bpf_program fp;
    pcap_t* handle; 
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(args.interface.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << errbuf << "\n";
        net = 0;
        mask = 0;
    }
    if ((handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errbuf)) == nullptr){
        std::cerr << errbuf << "\n";
        return 1;
    }
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << "\n";
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    if (pcap_loop(handle, args.n, gotPacket, nullptr) == PCAP_ERROR){
        return 1;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

int main(int argc, char *argv[]) {
    ArgumentParser args;
    if (args.argumentParser(argc, argv)){
        return 1;
    }
    if (args.showInterface) {
        if (printDevices()){
            return 1;
        }
        return 0;
    }
    if (runSniffer(args)){
        return 1;
    }

    return 0;
}
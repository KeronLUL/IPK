#include <iostream>
#include <getopt.h>
#include <cstring>
#include <pcap/pcap.h>

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

    void argumentParser(int argc, char *argv[]){
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
            return;
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
                        
                        exit(1);
                    }
                    catch (const std::out_of_range& oor){
                        std::cerr << "Argument " << optarg << " out of range\n";
                        exit(1);
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
                        exit(1);
                    }
                    catch (const std::out_of_range& oor){
                        std::cerr << "Argument " << optarg << " out of range\n";
                        exit(1);
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
                    exit(0);
                case '?':
                default:
                    std::cerr << "Invalid arguments\n";
                    exit(1);
            }
        }
        if (interface != "" && showInterface){
            std::cerr << "Invalid arguments\n";
            exit(1);
        }
    }
};

void printDevices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

    if (pcap_findalldevs(&interfaces, errbuf) != PCAP_ERROR){
        for (pcap_if_t* interface = interfaces; interface; interface = interface->next){
            std::cout << interface->name << "\n";
        }
        pcap_freealldevs(interfaces);
    } else {
        std::cerr << errbuf << "\n";
        exit(1);
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    const size_t size = header->len;
    std::cout << size << "\n";
}

void runSniffer(ArgumentParser args){
    char errbuf[PCAP_ERRBUF_SIZE];
    const std::string filter = "ip or ip6";
    struct bpf_program fp;
    pcap_t* handle; 
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(args.interface.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << "Couldn't get netmask for device " << args.interface << ": " << errbuf << "\n";
        net = 0;
        mask = 0;
    }
    if ((handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errbuf)) == nullptr){
        std::cerr << errbuf << "\n";
        exit(1);
    }
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << "\n";
        pcap_freecode(fp);
        pcap_close(handle);
        exit(1);
    }
    if (pcap_loop(handle, args.n, got_packet, nullptr) == PCAP_ERROR){
        exit(1);
    }
    
    pcap_freecode(fp);
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    ArgumentParser args;
    args.argumentParser(argc, argv);

    if (args.showInterface) {
        printDevices();
        return 0;
    }

    runSniffer(args);

    return 0;
}
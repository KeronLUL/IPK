#include <iostream>
#include <getopt.h>
#include <cstring>
#include <pcap/pcap.h>

class ArgumentParser {
    public:
        std::string interface;
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
            std::cerr << "Invalid arguments\n";
            exit(1);
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
                        std::cerr << "Argument " << optarg << " out of range\n";
                        exit(1);
                    }
                    catch (const std::out_of_range& oor){
                        printHelp();
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
    }
};

int main(int argc, char *argv[]) {
    ArgumentParser args;
    args.argumentParser(argc, argv);
    return 0;
}